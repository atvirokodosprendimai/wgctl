package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type HeadConfig struct {
	Token               string   `json:"token"`
	ListenAddr          string   `json:"listen_addr"`
	IngressListenAddr   string   `json:"ingress_listen_addr"`
	Endpoint            string   `json:"endpoint"`
	TunnelCIDR          string   `json:"tunnel_cidr"`
	ServerAddress       string   `json:"server_address"`
	ServerPrivateKey    string   `json:"server_private_key"`
	ListenPort          int      `json:"listen_port"`
	MTU                 int      `json:"mtu"`
	AllowedIPs          []string `json:"allowed_ips"`
	DNS                 []string `json:"dns"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type HeadRuntimeConfig struct {
	Token               string
	ListenAddr          string
	IngressListenAddr   string
	Endpoint            *net.UDPAddr
	Pool                netip.Prefix
	ServerAddress       netip.Prefix
	ServerPrivateKey    wgtypes.Key
	ListenPort          int
	MTU                 int
	AllowedIPs          []netip.Prefix
	DNS                 []netip.Addr
	PersistentKeepalive timeSeconds
}

type timeSeconds int

type HeadService struct {
	ifaceName string
	runtime   *HeadRuntimeConfig

	mu        sync.Mutex
	leases    map[string]netip.Addr
	registry  map[string]RegistryEntry
	labelRefs map[string]RegistryEntry
}

type RegistryEntry struct {
	PublicKey string   `json:"public_key"`
	IP        string   `json:"ip"`
	ProxyPort int      `json:"proxy_port"`
	Labels    []string `json:"labels,omitempty"`
	Domain    string   `json:"domain,omitempty"`
}

func runHead(args []string) error {
	fs := flag.NewFlagSet("head", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to head JSON config")
	ifName := fs.String("name", defaultTUNName("wg-head0"), "tunnel interface name")
	logLevel := fs.String("log-level", "info", "silent|error|verbose")
	noSystemConfig := fs.Bool("no-system-config", false, "skip interface address assignment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) == "" {
		return errors.New("-config is required")
	}

	hCfg, err := LoadHeadConfig(*configPath)
	if err != nil {
		return err
	}

	serverCfg := &ClientConfig{
		Interface: InterfaceConfig{
			PrivateKey: hCfg.ServerPrivateKey,
			Address:    []netip.Prefix{hCfg.ServerAddress},
			ListenPort: &hCfg.ListenPort,
			MTU:        hCfg.MTU,
		},
		Peers: nil,
	}

	tunName, err := normalizeTUNName(*ifName)
	if err != nil {
		return err
	}

	tunDev, err := tun.CreateTUN(tunName, serverCfg.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	realName, err := tunDev.Name()
	if err != nil {
		return fmt.Errorf("get tun name: %w", err)
	}

	logger := device.NewLogger(parseLogLevel(*logLevel), fmt.Sprintf("(%s) ", realName))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	uapiFile, err := ipc.UAPIOpen(realName)
	if err != nil {
		dev.Close()
		return fmt.Errorf("open uapi: %w", err)
	}
	defer uapiFile.Close()

	uapi, err := ipc.UAPIListen(realName, uapiFile)
	if err != nil {
		dev.Close()
		return fmt.Errorf("listen uapi: %w", err)
	}
	defer uapi.Close()

	go serveUAPI(dev, uapi)

	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring device up: %w", err)
	}

	if err := applyWGConfig(realName, serverCfg); err != nil {
		dev.Close()
		return fmt.Errorf("apply wireguard config: %w", err)
	}

	if !*noSystemConfig {
		if err := configureInterface(realName, serverCfg); err != nil {
			log.Printf("warning: interface address setup failed: %v", err)
		}
	}

	headSvc := &HeadService{
		ifaceName: realName,
		runtime:   hCfg,
		leases:    map[string]netip.Addr{},
		registry:  map[string]RegistryEntry{},
		labelRefs: map[string]RegistryEntry{},
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/v1/enroll", headSvc.handleEnroll)
	httpMux.HandleFunc("/v1/registry", headSvc.handleRegistry)

	httpServer := &http.Server{
		Addr:    hCfg.ListenAddr,
		Handler: httpMux,
	}
	ingressServer := &http.Server{
		Addr:    hCfg.IngressListenAddr,
		Handler: http.HandlerFunc(headSvc.handleIngress),
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("head http server stopped: %v", err)
		}
	}()
	go func() {
		if err := ingressServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("head ingress server stopped: %v", err)
		}
	}()

	log.Printf("head is up: iface=%q api=%s ingress=%s endpoint=%s", realName, hCfg.ListenAddr, hCfg.IngressListenAddr, hCfg.Endpoint.String())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	dev.Close()
	_ = httpServer.Close()
	_ = ingressServer.Close()
	return nil
}

func (s *HeadService) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if !s.requestAuthorizedToken(r, req.Token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	pubKey, err := wgtypes.ParseKey(strings.TrimSpace(req.PublicKey))
	if err != nil {
		http.Error(w, "invalid public_key", http.StatusBadRequest)
		return
	}

	labels := normalizeLabels(strings.Join(req.Labels, ","))
	domain := normalizeDomain(req.Domain)
	proxyPort := req.ProxyPort
	if proxyPort <= 0 {
		proxyPort = 18080
	}

	peerAddr, err := s.ensurePeer(pubKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.registerIngress(pubKey.String(), peerAddr, proxyPort, labels, domain)

	resp := enrollResponse{
		ClientAddress:       netip.PrefixFrom(peerAddr, hostBits(peerAddr)).String(),
		DNS:                 addrsToStrings(s.runtime.DNS),
		MTU:                 s.runtime.MTU,
		ServerPublicKey:     s.runtime.ServerPrivateKey.PublicKey().String(),
		Endpoint:            s.runtime.Endpoint.String(),
		AllowedIPs:          prefixesToStrings(s.runtime.AllowedIPs),
		PersistentKeepalive: int(s.runtime.PersistentKeepalive),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *HeadService) requestAuthorized(r *http.Request) bool {
	return s.requestAuthorizedToken(r, "")
}

func (s *HeadService) requestAuthorizedToken(r *http.Request, bodyToken string) bool {
	token := strings.TrimSpace(bodyToken)
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[7:])
	}
	if token == "" || token != s.runtime.Token {
		return false
	}
	return true
}

func (s *HeadService) registerIngress(pubKey string, ip netip.Addr, proxyPort int, labels []string, domain string) {
	entry := RegistryEntry{
		PublicKey: pubKey,
		IP:        ip.String(),
		ProxyPort: proxyPort,
		Labels:    labels,
		Domain:    domain,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if old, ok := s.labelRefs[pubKey]; ok {
		for _, label := range old.Labels {
			if old.Domain == "" {
				continue
			}
			delete(s.registry, label+"."+old.Domain)
		}
		if old.Domain != "" && len(old.Labels) == 0 {
			delete(s.registry, old.Domain)
		}
	}

	if domain != "" {
		if len(labels) == 0 {
			s.registry[domain] = entry
		} else {
			for _, label := range labels {
				s.registry[label+"."+domain] = entry
			}
		}
	}

	s.labelRefs[pubKey] = entry
}

func requestHost(rawHost string) string {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	return normalizeDomain(host)
}

func (s *HeadService) handleRegistry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requestAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	out := make(map[string]RegistryEntry, len(s.registry))
	for host, entry := range s.registry {
		out[host] = entry
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *HeadService) handleIngress(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r.Host)
	if host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	entry, ok := s.registry[host]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "host not registered", http.StatusNotFound)
		return
	}

	targetURL, err := url.Parse(fmt.Sprintf("http://%s:%d", entry.IP, entry.ProxyPort))
	if err != nil {
		http.Error(w, "invalid backend target", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		http.Error(rw, fmt.Sprintf("proxy error: %v", proxyErr), http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func (s *HeadService) ensurePeer(pub wgtypes.Key) (netip.Addr, error) {
	pubString := pub.String()

	s.mu.Lock()
	if addr, ok := s.leases[pubString]; ok {
		s.mu.Unlock()
		return addr, s.applyPeer(pub, addr)
	}

	addr, err := s.allocateLocked()
	if err != nil {
		s.mu.Unlock()
		return netip.Addr{}, err
	}
	s.leases[pubString] = addr
	s.mu.Unlock()

	if err := s.applyPeer(pub, addr); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func (s *HeadService) allocateLocked() (netip.Addr, error) {
	for addr := s.runtime.Pool.Addr().Next(); s.runtime.Pool.Contains(addr); addr = addr.Next() {
		if addr == s.runtime.ServerAddress.Addr() {
			continue
		}
		used := false
		for _, inUse := range s.leases {
			if inUse == addr {
				used = true
				break
			}
		}
		if !used {
			return addr, nil
		}
	}
	return netip.Addr{}, errors.New("ip pool exhausted")
}

func (s *HeadService) applyPeer(pub wgtypes.Key, addr netip.Addr) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	allowed := []net.IPNet{hostPrefixToIPNet(addr)}
	peer := wgtypes.PeerConfig{
		PublicKey:         pub,
		ReplaceAllowedIPs: true,
		AllowedIPs:        allowed,
	}

	return client.ConfigureDevice(s.ifaceName, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}

func LoadHeadConfig(path string) (*HeadRuntimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw HeadConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse head config: %w", err)
	}

	if strings.TrimSpace(raw.Token) == "" {
		return nil, errors.New("head config token is required")
	}
	if raw.ListenPort <= 0 {
		return nil, errors.New("head config listen_port is required")
	}
	if raw.MTU == 0 {
		raw.MTU = 1420
	}
	if raw.ListenAddr == "" {
		raw.ListenAddr = ":8080"
	}
	if raw.IngressListenAddr == "" {
		raw.IngressListenAddr = ":80"
	}
	if len(raw.AllowedIPs) == 0 {
		raw.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	if raw.PersistentKeepalive == 0 {
		raw.PersistentKeepalive = 25
	}

	endpoint, err := net.ResolveUDPAddr("udp", raw.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	pool, err := netip.ParsePrefix(raw.TunnelCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel_cidr: %w", err)
	}
	serverAddress, err := netip.ParsePrefix(raw.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid server_address: %w", err)
	}
	serverPriv, err := wgtypes.ParseKey(strings.TrimSpace(raw.ServerPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("invalid server_private_key: %w", err)
	}

	allowed, err := parseJSONPrefixes(raw.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("invalid allowed_ips: %w", err)
	}
	dns, err := parseJSONAddrs(raw.DNS)
	if err != nil {
		return nil, fmt.Errorf("invalid dns: %w", err)
	}

	return &HeadRuntimeConfig{
		Token:               raw.Token,
		ListenAddr:          raw.ListenAddr,
		IngressListenAddr:   raw.IngressListenAddr,
		Endpoint:            endpoint,
		Pool:                pool,
		ServerAddress:       serverAddress,
		ServerPrivateKey:    serverPriv,
		ListenPort:          raw.ListenPort,
		MTU:                 raw.MTU,
		AllowedIPs:          allowed,
		DNS:                 dns,
		PersistentKeepalive: timeSeconds(raw.PersistentKeepalive),
	}, nil
}

func parseJSONPrefixes(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		p, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseJSONAddrs(items []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(items))
	for _, item := range items {
		a, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func addrsToStrings(items []netip.Addr) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.String())
	}
	return out
}

func prefixesToStrings(items []netip.Prefix) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.String())
	}
	return out
}

func hostBits(addr netip.Addr) int {
	if addr.Is4() {
		return 32
	}
	return 128
}

func hostPrefixToIPNet(addr netip.Addr) net.IPNet {
	bits := hostBits(addr)
	return net.IPNet{
		IP:   net.IP(addr.AsSlice()),
		Mask: net.CIDRMask(bits, bits),
	}
}
