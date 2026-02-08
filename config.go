package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ClientConfig struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
}

type InterfaceConfig struct {
	PrivateKey wgtypes.Key
	Address    []netip.Prefix
	DNS        []netip.Addr
	ListenPort *int
	MTU        int
}

type PeerConfig struct {
	PublicKey                   wgtypes.Key
	PresharedKey                *wgtypes.Key
	Endpoint                    *net.UDPAddr
	EndpointCandidates          []net.UDPAddr
	SourceAddress               netip.Addr
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval *time.Duration
}

func ParseConfigFile(path string) (*ClientConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &ClientConfig{}
	var section string
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				currentPeer = nil
			case "peer":
				cfg.Peers = append(cfg.Peers, PeerConfig{})
				currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section %q", lineNo, section)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if err := parseInterfaceKV(&cfg.Interface, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("line %d: internal parser state error", lineNo)
			}
			if err := parsePeerKV(currentPeer, key, value); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return nil, fmt.Errorf("line %d: key-value outside of section", lineNo)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if cfg.Interface.PrivateKey == (wgtypes.Key{}) {
		return nil, fmt.Errorf("missing Interface.PrivateKey")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("missing at least one [Peer]")
	}
	for i := range cfg.Peers {
		if cfg.Peers[i].PublicKey == (wgtypes.Key{}) {
			return nil, fmt.Errorf("peer %d missing PublicKey", i+1)
		}
	}

	if cfg.Interface.MTU == 0 {
		cfg.Interface.MTU = 1420
	}

	return cfg, nil
}

func parseInterfaceKV(cfg *InterfaceConfig, key, value string) error {
	switch key {
	case "privatekey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid PrivateKey: %w", err)
		}
		cfg.PrivateKey = k
	case "address":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return fmt.Errorf("invalid Address: %w", err)
		}
		cfg.Address = append(cfg.Address, prefixes...)
	case "dns":
		items := splitCSV(value)
		for _, item := range items {
			if ip, err := netip.ParseAddr(item); err == nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	case "listenport":
		p, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid ListenPort: %w", err)
		}
		cfg.ListenPort = &p
	case "mtu":
		m, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid MTU: %w", err)
		}
		cfg.MTU = m
	default:
	}
	return nil
}

func parsePeerKV(cfg *PeerConfig, key, value string) error {
	switch key {
	case "publickey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid PublicKey: %w", err)
		}
		cfg.PublicKey = k
	case "presharedkey":
		k, err := wgtypes.ParseKey(value)
		if err != nil {
			return fmt.Errorf("invalid PresharedKey: %w", err)
		}
		cfg.PresharedKey = &k
	case "endpoint":
		ep, err := net.ResolveUDPAddr("udp", value)
		if err != nil {
			return fmt.Errorf("invalid Endpoint: %w", err)
		}
		cfg.Endpoint = ep
	case "allowedips":
		prefixes, err := parsePrefixList(value)
		if err != nil {
			return fmt.Errorf("invalid AllowedIPs: %w", err)
		}
		cfg.AllowedIPs = append(cfg.AllowedIPs, prefixes...)
	case "persistentkeepalive", "persistentkeepaliveinterval":
		secs, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid PersistentKeepalive: %w", err)
		}
		d := time.Duration(secs) * time.Second
		cfg.PersistentKeepaliveInterval = &d
	default:
	}
	return nil
}

func parsePrefixList(v string) ([]netip.Prefix, error) {
	items := splitCSV(v)
	out := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *ClientConfig) WGConfig() wgtypes.Config {
	peers := make([]wgtypes.PeerConfig, 0, len(c.Peers))
	for _, p := range c.Peers {
		peer := wgtypes.PeerConfig{
			PublicKey:         p.PublicKey,
			PresharedKey:      p.PresharedKey,
			Endpoint:          p.Endpoint,
			ReplaceAllowedIPs: true,
			AllowedIPs:        toIPNets(p.AllowedIPs),
		}
		if p.PersistentKeepaliveInterval != nil {
			peer.PersistentKeepaliveInterval = p.PersistentKeepaliveInterval
		}
		peers = append(peers, peer)
	}

	return wgtypes.Config{
		PrivateKey:   &c.Interface.PrivateKey,
		ListenPort:   c.Interface.ListenPort,
		ReplacePeers: true,
		Peers:        peers,
	}
}

func toIPNets(prefixes []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, 0, len(prefixes))
	for _, prefix := range prefixes {
		addr := prefix.Addr()
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		out = append(out, net.IPNet{
			IP:   net.IP(addr.AsSlice()),
			Mask: net.CIDRMask(prefix.Bits(), bits),
		})
	}
	return out
}
