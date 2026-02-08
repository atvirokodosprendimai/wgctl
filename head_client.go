package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type enrollRequest struct {
	Token     string   `json:"token"`
	PublicKey string   `json:"public_key"`
	Labels    []string `json:"labels,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	ProxyPort int      `json:"proxy_port,omitempty"`
}

type enrollResponse struct {
	ClientAddress       string   `json:"client_address"`
	DNS                 []string `json:"dns"`
	MTU                 int      `json:"mtu"`
	ServerPublicKey     string   `json:"server_public_key"`
	Endpoint            string   `json:"endpoint"`
	Endpoints           []string `json:"endpoints,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type EnrollmentOptions struct {
	Labels    []string
	Domain    string
	Domains   []string
	ProxyPort int
}

func FetchClientConfigFromHead(headURL, token string, publicKey wgtypes.Key, opts EnrollmentOptions) (*ClientConfig, error) {
	reqBody := enrollRequest{
		Token:     token,
		PublicKey: publicKey.String(),
		Labels:    opts.Labels,
		Domain:    opts.Domain,
		Domains:   opts.Domains,
		ProxyPort: opts.ProxyPort,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(strings.TrimSpace(headURL), "/") + "/v1/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("head request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("head request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var enroll enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enroll); err != nil {
		return nil, fmt.Errorf("decode head response: %w", err)
	}

	serverPub, err := wgtypes.ParseKey(strings.TrimSpace(enroll.ServerPublicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid server_public_key: %w", err)
	}

	address, err := netip.ParsePrefix(strings.TrimSpace(enroll.ClientAddress))
	if err != nil {
		return nil, fmt.Errorf("invalid client_address: %w", err)
	}

	endpoint, err := net.ResolveUDPAddr("udp", strings.TrimSpace(enroll.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	allowed, err := parseJSONPrefixes(enroll.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("invalid allowed_ips: %w", err)
	}

	dns, err := parseJSONAddrs(enroll.DNS)
	if err != nil {
		return nil, fmt.Errorf("invalid dns: %w", err)
	}

	keepalive := time.Duration(enroll.PersistentKeepalive) * time.Second
	if enroll.MTU == 0 {
		enroll.MTU = 1420
	}

	endpointCandidates := make([]net.UDPAddr, 0, len(enroll.Endpoints))
	for _, raw := range enroll.Endpoints {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ep, epErr := net.ResolveUDPAddr("udp", raw)
		if epErr != nil {
			return nil, fmt.Errorf("invalid endpoints entry %q: %w", raw, epErr)
		}
		endpointCandidates = append(endpointCandidates, *ep)
	}
	if len(endpointCandidates) == 0 {
		endpointCandidates = append(endpointCandidates, *endpoint)
	}

	return &ClientConfig{
		Interface: InterfaceConfig{
			Address: []netip.Prefix{address},
			DNS:     dns,
			MTU:     enroll.MTU,
		},
		Peers: []PeerConfig{{
			PublicKey:                   serverPub,
			Endpoint:                    endpoint,
			EndpointCandidates:          endpointCandidates,
			SourceAddress:               address.Addr(),
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: &keepalive,
		}},
	}, nil
}
