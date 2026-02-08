package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func startClientProxy(cfg *ClientConfig, listenPort int, target string) (*http.Server, error) {
	targetURL, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("parse -to URL: %w", err)
	}
	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return nil, fmt.Errorf("-to must use http or https scheme")
	}

	listenAddr, err := proxyListenAddr(cfg, listenPort)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: proxy,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("client proxy stopped: %v\n", err)
		}
	}()

	return srv, nil
}

func proxyListenAddr(cfg *ClientConfig, port int) (string, error) {
	_ = cfg
	return net.JoinHostPort("", fmt.Sprintf("%d", port)), nil

	/*
		for _, prefix := range cfg.Interface.Address {
			ip := prefix.Addr().Unmap()
			if !ip.Is4() {
				continue
			}
			return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
		}

		for _, prefix := range cfg.Interface.Address {
			ip := prefix.Addr().Unmap()
			if !ip.Is6() {
				continue
			}
			return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil
		}

		return "", fmt.Errorf("cannot start proxy: client has no interface address")
	*/
}

func normalizeLabels(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		v := strings.ToLower(strings.TrimSpace(part))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeDomain(v string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(v)), ".")
}
