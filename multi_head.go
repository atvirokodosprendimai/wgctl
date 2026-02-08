package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func parseCSV(v string) []string {
	return splitCSV(v)
}

func resolveHeadTokens(heads []string, singleToken, tokensCSV string) ([]string, error) {
	if len(heads) == 0 {
		return nil, errors.New("no heads configured")
	}

	if strings.TrimSpace(tokensCSV) != "" {
		tokens := splitCSV(tokensCSV)
		if len(tokens) == 1 && len(heads) > 1 {
			out := make([]string, len(heads))
			for i := range out {
				out[i] = tokens[0]
			}
			return out, nil
		}
		if len(tokens) != len(heads) {
			return nil, fmt.Errorf("-tokens count (%d) must match -heads count (%d), or provide one token", len(tokens), len(heads))
		}
		return tokens, nil
	}

	if strings.TrimSpace(singleToken) == "" {
		return nil, errors.New("-token (or -tokens) is required when using -head/-heads")
	}
	out := make([]string, len(heads))
	for i := range out {
		out[i] = singleToken
	}
	return out, nil
}

func mergeClientConfigs(dst, src *ClientConfig) {
	if dst == nil || src == nil {
		return
	}

	dst.Interface.Address = dedupePrefixes(append(dst.Interface.Address, src.Interface.Address...))
	dst.Interface.DNS = dedupeAddrs(append(dst.Interface.DNS, src.Interface.DNS...))
	if dst.Interface.MTU == 0 || (src.Interface.MTU > 0 && src.Interface.MTU < dst.Interface.MTU) {
		dst.Interface.MTU = src.Interface.MTU
	}

	dst.Peers = append(dst.Peers, src.Peers...)
}

func dedupePrefixes(items []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = item.Masked()
		k := item.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, item)
	}
	return out
}

func dedupeAddrs(items []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = item.Unmap()
		k := item.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, item)
	}
	return out
}
