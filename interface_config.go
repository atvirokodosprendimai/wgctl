package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
)

func configureInterface(name string, cfg *ClientConfig) error {
	switch runtime.GOOS {
	case "linux":
		return configureLinuxInterface(name, cfg)
	case "darwin":
		return configureDarwinInterface(name, cfg)
	default:
		return fmt.Errorf("automatic interface configuration is not implemented for %s", runtime.GOOS)
	}
}

func configureRoutes(name string, cfg *ClientConfig) error {
	routeEntries := collectAllowedRouteEntries(cfg)
	if len(routeEntries) == 0 {
		return nil
	}
	routes := routePrefixes(routeEntries)

	if err := configureEndpointBypassRoutes(cfg, routes); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinuxRoutes(name, routes)
	case "darwin":
		return configureDarwinRoutes(name, routeEntries, cfg)
	default:
		return fmt.Errorf("automatic route configuration is not implemented for %s", runtime.GOOS)
	}
}

func configureEndpointBypassRoutes(cfg *ClientConfig, routes []netip.Prefix) error {
	hasDefaultV4 := hasDefaultRoute(routes, false)
	hasDefaultV6 := hasDefaultRoute(routes, true)
	if !hasDefaultV4 && !hasDefaultV6 {
		return nil
	}

	for _, ep := range collectPeerEndpointIPs(cfg) {
		if ep.Is4() && !hasDefaultV4 {
			continue
		}
		if ep.Is6() && !hasDefaultV6 {
			continue
		}

		switch runtime.GOOS {
		case "linux":
			if err := addLinuxEndpointBypass(ep); err != nil {
				return err
			}
		case "darwin":
			if err := addDarwinEndpointBypass(ep); err != nil {
				return err
			}
		}
	}

	return nil
}

func hasDefaultRoute(routes []netip.Prefix, ipv6 bool) bool {
	for _, route := range routes {
		addr := route.Addr()
		if addr.Is6() != ipv6 {
			continue
		}
		if route.Bits() == 0 {
			return true
		}
	}
	return false
}

func collectPeerEndpointIPs(cfg *ClientConfig) []netip.Addr {
	out := make([]netip.Addr, 0)
	seen := map[string]struct{}{}
	addIP := func(ip net.IP) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		addr = addr.Unmap()
		key := addr.String()
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, addr)
	}

	for _, peer := range cfg.Peers {
		if peer.Endpoint == nil {
			for i := range peer.EndpointCandidates {
				addIP(peer.EndpointCandidates[i].IP)
			}
			continue
		}
		addIP(peer.Endpoint.IP)
		for i := range peer.EndpointCandidates {
			addIP(peer.EndpointCandidates[i].IP)
		}
	}

	return out
}

func addLinuxEndpointBypass(ip netip.Addr) error {
	dev, gw, err := linuxRouteGet(ip)
	if err != nil {
		return err
	}

	pfx := ip.String()
	if ip.Is4() {
		pfx += "/32"
		if gw != "" {
			return runCmdAllowExists("ip", "route", "add", pfx, "via", gw, "dev", dev)
		}
		return runCmdAllowExists("ip", "route", "add", pfx, "dev", dev)
	}

	pfx += "/128"
	if gw != "" {
		return runCmdAllowExists("ip", "-6", "route", "add", pfx, "via", gw, "dev", dev)
	}
	return runCmdAllowExists("ip", "-6", "route", "add", pfx, "dev", dev)
}

func linuxRouteGet(ip netip.Addr) (dev string, gw string, err error) {
	cmd := exec.Command("ip", "route", "get", ip.String())
	if ip.Is6() {
		cmd = exec.Command("ip", "-6", "route", "get", ip.String())
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("route lookup failed for %s: %v (%s)", ip, err, strings.TrimSpace(string(output)))
	}

	fields := strings.Fields(string(output))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
		if fields[i] == "via" {
			gw = fields[i+1]
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("route lookup returned no dev for %s", ip)
	}
	return dev, gw, nil
}

func addDarwinEndpointBypass(ip netip.Addr) error {
	gw, iface, err := darwinRouteGet(ip)
	if err != nil {
		return err
	}

	if ip.Is4() {
		if gw != "" {
			return runCmdAllowExists("route", "-n", "add", "-inet", "-host", ip.String(), gw)
		}
		if iface == "" {
			return fmt.Errorf("route lookup returned no gateway/interface for %s", ip)
		}
		return runCmdAllowExists("route", "-n", "add", "-inet", "-host", ip.String(), "-interface", iface)
	}

	if gw != "" {
		return runCmdAllowExists("route", "-n", "add", "-inet6", "-host", ip.String(), gw)
	}
	if iface == "" {
		return fmt.Errorf("route lookup returned no gateway/interface for %s", ip)
	}
	return runCmdAllowExists("route", "-n", "add", "-inet6", "-host", ip.String(), "-interface", iface)
}

func darwinRouteGet(ip netip.Addr) (gateway string, iface string, err error) {
	args := []string{"-n", "get"}
	if ip.Is4() {
		args = append(args, "-inet", ip.String())
	} else {
		args = append(args, "-inet6", ip.String())
	}
	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("route lookup failed for %s: %v (%s)", ip, err, strings.TrimSpace(string(output)))
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return gateway, iface, nil
}

func configureLinuxInterface(name string, cfg *ClientConfig) error {
	if err := runCmd("ip", "link", "set", "up", "dev", name); err != nil {
		return err
	}
	for _, prefix := range cfg.Interface.Address {
		if err := runCmdAllowExists("ip", "address", "add", prefix.String(), "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func configureDarwinInterface(name string, cfg *ClientConfig) error {
	if err := runCmd("ifconfig", name, "up"); err != nil {
		return err
	}
	for _, prefix := range cfg.Interface.Address {
		addr := prefix.Addr()
		if addr.Is4() {
			mask := net.IP(net.CIDRMask(prefix.Bits(), 32)).String()
			if err := runCmdAllowExists("ifconfig", name, "inet", addr.String(), addr.String(), "netmask", mask, "alias"); err != nil {
				return err
			}
			continue
		}
		if err := runCmdAllowExists("ifconfig", name, "inet6", prefix.String(), "add"); err != nil {
			return err
		}
	}
	return nil
}

func configureLinuxRoutes(name string, routes []netip.Prefix) error {
	for _, route := range routes {
		route = route.Masked()
		if route.Addr().Is6() {
			if err := runCmdAllowExists("ip", "-6", "route", "add", route.String(), "dev", name); err != nil {
				return err
			}
			continue
		}
		if err := runCmdAllowExists("ip", "route", "add", route.String(), "dev", name); err != nil {
			return err
		}
	}
	return nil
}

func configureDarwinRoutes(name string, routes []routeEntry, cfg *ClientConfig) error {
	defaultIFA4 := firstInterfaceAddr(cfg.Interface.Address, false)
	defaultIFA6 := firstInterfaceAddr(cfg.Interface.Address, true)

	for _, entry := range routes {
		route := entry.Prefix
		route = route.Masked()
		ifa4 := defaultIFA4
		ifa6 := defaultIFA6
		if entry.Source.IsValid() {
			if entry.Source.Is4() {
				ifa4 = entry.Source.String()
			}
			if entry.Source.Is6() {
				ifa6 = entry.Source.String()
			}
		}
		if route.Addr().Is6() {
			target := route.String()
			if route.Bits() == 0 {
				target = "default"
			}
			if route.Bits() == 128 {
				args := []string{"-n", "add", "-inet6", "-host", route.Addr().String(), "-interface", name, "-ifscope", name}
				if ifa6 != "" {
					args = append(args, "-ifa", ifa6)
				}
				if err := runCmdAllowExists("route", args...); err != nil {
					return err
				}
				continue
			}
			args := []string{"-n", "add", "-inet6", target, "-interface", name, "-ifscope", name}
			if ifa6 != "" {
				args = append(args, "-ifa", ifa6)
			}
			if err := runCmdAllowExists("route", args...); err != nil {
				return err
			}
			continue
		}

		target := route.String()
		if route.Bits() == 0 {
			target = "default"
		}
		if route.Bits() == 32 {
			args := []string{"-n", "add", "-inet", "-host", route.Addr().String(), "-interface", name, "-ifscope", name}
			if ifa4 != "" {
				args = append(args, "-ifa", ifa4)
			}
			if err := runCmdAllowExists("route", args...); err != nil {
				return err
			}
			continue
		}
		args := []string{"-n", "add", "-inet", target, "-interface", name, "-ifscope", name}
		if ifa4 != "" {
			args = append(args, "-ifa", ifa4)
		}
		if err := runCmdAllowExists("route", args...); err != nil {
			return err
		}
	}
	return nil
}

func firstInterfaceAddr(addrs []netip.Prefix, ipv6 bool) string {
	for _, p := range addrs {
		a := p.Addr()
		if a.Is6() == ipv6 {
			return a.String()
		}
	}
	return ""
}

func collectAllowedIPs(cfg *ClientConfig) []netip.Prefix {
	out := make([]netip.Prefix, 0)
	seen := map[string]struct{}{}

	for _, peer := range cfg.Peers {
		for _, allowed := range peer.AllowedIPs {
			allowed = allowed.Masked()
			key := allowed.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, allowed)
		}
	}

	return out
}

type routeEntry struct {
	Prefix netip.Prefix
	Source netip.Addr
}

func collectAllowedRouteEntries(cfg *ClientConfig) []routeEntry {
	out := make([]routeEntry, 0)
	seen := map[string]struct{}{}

	for _, peer := range cfg.Peers {
		for _, allowed := range peer.AllowedIPs {
			allowed = allowed.Masked()
			key := allowed.String() + "|" + peer.SourceAddress.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, routeEntry{Prefix: allowed, Source: peer.SourceAddress})
		}
	}

	if len(out) == 0 {
		return out
	}

	return out
}

func routePrefixes(entries []routeEntry) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		k := entry.Prefix.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, entry.Prefix)
	}
	return out
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runCmdAllowExists(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.ToLower(string(output))
	if strings.Contains(msg, "file exists") || strings.Contains(msg, "exists") {
		return nil
	}
	return fmt.Errorf("%s %s failed: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
}
