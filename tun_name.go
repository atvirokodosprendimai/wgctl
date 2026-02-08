package main

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

var darwinUTUNPattern = regexp.MustCompile(`^utun[0-9]*$`)

func defaultTUNName(nonDarwin string) string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return nonDarwin
}

func normalizeTUNName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return defaultTUNName("wg0"), nil
	}
	if runtime.GOOS != "darwin" {
		return name, nil
	}
	if !darwinUTUNPattern.MatchString(name) {
		return "", fmt.Errorf("on darwin interface name must match utun[0-9]*, got %q", name)
	}
	return name, nil
}
