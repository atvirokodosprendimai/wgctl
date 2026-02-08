package main

import (
	"log"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func startEndpointFailover(iface string, cfg *ClientConfig) func() {
	if cfg == nil || len(cfg.Peers) != 1 {
		return nil
	}
	peer := cfg.Peers[0]
	if len(peer.EndpointCandidates) < 2 {
		return nil
	}

	stop := make(chan struct{})
	var once sync.Once

	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()

		client, err := wgctrl.New()
		if err != nil {
			log.Printf("warning: endpoint failover disabled: %v", err)
			return
		}
		defer client.Close()

		index := endpointIndex(peer.EndpointCandidates, peer.Endpoint)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				dev, devErr := client.Device(iface)
				if devErr != nil || len(dev.Peers) == 0 {
					continue
				}
				latest := dev.Peers[0].LastHandshakeTime
				if !latest.IsZero() && time.Since(latest) < 25*time.Second {
					continue
				}

				index = (index + 1) % len(peer.EndpointCandidates)
				next := peer.EndpointCandidates[index]
				if err := client.ConfigureDevice(iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
					PublicKey: peer.PublicKey,
					Endpoint:  &net.UDPAddr{IP: append([]byte(nil), next.IP...), Port: next.Port, Zone: next.Zone},
				}}}); err != nil {
					continue
				}
				log.Printf("endpoint failover switched to %s", next.String())
			}
		}
	}()

	return func() {
		once.Do(func() { close(stop) })
	}
}

func endpointIndex(candidates []net.UDPAddr, current *net.UDPAddr) int {
	if current == nil {
		return 0
	}
	for i := range candidates {
		if candidates[i].String() == current.String() {
			return i
		}
	}
	return 0
}
