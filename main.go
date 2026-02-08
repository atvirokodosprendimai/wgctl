package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		if err := run(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "head":
		if err := runHead(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "genkey":
		if err := genKey(); err != nil {
			log.Fatal(err)
		}
	case "genpsk":
		if err := genPresharedKey(); err != nil {
			log.Fatal(err)
		}
	case "pubkey":
		if err := pubKey(); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to wg-quick style config")
	headURL := fs.String("head", "", "head base URL (example: http://127.0.0.1:8080)")
	headsFlag := fs.String("heads", "", "comma separated head URLs for multi-head (example: http://h1:8080,http://h2:8080)")
	token := fs.String("token", "", "shared token for head enrollment")
	tokensFlag := fs.String("tokens", "", "comma separated tokens mapped to -heads")
	privateKey := fs.String("private-key", "", "client private key (base64); generated if empty")
	labelsFlag := fs.String("labels", "", "comma separated labels for head registry")
	domainFlag := fs.String("domain", "", "base domain for head registry (example: apps.example.com)")
	domainsFlag := fs.String("domains", "", "comma separated domains for head registry")
	proxyPort := fs.Int("proxy-port", 18080, "client proxy listen port for head ingress")
	proxyTo := fs.String("to", "", "upstream target URL for local proxy (example: http://localhost:9999)")
	ifName := fs.String("name", defaultTUNName("wg0"), "tunnel interface name")
	logLevel := fs.String("log-level", "info", "silent|error|verbose")
	noSystemConfig := fs.Bool("no-system-config", false, "skip interface address assignment")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var cfg *ClientConfig
	var err error

	allHeads := parseCSV(strings.TrimSpace(*headsFlag))
	if strings.TrimSpace(*headURL) != "" {
		allHeads = append(allHeads, strings.TrimSpace(*headURL))
	}

	if len(allHeads) > 0 {
		headTokens, err := resolveHeadTokens(allHeads, strings.TrimSpace(*token), strings.TrimSpace(*tokensFlag))
		if err != nil {
			return err
		}

		var priv wgtypes.Key
		if strings.TrimSpace(*privateKey) == "" {
			priv, err = wgtypes.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("generate client private key: %w", err)
			}
			log.Printf("generated ephemeral client key for this session")
		} else {
			priv, err = wgtypes.ParseKey(strings.TrimSpace(*privateKey))
			if err != nil {
				return fmt.Errorf("parse -private-key: %w", err)
			}
		}

		enrollOpts := EnrollmentOptions{
			Labels:    normalizeLabels(*labelsFlag),
			Domain:    normalizeDomain(*domainFlag),
			Domains:   normalizeLabels(*domainsFlag),
			ProxyPort: *proxyPort,
		}
		for i, d := range enrollOpts.Domains {
			enrollOpts.Domains[i] = normalizeDomain(d)
		}

		for i := range allHeads {
			hCfg, headErr := FetchClientConfigFromHead(allHeads[i], headTokens[i], priv.PublicKey(), enrollOpts)
			if headErr != nil {
				return fmt.Errorf("head enroll failed for %s: %w", allHeads[i], headErr)
			}
			if cfg == nil {
				cfg = hCfg
				continue
			}
			mergeClientConfigs(cfg, hCfg)
		}

		cfg.Interface.PrivateKey = priv
	} else {
		if strings.TrimSpace(*configPath) == "" {
			return errors.New("-config is required when -head is not set")
		}
		cfg, err = ParseConfigFile(*configPath)
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
	}

	tunName, err := normalizeTUNName(*ifName)
	if err != nil {
		return err
	}

	tunDev, err := tun.CreateTUN(tunName, cfg.Interface.MTU)
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

	if err := applyWGConfig(realName, cfg); err != nil {
		dev.Close()
		return fmt.Errorf("apply wireguard config: %w", err)
	}

	if !*noSystemConfig {
		if err := configureInterface(realName, cfg); err != nil {
			log.Printf("warning: interface address setup failed: %v", err)
		}
		if err := configureRoutes(realName, cfg); err != nil {
			log.Printf("warning: route setup failed: %v", err)
		}
	}

	var proxyServer *http.Server
	if strings.TrimSpace(*proxyTo) != "" {
		proxyServer, err = startClientProxy(cfg, *proxyPort, *proxyTo)
		if err != nil {
			log.Printf("warning: local proxy failed to start: %v", err)
		} else {
			log.Printf("client proxy is up: listen=%s target=%s", proxyServer.Addr, *proxyTo)
		}
	}

	log.Printf("wireguard userland tunnel %q is up", realName)
	stopFailover := startEndpointFailover(realName, cfg)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("shutting down %q", realName)
	if stopFailover != nil {
		stopFailover()
	}
	if proxyServer != nil {
		_ = proxyServer.Close()
	}
	dev.Close()
	return nil
}

func serveUAPI(dev *device.Device, uapi net.Listener) {
	for {
		conn, err := uapi.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go dev.IpcHandle(conn)
	}
}

func applyWGConfig(name string, cfg *ClientConfig) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	return client.ConfigureDevice(name, cfg.WGConfig())
}

func genKey() error {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(priv.String())
	return nil
}

func genPresharedKey() error {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return err
	}
	fmt.Println(wgtypes.Key(psk).String())
	return nil
}

func pubKey() error {
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	fmt.Println(priv.PublicKey().String())
	return nil
}

func parseLogLevel(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent":
		return device.LogLevelSilent
	case "error":
		return device.LogLevelError
	default:
		return device.LogLevelVerbose
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "wgctl: wireguard-go userland client\\n\\n")
	fmt.Fprintf(os.Stderr, "Usage:\\n")
	fmt.Fprintf(os.Stderr, "  wgctl run -config client.conf [-name wg0] [-log-level verbose] [-no-system-config]\\n")
	fmt.Fprintf(os.Stderr, "  wgctl run -head http://127.0.0.1:8080 -token SECRET [-private-key KEY] [-labels a,b] [-domain app.example.com|-domains a.example.com,b.example.com] [-to http://localhost:9999] [-name wg0]\\n")
	fmt.Fprintf(os.Stderr, "  wgctl run -heads http://h1:8080,http://h2:8080 -tokens t1,t2 [-private-key KEY] [-domains a.example.com,b.example.com] [-to http://localhost:9999]\\n")
	fmt.Fprintf(os.Stderr, "  wgctl head -config head.json [-name wg-head0] [-log-level verbose] [-no-system-config]\\n")
	fmt.Fprintf(os.Stderr, "  wgctl genkey\\n")
	fmt.Fprintf(os.Stderr, "  wgctl genpsk\\n")
	fmt.Fprintf(os.Stderr, "  wgctl pubkey < privatekey\\n")
}
