# wgctl

`wgctl` is a lightweight WireGuard userland client in Go using `wireguard-go` primitives.

## Features

- Runs a WireGuard tunnel fully in userspace (`tun` + `wireguard-go` device)
- Reads a wg-quick style config (`[Interface]`, `[Peer]`)
- Supports head mode over HTTP with token-auth enrollment
- Supports label/domain registry and HTTP ingress forwarding
- Applies peer/interface crypto settings through WireGuard UAPI/wgctrl
- Optionally assigns interface IP addresses on Linux/macOS
- Includes key helpers (`genkey`, `genpsk`, `pubkey`)

## Build

```bash
go build ./...
```

## Usage

```bash
./wgctl run -config ./client.conf -name wg0
```

or enroll from head:

```bash
./wgctl run -head http://127.0.0.1:8080 -token supersecret -private-key <base64-private-key>

# with ingress registration + local proxy
./wgctl run -head http://127.0.0.1:8080 -token supersecret \
  -labels web1,web2 -domains something.domain.tld,api.domain.tld \
  -to http://localhost:9999 -proxy-port 18080

# multi-head client (two independent WG peers)
./wgctl run -heads http://h1:8080,http://h2:8080 -tokens t1,t2 \
  -domains app.domain.tld,api.domain.tld -to http://localhost:9999
```

Flags:

- `-config`: path to config file (required)
- `-head`: head API base URL for dynamic config
- `-heads`: comma-separated head API URLs for multi-head mode
- `-token`: shared token for head enrollment
- `-tokens`: comma-separated tokens mapped to `-heads` (or single token for all)
- `-private-key`: client private key for head mode (if omitted, an ephemeral key is generated)
- `-labels`: comma-separated labels to register on head ingress
- `-domain`: single exact domain routed to this node
- `-domains`: comma-separated exact domains routed to this node
- `-to`: start local reverse proxy and forward to upstream URL
- `-proxy-port`: local proxy listen port for head->client forwarding (default `18080`)
- `-name`: tunnel interface name (default `wg0`)
- `-log-level`: `silent`, `error`, or `verbose`
- `-no-system-config`: skip IP assignment on interface

## Head mode

Run a userland WireGuard server plus HTTP control plane:

```bash
./wgctl head -config ./head.json -name wg-head0
```

Example `head.json`:

```json
{
  "token": "supersecret",
  "listen_addr": ":8080",
  "ingress_listen_addr": ":80",
  "endpoint": "203.0.113.10:51820",
  "endpoints": ["203.0.113.10:51820", "198.51.100.10:51820"],
  "tunnel_cidr": "10.90.0.0/24",
  "server_address": "10.90.0.1/24",
  "server_private_key": "<base64-private-key>",
  "listen_port": 51820,
  "mtu": 1420,
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "dns": ["1.1.1.1", "9.9.9.9"],
  "persistent_keepalive": 25
}
```

Enrollment endpoint:

- `POST /v1/enroll`
- Authorization via `Authorization: Bearer <token>` (or `token` in JSON body)
- Body:

```json
{
  "public_key": "<client-public-key>",
  "token": "supersecret",
  "labels": ["web1", "web2"],
  "domains": ["something.domain.tld", "api.domain.tld"],
  "proxy_port": 18080
}
```

Registry endpoint:

- `GET /v1/registry` with `Authorization: Bearer <token>`

Ingress behavior:

- Head listens on `ingress_listen_addr` (default `:80`)
- Incoming host `something.domain.tld` (and any registered domain) is proxied over WG tunnel to enrolled client at `<client_tunnel_ip>:proxy_port`
- Client proxy then forwards to `-to` target (for example `http://localhost:9999`)
- `labels` are stored as metadata in registry and do not create subdomain routes

HA endpoints:

- Head can return multiple endpoints via `endpoints`
- Client keeps endpoint candidates and automatically switches when handshake is stale

Multi-head mode:

- Client can enroll to multiple heads in one process (`-heads`)
- Interface addresses and peers from all heads are merged into one tunnel interface
- Works best when heads use different VPN subnets / non-overlapping `AllowedIPs`

Key helpers:

```bash
./wgctl genkey
./wgctl genpsk
./wgctl pubkey < privatekey.txt
```

## Example config

```ini
[Interface]
PrivateKey = <base64-private-key>
Address = 10.10.0.2/24
MTU = 1420

[Peer]
PublicKey = <server-public-key>
Endpoint = 198.51.100.42:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

## Notes

- Running this usually requires root/admin privileges to create and configure TUN interfaces.
- DNS and route orchestration are intentionally not managed yet.
