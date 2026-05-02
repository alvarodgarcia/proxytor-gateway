# ProxyTor Gateway on Proxmox LXC

This guide describes a recommended LXC deployment model for ProxyTor Gateway on Proxmox.

## Recommended model

ProxyTor Gateway is best deployed in a Debian LXC container with controlled LAN or VPN access.

Recommended base:

- Debian 12 Bookworm.
- Static LAN IP.
- systemd enabled.
- Firewall enabled at Proxmox or network level.
- No direct public exposure of proxy ports.

## Recommended resources

| Resource | Suggested value |
|---|---:|
| CPU | 1-2 vCPU |
| RAM | 512 MB - 1 GB |
| Disk | 8-16 GB |
| Network | Static IP |
| OS | Debian 12 |

## Container creation example

Example Proxmox settings:

```text
Hostname: proxytor
Template: debian-12-standard
Disk: 8G or higher
CPU: 1 or 2 cores
Memory: 512M or higher
Network: bridged LAN interface
IPv4: static
Unprivileged: yes
Nesting: optional
```

## Install from GitHub

```bash
apt update
apt install -y git ca-certificates

git clone https://github.com/alvarodgarcia/proxytor-gateway.git
cd proxytor-gateway

sudo bash scripts/install.sh
```

## Safe installer re-run

The installer preserves existing runtime configuration by default.

Normal re-run:

```bash
sudo bash scripts/install.sh
```

Skip package installation on an already prepared container:

```bash
sudo bash scripts/install.sh --skip-packages
```

Preview actions without changing the system:

```bash
sudo bash scripts/install.sh --dry-run
```

Replace Tor and Privoxy configuration only when explicitly required:

```bash
sudo bash scripts/install.sh --force-config
```

## Network ports

| Port | Service | Recommended exposure |
|---:|---|---|
| 8088/tcp | Dashboard/API | LAN/VPN or protected reverse proxy |
| 8118/tcp | Privoxy HTTP proxy | Trusted LAN/VPN clients only |
| 9050/tcp | Tor SOCKS5 proxy | Trusted LAN/VPN clients only |
| 9051/tcp | Tor ControlPort | Localhost only |

Do not expose 9050/tcp or 8118/tcp directly to the Internet.

## Recommended firewall policy

Allow only trusted sources:

```text
Trusted LAN/VPN clients -> 8088/tcp
Trusted LAN/VPN clients -> 8118/tcp
Trusted LAN/VPN clients -> 9050/tcp
Internet -> denied
```

## Check services

```bash
systemctl status tor@default --no-pager
systemctl status privoxy --no-pager
systemctl status proxytor-api --no-pager
```

## Check listening ports

```bash
ss -lntup | grep -E ':9050|:9051|:8118|:8088'
```

Expected result:

```text
9050/tcp - Tor SOCKS
9051/tcp - Tor ControlPort, local only
8118/tcp - Privoxy
8088/tcp - ProxyTor API/dashboard
```

## Test Tor SOCKS

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

## Test Privoxy

```bash
curl -x http://127.0.0.1:8118 https://check.torproject.org/api/ip
```

## Dashboard access

Open:

```text
http://PROXYTOR_IP:8088/
```

Admin token:

```bash
sudo cat /etc/proxytor-api/token
```

Viewer token:

```bash
sudo cat /etc/proxytor-api/token.viewer
```

## Optional reverse proxy

A reverse proxy is optional.

Recommended only for dashboard/API access:

```text
https://proxytor.example.com -> http://PROXYTOR_IP:8088
```

Do not publish 9050/tcp or 8118/tcp as public reverse proxy services.

## Backup

```bash
sudo bash scripts/backup.sh
```

## Update

```bash
sudo bash scripts/update.sh
```

## Notes

- LXC is the recommended lightweight deployment model.
- Docker support is not the primary deployment target yet.
- For production-like use, restrict access using firewall rules, VPN or private reverse proxy access.
