# Deployment Guide

ProxyTor Gateway is designed for Debian 12 Bookworm and can be deployed on a VM, bare-metal host or LXC/container-like environment with systemd support.

## Default services and ports

| Service | Port | Scope | Description |
|---|---:|---|---|
| Tor SOCKS | `9050/tcp` | Trusted network only | SOCKS5 proxy endpoint |
| Tor ControlPort | `9051/tcp` | Localhost only | Tor control interface |
| Privoxy | `8118/tcp` | Trusted network only | HTTP proxy endpoint |
| ProxyTor API | `8088/tcp` | Private/reverse proxy | Dashboard and API |

Do not expose these ports directly to the Internet.

## Basic deployment

Clone the repository:

- `git clone https://github.com/alvarodgarcia/proxytor-gateway.git`
- `cd proxytor-gateway`

Run the installer:

- `sudo bash scripts/install.sh`

The installer creates:

| Path | Purpose |
|---|---|
| `/opt/proxytor-api` | Application files and Python virtual environment |
| `/etc/proxytor-api` | Local configuration and tokens |
| `/var/lib/proxytor-api` | Runtime data and SQLite database |
| `/etc/default/proxytor-telegram` | Telegram bot environment file |

## Post-installation checks

Check services:

- `systemctl status tor@default --no-pager`
- `systemctl status privoxy --no-pager`
- `systemctl status proxytor-api --no-pager`

Check listening ports:

- `ss -lntup | egrep ':9050|:9051|:8118|:8088'`

Read generated tokens:

- `sudo cat /etc/proxytor-api/token`
- `sudo cat /etc/proxytor-api/token.viewer`

Open the dashboard:

- `http://PROXYTOR_IP:8088/`

## Reverse proxy deployment

Recommended model:

| Field | Value |
|---|---|
| Scheme | `http` |
| Forward Host/IP | `PROXYTOR_IP` |
| Forward Port | `8088` |
| Force SSL | On |
| Websockets | Off |

Keep proxy ports `9050` and `8118` restricted to trusted clients.
