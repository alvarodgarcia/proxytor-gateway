# ProxyTor Gateway

ProxyTor Gateway is a self-hosted Tor + Privoxy gateway with a FastAPI dashboard, Telegram bot integration, token-based access control, traffic visibility, audit export, abuse detection and client banning.

> Status: `v0.1.0` initial sanitized release. Review and adapt configuration before production use.

## Features

- Tor SOCKS5 gateway on `9050/tcp`.
- Privoxy HTTP proxy on `8118/tcp`.
- FastAPI dashboard/API on `8088/tcp`.
- Admin and viewer tokens.
- Telegram bot integration.
- Token rotation support.
- Traffic and connection metrics.
- Recent client tracking.
- Audit events with CSV/JSON export by date range.
- Abuse detection by client connection count.
- Ban/unban controls from Telegram and dashboard.
- SQLite persistence.
- NPMplus-friendly deployment.

## Architecture

```text
Clients
  ↓
Privoxy HTTP :8118 / Tor SOCKS :9050
  ↓
ProxyTor Gateway
  ↓
Tor Network
  ↓
Internet
```

Dashboard/API path:

```text
Browser
  ↓
Reverse proxy / NPMplus / VPN
  ↓
ProxyTor API :8088
```

## Requirements

- Debian 12 Bookworm.
- Python 3.11+.
- Tor.
- Privoxy.
- systemd.
- SQLite.
- iptables.
- Optional: NPMplus or another reverse proxy.
- Optional: Telegram bot.

## Quick start

```bash
git clone https://github.com/alvarodgarcia/proxytor-gateway.git
cd proxytor-gateway
sudo bash scripts/install.sh
```

After installation, read the generated tokens:

```bash
sudo cat /etc/proxytor-api/token
sudo cat /etc/proxytor-api/token.viewer
```

Then open:

```text
http://PROXYTOR_IP:8088/
```

## Security warning

Do **not** expose these ports directly to the Internet:

- `9050/tcp` - Tor SOCKS.
- `8118/tcp` - Privoxy HTTP proxy.
- `8088/tcp` - ProxyTor API.

Use firewalling, private networks, VPN access, reverse proxy authentication, and strong token management.

## Repository layout

```text
config/        Example configuration files.
systemd/       systemd unit files.
scripts/       Install, update, backup and token scripts.
proxytor_api/  FastAPI dashboard/API.
telegram_bot/  Telegram bot integration.
docs/          Deployment and security documentation.
```

## Roadmap

- Harden installer idempotency.
- Add dashboard screenshots.
- Add GitHub Actions linting.
- Add packaged releases.
- Add Docker/LXC deployment examples.

## License

MIT License.
