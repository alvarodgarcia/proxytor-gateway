# Security Notes

ProxyTor Gateway handles sensitive operations such as proxy access, Tor control, token management, Telegram alerts and client banning.

## Services that must not be publicly exposed

| Port | Service | Recommendation |
|---:|---|---|
| `9050/tcp` | Tor SOCKS proxy | Trusted LAN/VPN only |
| `8118/tcp` | Privoxy HTTP proxy | Trusted LAN/VPN only |
| `8088/tcp` | ProxyTor API/dashboard | Protected reverse proxy, VPN or private access only |
| `9051/tcp` | Tor ControlPort | Localhost only |

## Secrets

Never commit or publish:

- `/etc/proxytor-api/token`
- `/etc/proxytor-api/token.viewer`
- `/etc/default/proxytor-telegram`
- Telegram bot tokens
- Real production domains
- Real internal IP addresses
- Private keys or certificates
- SQLite databases with real operational data

## Token model

| Role | Intended access |
|---|---|
| `viewer` | Read-only access to metrics, events and exports |
| `admin` | Service actions, token rotation and ban management |

Viewer tokens must not be able to restart services, rotate tokens or manage bans.

## Telegram

- Restrict bot responses to a single authorized `TELEGRAM_CHAT_ID`.
- Treat `/token_admin` output as sensitive.
- Avoid forwarding Telegram messages that contain tokens.
- Rotate tokens if a Telegram chat or bot token is exposed.

## Ban protection

Add reverse proxy, gateway and management IPs to `protected_ips` and `npmplus_ips` to avoid accidental self-bans.

## Operational recommendations

- Keep audit export enabled only for trusted users.
- Review logs and events regularly.
- Rotate admin tokens periodically.
- Keep the host updated.
- Test backup and restore procedures before relying on them.
