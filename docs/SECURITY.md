# Security Notes

ProxyTor Gateway handles sensitive operations such as proxy access, Tor control, token management, Telegram alerts and client banning.

## Services that must not be publicly exposed

| Port | Service | Recommendation |
|---:|---|---|
| `9050/tcp` | Tor SOCKS proxy | Trusted LAN/VPN only |
| `8118/tcp` | Privoxy HTTP proxy | Trusted LAN/VPN only |
| `8088/tcp` | ProxyTor API/dashboard | Protected reverse proxy, VPN or private access only |
| `9051/tcp` | Tor ControlPort | Localhost only |

NPMplus is **not required**. A reverse proxy is optional and only recommended when publishing the dashboard/API over HTTPS.

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

## Service privilege separation

ProxyTor does not need to run the dashboard/API as full root.

Current architecture:

- `proxytor-api.service` runs as the unprivileged user `proxytor-api`
- `proxytor-root-helper.service` runs as `root`
- privileged host operations are exposed only over the local Unix socket `/run/proxytor-root-helper.sock`

This reduces the impact of a dashboard bug or token leak compared with a design where the whole web service runs as `root`.

## Telegram

- Restrict bot responses to a single authorized `TELEGRAM_CHAT_ID`.
- Treat `/token_admin` output as sensitive.
- Avoid forwarding Telegram messages that contain tokens.
- Rotate tokens if a Telegram chat or bot token is exposed.

## Ban protection

Add gateway, management and reverse proxy IPs to `protected_ips` to avoid accidental self-bans.

If you use NPMplus or another TCP stream/reverse proxy in front of ProxyTor, also add those IPs to `npmplus_ips`. Leave `npmplus_ips` empty when no NPMplus/TCP stream is used.

Some LXC or container environments expose incomplete `iptables` or `nft` support. In those cases ProxyTor degrades gracefully: the dashboard remains available and the firewall limitation is logged instead of aborting the API startup.

## Operational recommendations

- Keep audit export enabled only for trusted users.
- Review logs and events regularly.
- Rotate admin tokens periodically.
- Keep the host updated.
- Test backup and restore procedures before relying on them.
- Verify both `proxytor-api.service` and `proxytor-root-helper.service` after upgrades.
