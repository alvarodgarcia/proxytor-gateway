# Security Policy

ProxyTor Gateway controls proxy access, Tor control operations, Telegram alerts and optional client banning. Treat every deployment as security-sensitive.

## Never expose publicly

Do not expose these ports directly to the Internet:

- `9050/tcp` - Tor SOCKS
- `8118/tcp` - Privoxy HTTP proxy
- `8088/tcp` - ProxyTor API

Use firewall rules, VPN access, private networks, reverse proxy authentication or equivalent controls.

## Secrets

Never commit real values for:

- `/etc/proxytor-api/token`
- `/etc/proxytor-api/token.viewer`
- `/etc/default/proxytor-telegram`
- Telegram bot tokens
- Real production domain names
- Real infrastructure IPs
- SQLite runtime databases

## Recommended deployment

- Bind Tor SOCKS and Privoxy only to trusted networks.
- Keep the API behind a reverse proxy or VPN.
- Use admin tokens only for operations.
- Use viewer tokens for dashboards.
- Review ban rules before enabling automatic enforcement.

## Reporting issues

Open a GitHub issue without secrets. For sensitive issues, contact the maintainer privately before publishing details.
