# Security Policy

ProxyTor Gateway handles sensitive infrastructure functions such as proxy access, Tor control, Telegram alerts, token management and client banning.

## Supported versions

| Version | Status |
|---|---|
| v0.1.x | Initial public release |

## Security recommendations

Do not expose the following ports directly to the Internet:

| Port | Service |
|---:|---|
| `9050/tcp` | Tor SOCKS proxy |
| `8118/tcp` | Privoxy HTTP proxy |
| `8088/tcp` | ProxyTor API/dashboard |

Recommended protections:

- Keep proxy ports restricted to trusted networks.
- Publish the dashboard only behind VPN, private access or a protected reverse proxy.
- Use strong admin and viewer tokens.
- Rotate tokens periodically.
- Keep Telegram bot credentials private.
- Review audit events regularly.
- Protect reverse proxy IPs from accidental bans.

## Secrets

Never commit:

- `/etc/proxytor-api/token`
- `/etc/proxytor-api/token.viewer`
- `/etc/default/proxytor-telegram`
- Telegram bot tokens
- Real internal IP addresses
- Production domains
- Private certificates or keys

## Reporting security issues

If you find a security issue, please open a private security advisory or contact the maintainer directly before publishing details.
