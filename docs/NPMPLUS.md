# NPMplus / Reverse Proxy

ProxyTor Gateway can be published behind NPMplus or another reverse proxy for dashboard access.

Only the dashboard/API port should be published through a normal HTTP reverse proxy.

## Recommended dashboard proxy host

| Field | Value |
|---|---|
| Domain | `proxytor.example.com` |
| Scheme | `http` |
| Forward Host/IP | `PROXYTOR_IP` |
| Forward Port | `8088` |
| Websockets | Off |
| Force SSL | On |
| HTTP/2 | On |

## Important warning

Do not expose these services as regular HTTP proxy hosts:

| Port | Service | Recommendation |
|---:|---|---|
| `9050/tcp` | Tor SOCKS | Keep LAN/VPN only |
| `8118/tcp` | Privoxy HTTP proxy | Keep LAN/VPN only |
| `8088/tcp` | ProxyTor API | Publish only with authentication/protection |

## Client IP visibility

If clients connect directly to ProxyTor, the dashboard can identify the real client IP.

If clients connect through a TCP stream or reverse proxy, ProxyTor may only see the reverse proxy IP. In that case, abuse detection and bans may affect the reverse proxy instead of the original client.

Protect reverse proxy IPs in `protected_ips` and `npmplus_ips`.

## Suggested access model

- Use direct LAN/VPN access for `9050` and `8118`.
- Use NPMplus/reverse proxy only for the dashboard on `8088`.
- Add extra authentication at the reverse proxy layer when possible.
- Keep admin tokens private.
