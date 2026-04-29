# Optional Reverse Proxy / NPMplus

ProxyTor Gateway does **not** require NPMplus.

ProxyTor works standalone with direct LAN/VPN access:

| Service | URL / Endpoint | Required |
|---|---|---|
| Dashboard/API | `http://PROXYTOR_IP:8088/` | Yes |
| Privoxy HTTP proxy | `http://PROXYTOR_IP:8118` | Yes |
| Tor SOCKS5 proxy | `PROXYTOR_IP:9050` | Optional client mode |

NPMplus is only one possible way to publish the dashboard/API over HTTPS. You may also use Nginx Proxy Manager, plain Nginx, Caddy, Traefik, Cloudflare Tunnel, Tailscale, WireGuard or any equivalent secure access layer.

## When to use a reverse proxy

Use a reverse proxy only if you want to expose the **dashboard/API** using a domain and HTTPS.

Do **not** publish the proxy ports through a normal HTTP reverse proxy.

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

Do not expose these services directly to the Internet:

| Port | Service | Recommendation |
|---:|---|---|
| `9050/tcp` | Tor SOCKS | Keep LAN/VPN only |
| `8118/tcp` | Privoxy HTTP proxy | Keep LAN/VPN only |
| `8088/tcp` | ProxyTor API | Publish only with authentication/protection |

## Configuration notes

The `npmplus_ips` setting is optional. Leave it empty if you are not using NPMplus or TCP streams:

```json
"npmplus_ips": []
```

If you use NPMplus or another reverse proxy/TCP stream in front of ProxyTor, add those proxy IPs to both `npmplus_ips` and `protected_ips` to avoid accidental self-bans:

```json
"npmplus_ips": [
  "REVERSE_PROXY_IP_1",
  "REVERSE_PROXY_IP_2",
  "REVERSE_PROXY_VIP"
],
"protected_ips": [
  "127.0.0.1",
  "LAN_GATEWAY_IP",
  "PROXYTOR_IP",
  "REVERSE_PROXY_IP_1",
  "REVERSE_PROXY_IP_2",
  "REVERSE_PROXY_VIP"
]
```

## Client IP visibility

If clients connect directly to ProxyTor, the dashboard can identify the real client IP.

If clients connect through a TCP stream or reverse proxy, ProxyTor may only see the reverse proxy IP. In that case, abuse detection and bans may affect the reverse proxy instead of the original client.

## Suggested access model

- Use direct LAN/VPN access for `9050` and `8118`.
- Use NPMplus or another reverse proxy only for the dashboard on `8088`.
- Add extra authentication at the reverse proxy layer when possible.
- Keep admin tokens private.
