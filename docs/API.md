# API Notes

ProxyTor Gateway exposes a FastAPI service on port `8088`.

The API is intended to be accessed from trusted networks, a VPN, or a protected reverse proxy. Do not expose it directly to the Internet without additional protection.

## Authentication

Authentication uses bearer tokens.

Roles:

| Role | Permissions |
|---|---|
| `viewer` | Read-only access to dashboard data, metrics, events and exports |
| `admin` | Full access, including service actions, token rotation and ban management |

Example:

```bash
curl -H "Authorization: Bearer ADMIN_TOKEN" http://127.0.0.1:8088/api/me
```

## Common endpoints

| Method | Endpoint | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/me` | viewer | Show authenticated role |
| `GET` | `/api/health` | viewer | Health check |
| `GET` | `/api/stats` | viewer | Current service, traffic and client stats |
| `GET` | `/api/history` | viewer | Historical metrics |
| `GET` | `/api/events` | viewer | Recent audit events |
| `GET` | `/api/events/export` | viewer | Export audit events as CSV/JSON |
| `GET` | `/api/bans` | viewer | List bans |
| `POST` | `/api/action/newnym` | admin | Request a new Tor circuit |
| `POST` | `/api/action/ban/{ip}` | admin | Ban a client IP |
| `POST` | `/api/action/unban/{ip}` | admin | Remove a client ban |
| `POST` | `/api/service/{service}/{action}` | admin | Manage supported services |

## Event export example

```bash
curl -H "Authorization: Bearer VIEWER_TOKEN" \
  "http://127.0.0.1:8088/api/events/export?date_from=2026-01-01&date_to=2026-01-31&format=csv" \
  -o proxytor-events.csv
```

Supported export formats:

- `csv`
- `json`

## Notes

- Sensitive actions must require the `admin` role.
- Viewer tokens should never be able to restart services, rotate tokens or manage bans.
- Keep API access restricted to trusted networks.
