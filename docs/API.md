
API Notes

ProxyTor Gateway exposes a FastAPI service on port 8088.

Use bearer token authentication:

curl -H "Authorization: Bearer ADMIN_TOKEN" http://127.0.0.1:8088/api/me

Roles:

admin - full access
viewer - read-only access
