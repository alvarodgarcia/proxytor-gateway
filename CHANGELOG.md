# Changelog

All notable changes to ProxyTor Gateway will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning where possible.

## [v0.1.0] - 2026-04-29

### Added

- Initial public project scaffold.
- Tor SOCKS5 gateway support.
- Privoxy HTTP proxy forwarding through Tor.
- FastAPI dashboard/API.
- Admin and viewer token model.
- Telegram bot integration.
- Token rotation support.
- SQLite persistence.
- Audit and event logging.
- CSV/JSON audit export by date range.
- Recent client tracking.
- Abuse detection based on connection thresholds.
- Ban/unban workflows through dashboard and Telegram.
- systemd service units.
- Example configuration files.

### Security

- Production secrets are excluded from the repository.
- Example configuration uses placeholders instead of real environment values.
- Tor exit IP change Telegram alerts are disabled by default to reduce alert noise.
