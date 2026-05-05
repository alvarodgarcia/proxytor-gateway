# Changelog

All notable changes to ProxyTor Gateway will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning where possible.

## [Unreleased]

### Added

- Local root-helper architecture for privileged operations through `proxytor-root-helper.service`.
- Split-privilege deployment model with `proxytor-api.service` running as `proxytor-api`.
- HTTP security headers for the dashboard/API.
- Configurable HTTPS-based GeoIP lookup with caching controls.
- Auth and admin-action rate limiting.
- Map fallback states for missing or partial geolocation data.

### Changed

- Admin token rotation no longer exposes the new token through API responses or chat notifications.
- Dashboard token handling now stays in browser memory instead of persistent storage.
- Dynamic dashboard rendering now avoids unsafe HTML injection paths.
- Firewall-dependent ban logic now degrades gracefully on hosts or containers without usable `iptables`/`nft`.
- Installer now provisions the unprivileged service account and root-helper service.

### Security

- Reduced dashboard privilege from full root to a narrow local privileged helper.
- Restricted subprocess execution environment for service, journal and firewall actions.
- Added API-side throttling for repeated authentication failures and admin write actions.

## [v0.1.1] - 2026-05-02

### Added

- Added release notes under `docs/releases/v0.1.1.md`.
- Added documentation for safer installer re-run behaviour.
- Added documentation for installer options:
  - `--dry-run`
  - `--skip-packages`
  - `--force-config`
  - `--help`

### Changed

- Improved installer idempotency.
- Existing Tor and Privoxy configuration files are preserved by default.
- ProxyTor Tor and Privoxy example configurations are installed separately.
- Existing tokens, `config.json` and Telegram environment configuration are preserved.
- Existing Python virtual environment is reused when present.
- README roadmap updated to reflect completed installer, dashboard screenshots and CI validation work.

### Security

- Reduced risk of accidental configuration overwrite during repeated installs.
- Added safer operational guidance for re-running the installer.
- Kept production values and private environment data out of public documentation.

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
