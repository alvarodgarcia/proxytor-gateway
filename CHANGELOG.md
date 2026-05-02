# Changelog

All notable changes to ProxyTor Gateway will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning where possible.

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
