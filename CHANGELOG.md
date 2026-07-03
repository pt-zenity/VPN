# Changelog

All notable changes to this project are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/);  
versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-07-03

### Added
- **Full English translation** — entire UI, error messages, JS strings, dialogs,
  toasts, confirmation prompts, date locales and API responses translated from
  Spanish to English across all files:
  - `vpn_manager/ui/login.html`
  - `vpn_manager/ui/index.html`
  - `vpn_manager/api/app.py`
  - `vpn_manager/users.py`
  - `vpn_manager/preflight.py`
  - `vpn_manager/installer.py`
  - `vpn_manager/delivery.py`
  - `vpn_manager/bootstrap.py`
- **Versioning system** — `vpn_manager/__init__.py` now exports `__version__ = "1.0.0"`;
  `FastAPI` app uses it; startup banner prints the version.
- **`/api/version` endpoint** — public endpoint returning `{"version": "1.0.0"}`.
- **Version badge** — sidebar footer shows the running version fetched from `/api/version`.
- **`/health` extended** — now includes `"version"` field alongside `status` and `sandbox`.
- **Production configuration** — `.env` and `ecosystem.config.cjs` added for PM2-based
  production deployment with `VPNM_SANDBOX=false`, PBKDF2-SHA256 password hash, and
  random 256-bit session secret key.
- **`CHANGELOG.md`** — this file.
- **`README.md`** — rewritten in English with full feature list, API reference,
  configuration guide, security notes, and deployment instructions.

### Changed
- `pyproject.toml` version bumped `0.3.0` → `1.0.0`.
- `pyproject.toml` description updated to English.
- `__main__.py` startup message now includes version: `VPN Manager v1.0.0 — ...`.
- HTML `lang` attribute changed from `es` to `en` in both `login.html` and `index.html`.
- Date/time locale changed from `es-ES` to `en-GB` throughout the UI.

---

## [0.3.0] — (upstream)

### Added
- WireGuard backend: peers, keys, `wg show`, QR code, editable configuration.
- Activity log page — panel action history (logins, device changes, installs…).
- Audit API (`/api/audit`) with full-text search and level filter.
- Multi-user support with roles: `admin`, `operator`, `viewer`.
- Two-factor authentication (TOTP / Google Authenticator, QR setup flow).
- System page — OS detection, package manager, VPN service install status.
- Bootstrap installer — full server setup via pinned script + SHA-256 verification.
- Prometheus metrics endpoint (`/metrics`).

### Changed
- Password hashing upgraded to PBKDF2-SHA256 with 600,000 iterations.
- Login throttle (IP-based block after repeated failures).

---

## [0.2.0] — (upstream)

### Added
- OpenVPN write operations: create client, revoke, renew, download `.ovpn`.
- Server configuration editor (key fields + raw directives).
- Service control: start, stop, restart, reload.
- Active connections list with disconnect action.
- Email delivery of client configs (SMTP optional).
- Save config to server filesystem.

---

## [0.1.0] — (upstream)

### Added
- Initial release — OpenVPN read-only panel (status, clients, connections, logs).
- FastAPI + Uvicorn backend, single-file HTML/JS frontend.
- Session cookie authentication (PBKDF2 + `itsdangerous`).
- Sandbox mode with demo data in `./sandbox/`.
