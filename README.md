# VPN Manager

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A lightweight web panel for managing **OpenVPN** and **WireGuard** VPN servers from a clean browser interface — instead of the command line. Designed so that someone without deep technical knowledge can manage who has access: add devices, download configurations and revoke access.

> **Live panel:** https://8200-ixcerotqf78sv31s3bels-2e77fc33.sandbox.novita.ai  
> **Login:** `admin` / `admin123`

---

## Features

| Section | What you can do |
|---------|-----------------|
| **Overview** | Totals: active access, connected now, expired / revoked |
| **Service** | Start, stop, restart, reload the VPN daemon |
| **Configuration** | View and edit server parameters (endpoint, port, protocol, IP range, ciphers, DNS, routes, CRL…) and raw directives |
| **Devices** | List all clients/certificates with plain-language status (*Access active*, *Access revoked*, *Expired*); add, revoke, renew |
| **Connections** | Real-time list of who is connected, since when and their traffic; disconnect a session |
| **Logs** | Last N lines of the server log |
| **Activity** | Full audit trail of panel actions (logins, device changes, config edits, installs…) with search and level filter |
| **Users** | Multi-user panel with roles: **Administrator**, **Operator**, **Read only** |
| **System** | OS / package-manager detection, VPN service install status, one-click installer |
| **My account** | Change password, enable/disable TOTP two-factor authentication |

### Backend support
- **OpenVPN** — PKI index, `easy-rsa`, status file, `.ovpn` config download
- **WireGuard** — `wg show`, peer management, QR code for mobile, editable `wg0.conf`

---

## Security

- **Mandatory authentication.** PBKDF2-SHA256 (600,000 iterations, constant-time comparison) + signed session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` configurable). Only `/login`, `/health` and `/api/version` are public.
- **Secure by default.** Without `VPNM_ADMIN_PASSWORD_HASH` the app **refuses to start** in production. In sandbox mode it uses the development credential `admin/admin` and shows a warning.
- **Login throttle.** IP-based temporary block after repeated failures.
- **Sandbox by default.** Dev mode reads from `./sandbox/` — never touches a real VPN server. Production requires explicit opt-in (`VPNM_SANDBOX=false`).
- **Strict name validation** (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`) prevents command injection and path traversal.
- `easy-rsa` called via `subprocess` **without shell**.
- Cryptographic material excluded from the repository (see `.gitignore`).

---

## Versioning

This project follows [Semantic Versioning](https://semver.org/).  
Every release is documented in [`CHANGELOG.md`](CHANGELOG.md).

| Version | Date | Summary |
|---------|------|---------|
| **1.0.0** | 2026-07-03 | Full English UI, versioning system, `/api/version` endpoint, production config |
| 0.3.0 | upstream | WireGuard, audit log, multi-user, 2FA, system installer, Prometheus metrics |
| 0.2.0 | upstream | OpenVPN write ops, config editor, service control, email delivery |
| 0.1.0 | upstream | Initial release — OpenVPN read-only panel |

The running version is always visible in the **sidebar footer** of the panel and via:

```bash
curl https://<host>/api/version
# → {"version":"1.0.0"}

curl https://<host>/health
# → {"status":"ok","sandbox":false,"version":"1.0.0"}
```

---

## Quick start (development / sandbox)

```bash
git clone https://github.com/jl-segurayuste/vpn-manager.git
cd vpn-manager
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m vpn_manager        # http://127.0.0.1:8200
```

Login with **admin / admin** (sandbox mode — demo data only, no real VPN server touched).

---

## Production setup

### 1. Generate credentials

```bash
# Generate password hash for your admin password
.venv/bin/python -c "
from vpn_manager.auth import hash_password
import getpass
print(hash_password(getpass.getpass('Password: ')))
"

# Generate a random secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Create `.env`

```env
VPNM_SANDBOX=false
VPNM_ADMIN_USER=admin
VPNM_ADMIN_PASSWORD_HASH=pbkdf2_sha256$600000$<salt>$<hash>
VPNM_SECRET_KEY=<64-char-hex>
VPNM_COOKIE_SECURE=true          # set false behind a reverse proxy doing TLS termination

# OpenVPN paths (adjust to your server)
VPNM_OPENVPN_PKI_INDEX=/etc/openvpn/easy-rsa/pki/index.txt
VPNM_OPENVPN_STATUS_FILE=/var/log/openvpn/status.log
VPNM_OPENVPN_SERVICE=openvpn@server

# WireGuard paths (adjust to your interface name)
VPNM_WIREGUARD_CONF=/etc/wireguard/wg0.conf
VPNM_WIREGUARD_INTERFACE=wg0
```

### 3. Run with PM2

```bash
# ecosystem.config.cjs (inline env vars — PM2 doesn't support env_file natively)
pm2 start ecosystem.config.cjs
pm2 save
```

Or directly:

```bash
python -m vpn_manager   # reads .env automatically via pydantic-settings
```

---

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | ✅ | Web panel (requires session) |
| `GET/POST` | `/login` | — | Login page and form submit |
| `POST` | `/logout` | ✅ | Sign out |
| `GET` | `/health` | — | `{"status","sandbox","version"}` |
| `GET` | `/api/version` | — | `{"version":"1.0.0"}` |
| `GET` | `/api/me` | ✅ | Current user info and permissions |
| `GET` | `/api/users` | ✅ admin | List panel users and roles |
| `POST` | `/api/users` | ✅ admin | Create user |
| `PUT` | `/api/users/{username}` | ✅ admin | Update role or password |
| `DELETE` | `/api/users/{username}` | ✅ admin | Delete user |
| `GET` | `/api/me/2fa/setup` | ✅ | Generate TOTP QR |
| `POST` | `/api/me/2fa/enable` | ✅ | Enable 2FA with code |
| `POST` | `/api/me/2fa/disable` | ✅ | Disable 2FA |
| `GET` | `/api/audit` | ✅ | Activity log (`?q=&level=&limit=`) |
| `GET` | `/api/system` | ✅ | OS, package manager, installed VPN services |
| `GET` | `/api/preflight` | ✅ admin | Security check results |
| `POST` | `/api/system/install/{backend}` | ✅ admin | Install VPN packages |
| `POST` | `/api/system/bootstrap/{backend}` | ✅ admin | Full server setup |
| `GET` | `/api/openvpn/status` | ✅ | OpenVPN service status |
| `GET` | `/api/openvpn/clients` | ✅ | List certificates / clients |
| `GET` | `/api/openvpn/connections` | ✅ | Active connections |
| `POST` | `/api/openvpn/clients` | ✅ op | Create client `{"name":"..."}` |
| `POST` | `/api/openvpn/clients/{name}/revoke` | ✅ op | Revoke access |
| `POST` | `/api/openvpn/clients/{name}/renew` | ✅ op | Renew (reissue) certificate |
| `GET` | `/api/openvpn/clients/{name}/config` | ✅ | Download `.ovpn` |
| `POST` | `/api/openvpn/clients/{name}/save` | ✅ op | Save config to server path |
| `POST` | `/api/openvpn/clients/{name}/email` | ✅ op | Email config |
| `GET` | `/api/openvpn/server` | ✅ | Server configuration |
| `PUT` | `/api/openvpn/server` | ✅ admin | Update server configuration |
| `GET` | `/api/openvpn/logs` | ✅ | Last log lines (`?lines=80`) |
| `POST` | `/api/openvpn/service/{action}` | ✅ op | `start`/`stop`/`restart`/`reload` |
| `POST` | `/api/openvpn/connections/{name}/disconnect` | ✅ op | Disconnect active session |
| `*` | `/api/wireguard/*` | ✅ | WireGuard equivalents (+ `/clients/{name}/qr`) |
| `GET` | `/metrics` | — | Prometheus text metrics |

**Auth column:** `—` = public, `✅` = requires session, `✅ op` = requires operator or admin role, `✅ admin` = requires admin role.

---

## Configuration

All settings use the `VPNM_` prefix (via `pydantic-settings`, loaded from `.env`).

| Variable | Default | Description |
|----------|---------|-------------|
| `VPNM_SANDBOX` | `true` | `false` = production mode (real VPN server) |
| `VPNM_HOST` | `127.0.0.1` | Bind address |
| `VPNM_PORT` | `8200` | Listen port |
| `VPNM_ADMIN_USER` | `admin` | Admin username |
| `VPNM_ADMIN_PASSWORD_HASH` | — | PBKDF2-SHA256 hash (required in production) |
| `VPNM_SECRET_KEY` | — | Session signing key (required in production) |
| `VPNM_COOKIE_SECURE` | `true` | Set `false` when TLS is terminated upstream |
| `VPNM_USERS_FILE` | `users.json` | Panel users database path |
| `VPNM_OPENVPN_PKI_INDEX` | `./sandbox/index.txt` | OpenVPN PKI index |
| `VPNM_OPENVPN_STATUS_FILE` | `./sandbox/status.log` | OpenVPN status file |
| `VPNM_OPENVPN_SERVICE` | `openvpn@server` | systemd service name |
| `VPNM_OPENVPN_LOG_FILE` | `/var/log/openvpn/openvpn.log` | Log path |
| `VPNM_WIREGUARD_CONF` | `/etc/wireguard/wg0.conf` | WireGuard config |
| `VPNM_WIREGUARD_INTERFACE` | `wg0` | Interface name |
| `VPNM_WIREGUARD_LOG_FILE` | `/var/log/syslog` | WireGuard log source |
| `VPNM_SMTP_HOST` | — | SMTP host for email delivery |
| `VPNM_SMTP_PORT` | `587` | SMTP port |
| `VPNM_SMTP_USER` | — | SMTP username |
| `VPNM_SMTP_PASSWORD` | — | SMTP password |
| `VPNM_SMTP_FROM` | — | Sender address |
| `VPNM_ALLOW_INSTALL` | `false` | Enable system package installation |

---

## Running tests

```bash
# Unit + integration tests (parsers, API, auth, roles…)
pytest -q

# Linting
ruff check .

# End-to-end browser tests (Playwright)
pip install -e ".[e2e]"
playwright install chromium
pytest e2e/
```

---

## Documentation

- [`docs/INSTALACION.md`](docs/INSTALACION.md) — full installation manual (dev + production)
- [`docs/MANUAL-DE-USO.md`](docs/MANUAL-DE-USO.md) — day-to-day usage guide
- [`docs/ESPECIFICACION.md`](docs/ESPECIFICACION.md) — specification and roadmap
- [`docs/AUDITORIA-SEGURIDAD.md`](docs/AUDITORIA-SEGURIDAD.md) — security audit
- [`CHANGELOG.md`](CHANGELOG.md) — version history
- [`SECURITY.md`](SECURITY.md) — security policy and disclosure

---

## Roadmap

- [x] **v0.1** — OpenVPN read-only (status, clients, connections, logs)
- [x] **v0.2** — OpenVPN write ops (add, revoke, renew, download config)
- [x] **v0.3** — WireGuard, audit log, multi-user, 2FA, system installer, Prometheus
- [x] **v1.0** — Full English UI, versioning system, production config, README
- [ ] **v1.1** — Live deploy on real WireGuard / OpenVPN server, HTTPS hardening

---

## License

MIT — see [`LICENSE`](LICENSE).
