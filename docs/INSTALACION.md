# VPN Manager — Manual de instalación

Guía para instalar y poner en marcha VPN Manager, tanto en **desarrollo** (modo
sandbox, sin tocar ningún servidor real) como en **producción** (gestionando un
servidor OpenVPN y/o WireGuard real).

> Principio de seguridad: por defecto la aplicación trabaja contra `./sandbox/` y
> **nunca** toca el sistema. Apuntar a un servidor real es una decisión explícita por
> configuración.

---

## 1. Requisitos

- **Python 3.11 o superior**.
- En producción, en la misma máquina que el servidor VPN:
  - OpenVPN + **easy-rsa** (para la PKI) si se gestiona OpenVPN.
  - **wireguard-tools** (`wg`, `wg-quick`) si se gestiona WireGuard.
  - Permisos para leer/escribir la configuración del servidor y ejecutar
    `systemctl` sobre el servicio (normalmente vía `sudo`/unidad systemd).

---

## 2. Instalación en desarrollo (sandbox)

```bash
git clone https://github.com/jl-segurayuste/vpn-manager.git
cd vpn-manager
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Arranca el panel (modo sandbox por defecto)
python -m vpn_manager
```

- Panel en **http://127.0.0.1:8200**.
- Credenciales de desarrollo: **admin / admin** (aviso en el log; cámbialas para prod).
- Trabaja contra `./sandbox/` con datos de demostración; no toca nada del sistema.

### Pruebas y calidad

```bash
pytest -q          # 65 pruebas
ruff check .       # estilo
```

---

## 3. Configuración (variables de entorno)

Copia `.env.example` a `.env` y ajusta. Todas las variables llevan prefijo `VPNM_`.

### Generales y autenticación

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_SANDBOX` | `true` | `false` para gestionar el servidor real. |
| `VPNM_ADMIN_USER` | `admin` | Usuario administrador. |
| `VPNM_ADMIN_PASSWORD_HASH` | *(vacío)* | Hash PBKDF2. **Obligatorio en producción.** Genera con `python -m vpn_manager.hashpw`. |
| `VPNM_SECRET_KEY` | *(vacío)* | Clave de firma de sesión. **Obligatoria en producción** (`python -c "import secrets;print(secrets.token_hex(32))"`). |
| `VPNM_COOKIE_SECURE` | `false` | `true` detrás de HTTPS. |

### OpenVPN

| Variable | Por defecto (sandbox) |
|----------|------------------------|
| `VPNM_OPENVPN_PKI_INDEX` | `sandbox/openvpn/pki/index.txt` → real: `/etc/openvpn/server/pki/index.txt` |
| `VPNM_OPENVPN_STATUS_FILE` | `sandbox/openvpn/openvpn-status.log` → real: el `status` del servidor |
| `VPNM_OPENVPN_LOG_FILE` | `sandbox/openvpn/openvpn.log` |
| `VPNM_OPENVPN_SERVER_CONF` | `sandbox/openvpn/server.conf` → real: `/etc/openvpn/server/server.conf` |
| `VPNM_OPENVPN_SERVICE` | `openvpn-server@server` |
| `VPNM_OPENVPN_PUBLIC_ENDPOINT` | `vpn.ejemplo.local` (IP/dominio público que va en el `.ovpn`) |

### WireGuard

| Variable | Por defecto (sandbox) |
|----------|------------------------|
| `VPNM_WIREGUARD_CONF` | `sandbox/wireguard/wg0.conf` → real: `/etc/wireguard/wg0.conf` |
| `VPNM_WIREGUARD_SHOW_FILE` | `sandbox/wireguard/wg-show.txt` (en real se usa `wg show`) |
| `VPNM_WIREGUARD_INTERFACE` | `wg0` |
| `VPNM_WIREGUARD_PUBLIC_ENDPOINT` | `vpn.ejemplo.local` |
| `VPNM_WIREGUARD_DNS` | `1.1.1.1` |

### Instalación de servicios (la app instala OpenVPN/WireGuard)

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_ALLOW_INSTALL` | `false` | Interruptor de seguridad. `true` para permitir instalar (además, el panel debe correr como **root**). |
| `VPNM_BOOTSTRAP_OPENVPN_URL` | *(vacío)* | URL del script de angristan **fijada a un commit** (`…/<COMMIT>/openvpn-install.sh`). |
| `VPNM_BOOTSTRAP_OPENVPN_SHA256` | *(vacío)* | SHA-256 de ese script. **Sin él no se ejecuta.** Cómputo: `curl -sL <url> \| sha256sum`. |
| `VPNM_BOOTSTRAP_WIREGUARD_URL` / `_SHA256` | *(vacío)* | Igual para WireGuard (`angristan/wireguard-install`). |

- **Instalar paquetes**: detecta la distro (apt/dnf/yum/pacman/zypper) e instala los
  paquetes. En RHEL/derivados añade EPEL para OpenVPN.
- **Instalación completa (llave en mano)**: descarga el script de angristan de la versión
  fijada, **verifica su SHA-256** y lo ejecuta (configura PKI + server.conf + firewall +
  primer cliente). En sandbox solo se **simula**.

### Entrega de configuraciones (guardar / correo)

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_EXPORT_DIR` | `sandbox/exports` | Directorio **permitido** para guardar configs (anti–traversal). |
| `VPNM_SMTP_HOST` | *(vacío)* | Servidor SMTP. Si está vacío, en sandbox se simula el envío. |
| `VPNM_SMTP_PORT` | `587` | |
| `VPNM_SMTP_USER` / `VPNM_SMTP_PASSWORD` | *(vacío)* | Credenciales SMTP. |
| `VPNM_SMTP_FROM` | `vpn-manager@localhost` | Remitente. |
| `VPNM_SMTP_STARTTLS` | `true` | STARTTLS. |

---

## 4. Despliegue en producción (interno)

> Recomendado: acceso **solo interno**, detrás de un proxy con HTTPS. No exponer a internet.

1. **Instala** en la máquina del servidor VPN (o con acceso a sus ficheros/servicio):
   ```bash
   python -m venv /opt/vpn-manager/.venv
   /opt/vpn-manager/.venv/bin/pip install -e /opt/vpn-manager
   ```
2. **Crea el `.env`** con `VPNM_SANDBOX=false`, las rutas reales, el hash de contraseña
   (`python -m vpn_manager.hashpw`), `VPNM_SECRET_KEY` y `VPNM_COOKIE_SECURE=true`.
3. **Unidad systemd** (ejemplo `/etc/systemd/system/vpn-manager.service`):
   ```ini
   [Unit]
   Description=VPN Manager
   After=network.target

   [Service]
   WorkingDirectory=/opt/vpn-manager
   EnvironmentFile=/opt/vpn-manager/.env
   ExecStart=/opt/vpn-manager/.venv/bin/python -m vpn_manager
   Restart=on-failure
   # Permisos acotados: solo lo necesario para gestionar el servicio VPN.

   [Install]
   WantedBy=multi-user.target
   ```
   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now vpn-manager
   ```
4. **Proxy inverso + HTTPS** (Caddy/Nginx) delante, en la red interna.
5. **Permisos:** para arrancar/parar el servicio y editar la config, la cuenta del
   servicio necesita acceso (vía `sudoers` acotado o capacidades concretas). Concede
   lo mínimo imprescindible.

---

## 5. Verificación post-instalación

- `GET /health` responde `{"status":"ok","sandbox":false}`.
- El login con tu contraseña real funciona; admin/admin **no** (no hay default en prod).
- En el panel, la sección **Configuración** muestra los parámetros reales del servidor.

Consulta el [Manual de uso](MANUAL-DE-USO.md) para el día a día, y
[AUDITORIA-SEGURIDAD.md](AUDITORIA-SEGURIDAD.md) para la postura de seguridad.
