"""Configuración del VPN Manager.

Seguro por defecto: en desarrollo apunta a `./sandbox`, NUNCA al VPN real del
servidor. Apuntar a producción (`/etc/openvpn`, `/etc/wireguard`) es una decisión
explícita vía variables de entorno.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Raíz del repo (…/vpn-manager).
ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "sandbox"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VPNM_", env_file=".env")

    # Si True (por defecto), trabaja contra el sandbox y NO toca el sistema real.
    sandbox: bool = True

    # OpenVPN
    openvpn_pki_index: Path = SANDBOX / "openvpn" / "pki" / "index.txt"
    openvpn_status_file: Path = SANDBOX / "openvpn" / "openvpn-status.log"
    openvpn_log_file: Path = SANDBOX / "openvpn" / "openvpn.log"
    openvpn_server_conf: Path = SANDBOX / "openvpn" / "server.conf"
    openvpn_service: str = "openvpn-server@server"
    # IP o dominio público al que se conectan los clientes (va en el .ovpn).
    openvpn_public_endpoint: str = "vpn.ejemplo.local"

    # WireGuard
    wireguard_dir: Path = SANDBOX / "wireguard"
    wireguard_conf: Path = SANDBOX / "wireguard" / "wg0.conf"
    wireguard_show_file: Path = SANDBOX / "wireguard" / "wg-show.txt"
    wireguard_log_file: Path = SANDBOX / "wireguard" / "wireguard.log"
    wireguard_interface: str = "wg0"
    wireguard_public_endpoint: str = "vpn.ejemplo.local"
    wireguard_dns: str = "1.1.1.1"

    # ── Autenticación del panel ────────────────────────────────────────────
    admin_user: str = "admin"
    # Hash PBKDF2 (`pbkdf2_sha256$it$salt$hash`). Vacío => en sandbox usa una
    # credencial de desarrollo con aviso; en producción la app se niega a arrancar.
    admin_password_hash: str = ""
    # Clave para firmar la cookie de sesión. Vacía => se genera una efímera (las
    # sesiones se invalidan al reiniciar). En producción, fijar VPNM_SECRET_KEY.
    secret_key: str = ""
    session_max_age: int = 8 * 3600  # 8 horas
    cookie_secure: bool = False  # poner True detrás de HTTPS
    # Fichero de usuarios del panel (multiusuario + roles). Si no existe, se siembra
    # con el admin de arriba.
    users_file: Path = SANDBOX / "data" / "users.json"

    # ── Entrega de configuraciones (guardar en ruta / enviar por correo) ────
    # Directorio base PERMITIDO para guardar configs en el servidor (anti-traversal).
    export_dir: Path = SANDBOX / "exports"
    # SMTP para enviar la config por correo. Si smtp_host está vacío, en sandbox se
    # simula (se guarda un .eml en export_dir/outbox); en producción da error.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "vpn-manager@localhost"
    smtp_starttls: bool = True


settings = Settings()
