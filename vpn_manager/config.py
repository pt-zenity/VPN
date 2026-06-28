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
    openvpn_service: str = "openvpn-server@server"

    # WireGuard (se completará en su fase)
    wireguard_dir: Path = SANDBOX / "wireguard"
    wireguard_interface: str = "wg0"

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


settings = Settings()
