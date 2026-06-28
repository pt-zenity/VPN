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
    openvpn_service: str = "openvpn-server@server"

    # WireGuard (se completará en su fase)
    wireguard_dir: Path = SANDBOX / "wireguard"
    wireguard_interface: str = "wg0"


settings = Settings()
