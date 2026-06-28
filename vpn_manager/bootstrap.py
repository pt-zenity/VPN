"""Instalación «llave en mano» de los servidores VPN.

Reutiliza los conocidos instaladores de angristan (MIT), que además de instalar los
paquetes configuran el servidor completo (PKI, server.conf, firewall/NAT, primer
cliente) en muchas distribuciones:

- OpenVPN:   https://github.com/angristan/openvpn-install   (openvpn-install.sh)
- WireGuard: https://github.com/angristan/wireguard-install (wireguard-install.sh)

NO incluimos su código en el repositorio: el panel **descarga** el script de una URL
**fijada a un commit concreto** y **verifica su SHA-256** antes de ejecutarlo (cadena
de suministro). Sin checksum configurado, no se ejecuta (fail-closed). En sandbox solo
se simula (no descarga ni ejecuta).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import urllib.request
from pathlib import Path

REPOS = {
    "openvpn": "angristan/openvpn-install",
    "wireguard": "angristan/wireguard-install",
}


class BootstrapError(Exception):
    """Error de negocio en la instalación llave en mano."""


def _source(backend: str, settings) -> tuple[str, str]:
    if backend == "openvpn":
        return settings.bootstrap_openvpn_url, settings.bootstrap_openvpn_sha256
    if backend == "wireguard":
        return settings.bootstrap_wireguard_url, settings.bootstrap_wireguard_sha256
    raise BootstrapError(f"Backend no válido: «{backend}».")


def fetch_and_verify(url: str, sha256_expected: str, dest: Path) -> Path:
    """Descarga `url`, comprueba su SHA-256 y lo guarda en `dest` (modo 700)."""
    if not url:
        raise BootstrapError("No hay URL del script configurada.")
    if not sha256_expected:
        raise BootstrapError("No hay SHA-256 configurado: no se ejecuta sin verificar.")
    if not url.startswith(("https://", "file://")):
        raise BootstrapError("La URL debe ser https://.")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (esquema validado)
            data = resp.read()
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"No se pudo descargar el script: {e}") from e
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, sha256_expected.strip().lower()):
        raise BootstrapError(
            "El SHA-256 del script descargado NO coincide con el configurado "
            f"(esperado {sha256_expected[:12]}…, obtenido {actual[:12]}…). No se ejecuta."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(0o700)
    return dest


def unattended_env(backend: str, settings) -> dict[str, str]:
    """Variables para ejecutar el script en modo desatendido (best-effort, ajustable)."""
    if backend == "openvpn":
        return {
            "AUTO_INSTALL": "y", "APPROVE_INSTALL": "y", "APPROVE_IP": "y",
            "IPV6_SUPPORT": "n", "PORT_CHOICE": "1", "PROTOCOL_CHOICE": "1",
            "DNS": "1", "COMPRESSION_ENABLED": "n", "CUSTOMIZE_ENC": "n",
            "CLIENT": "cliente1", "PASS": "1",
            "ENDPOINT": settings.openvpn_public_endpoint,
        }
    return {"AUTO_INSTALL": "y"}  # wireguard-install autodetecta la mayoría


def plan(backend: str, settings) -> dict:
    url, sha = _source(backend, settings)
    return {
        "backend": backend,
        "repo": REPOS.get(backend, ""),
        "url": url,
        "checksum_configured": bool(url and sha),
        "env": unattended_env(backend, settings),
    }


def run(backend: str, settings, sandbox: bool) -> dict:
    url, sha = _source(backend, settings)
    p = plan(backend, settings)
    if not (url and sha):
        raise BootstrapError(
            "Instalación llave en mano no configurada: fija la URL (a un commit) y su "
            "SHA-256 en VPNM_BOOTSTRAP_* para este backend."
        )
    if sandbox:
        return {"installed": False, "simulated": True, "plan": p,
                "detail": "Sandbox: se descargaría y verificaría el script, sin ejecutarlo."}
    if not settings.allow_install:
        raise BootstrapError("Instalación deshabilitada. Activa VPNM_ALLOW_INSTALL=true.")
    if os.geteuid() != 0:
        raise BootstrapError("La instalación requiere ejecutarse como root.")

    dest = Path(settings.bootstrap_dir) / f"{backend}-install.sh"
    fetch_and_verify(url, sha, dest)  # pragma: no cover - red + root
    env = {**os.environ, **unattended_env(backend, settings)}
    try:  # pragma: no cover - requiere root
        r = subprocess.run(
            ["bash", str(dest)], env=env, capture_output=True, text=True, timeout=900, check=True
        )
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise BootstrapError(f"El instalador falló: {e.stderr.strip() or e}") from e
    except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
        raise BootstrapError(f"No se pudo ejecutar el instalador: {e}") from e
    return {"installed": True, "simulated": False, "plan": p, "output": r.stdout[-3000:]}
