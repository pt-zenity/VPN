"""Turn-key installation of VPN servers.

Reuses the well-known angristan installers (MIT), which in addition to installing
packages set up the entire server (PKI, server.conf, firewall/NAT, first client)
on many distributions:

- OpenVPN:   https://github.com/angristan/openvpn-install   (openvpn-install.sh)
- WireGuard: https://github.com/angristan/wireguard-install (wireguard-install.sh)

We do NOT include their code in the repository: the panel **downloads** the script
from a URL **pinned to a specific commit** and **verifies its SHA-256** before
executing it (supply chain). Without a configured checksum, it does not run
(fail-closed). In sandbox mode it is only simulated (no download or execution).
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
    """Business error in turn-key installation."""


def _source(backend: str, settings) -> tuple[str, str]:
    if backend == "openvpn":
        return settings.bootstrap_openvpn_url, settings.bootstrap_openvpn_sha256
    if backend == "wireguard":
        return settings.bootstrap_wireguard_url, settings.bootstrap_wireguard_sha256
    raise BootstrapError(f"Invalid backend: «{backend}».")


def fetch_and_verify(url: str, sha256_expected: str, dest: Path) -> Path:
    """Downloads `url`, verifies its SHA-256 and saves it to `dest` (mode 700)."""
    if not url:
        raise BootstrapError("No script URL configured.")
    if not sha256_expected:
        raise BootstrapError("No SHA-256 configured: will not execute without verification.")
    if not url.startswith(("https://", "file://")):
        raise BootstrapError("URL must use https://.")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (scheme validated)
            data = resp.read()
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"Could not download the script: {e}") from e
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, sha256_expected.strip().lower()):
        raise BootstrapError(
            "The SHA-256 of the downloaded script does NOT match the configured one "
            f"(expected {sha256_expected[:12]}…, got {actual[:12]}…). Aborting."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(0o700)
    return dest


def unattended_env(backend: str, settings) -> dict[str, str]:
    """Environment variables for running the script in unattended mode (best-effort, adjustable)."""
    if backend == "openvpn":
        return {
            "AUTO_INSTALL": "y", "APPROVE_INSTALL": "y", "APPROVE_IP": "y",
            "IPV6_SUPPORT": "n", "PORT_CHOICE": "1", "PROTOCOL_CHOICE": "1",
            "DNS": "1", "COMPRESSION_ENABLED": "n", "CUSTOMIZE_ENC": "n",
            "CLIENT": "client1", "PASS": "1",
            "ENDPOINT": settings.openvpn_public_endpoint,
        }
    return {"AUTO_INSTALL": "y"}  # wireguard-install auto-detects most settings


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
            "Turn-key installation not configured: set the URL (pinned to a commit) and its "
            "SHA-256 in VPNM_BOOTSTRAP_* for this backend."
        )
    if sandbox:
        return {"installed": False, "simulated": True, "plan": p,
                "detail": "Sandbox: the script would be downloaded and verified, but not executed."}
    if not settings.allow_install:
        raise BootstrapError("Installation disabled. Set VPNM_ALLOW_INSTALL=true to enable.")
    if os.geteuid() != 0:
        raise BootstrapError("Installation requires running as root.")

    dest = Path(settings.bootstrap_dir) / f"{backend}-install.sh"
    fetch_and_verify(url, sha, dest)  # pragma: no cover - red + root
    env = {**os.environ, **unattended_env(backend, settings)}
    try:  # pragma: no cover - requires root
        r = subprocess.run(
            ["bash", str(dest)], env=env, capture_output=True, text=True, timeout=900, check=True
        )
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise BootstrapError(f"The installer failed: {e.stderr.strip() or e}") from e
    except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
        raise BootstrapError(f"Could not execute the installer: {e}") from e
    return {"installed": True, "simulated": False, "plan": p, "output": r.stdout[-3000:]}
