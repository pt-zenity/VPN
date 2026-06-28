"""E2E de la interfaz web (navegador real, Playwright + Chrome del sistema).

Arranca el panel en un subproceso aislado (copia temporal del sandbox, para no tocar
los fixtures del repo) y verifica el flujo real en navegador: login → panel → alta de
dispositivo → aparece en la lista → su configuración es descargable.

Separado de la suite unitaria (`tests/`): requiere Chrome. Ejecutar con:
    pip install -e ".[e2e]" && pytest e2e/
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PORT = 8211
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    work = tmp_path_factory.mktemp("e2e")
    sb = work / "sandbox"
    shutil.copytree(REPO / "sandbox", sb)
    ov, wg, data = sb / "openvpn", sb / "wireguard", sb / "data"
    env = {
        **os.environ,
        "VPNM_HOST": "127.0.0.1", "VPNM_PORT": str(PORT), "VPNM_SANDBOX": "true",
        "VPNM_OPENVPN_PKI_INDEX": str(ov / "pki" / "index.txt"),
        "VPNM_OPENVPN_STATUS_FILE": str(ov / "openvpn-status.log"),
        "VPNM_OPENVPN_LOG_FILE": str(ov / "openvpn.log"),
        "VPNM_OPENVPN_SERVER_CONF": str(ov / "server.conf"),
        "VPNM_WIREGUARD_CONF": str(wg / "wg0.conf"),
        "VPNM_WIREGUARD_SHOW_FILE": str(wg / "wg-show.txt"),
        "VPNM_WIREGUARD_LOG_FILE": str(wg / "wireguard.log"),
        "VPNM_USERS_FILE": str(data / "users.json"),
        "VPNM_AUDIT_FILE": str(data / "audit.jsonl"),
        "VPNM_EXPORT_DIR": str(sb / "exports"),
    }
    proc = subprocess.Popen([sys.executable, "-m", "vpn_manager"], env=env, cwd=str(REPO))
    try:
        _wait_health()
        yield BASE
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _launch(p):
    """Chromium de Playwright (CI) o, si no está, el Chrome del sistema (local)."""
    try:
        return p.chromium.launch(headless=True)
    except Exception:  # noqa: BLE001
        return p.chromium.launch(channel="chrome", headless=True)


def _wait_health(timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if urllib.request.urlopen(f"{BASE}/health", timeout=2).status == 200:
                return
        except Exception:  # noqa: BLE001
            time.sleep(0.4)
    raise RuntimeError("el servidor no respondió a /health a tiempo")


def test_login_y_alta_de_dispositivo(server):
    playwright = pytest.importorskip("playwright.sync_api")
    with playwright.sync_playwright() as p:
        browser = _launch(p)
        page = browser.new_page()
        try:
            # Login.
            page.goto(f"{server}/login")
            page.fill("#u", "admin")
            page.fill("#p", "admin")
            page.click("button[type=submit]")
            page.wait_for_url(f"{server}/")
            assert "Panel de la VPN" in page.locator("h1").inner_text()

            # Ir a Dispositivos y dar de alta uno.
            page.click("nav a[data-page='clientes']")
            page.click("#add-btn")
            page.fill("#add-name", "e2e-portatil")
            page.click("button:has-text('Crear acceso')")

            # Aparece en la lista con su configuración descargable (en SU fila).
            page.wait_for_selector("text=e2e-portatil", timeout=8000)
            row = page.locator("#clients .row", has_text="e2e-portatil")
            link = row.locator("a.act", has_text="Descargar")
            assert "e2e-portatil/config" in (link.get_attribute("href") or "")
        finally:
            browser.close()
