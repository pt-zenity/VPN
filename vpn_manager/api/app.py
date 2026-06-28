"""API FastAPI del VPN Manager.

Fase 1: lectura de OpenVPN (estado, clientes, conexiones).
Fase 2: escritura de OpenVPN (alta, revocación, descarga de configuración).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from ..backends.base import (
    AlreadyExists,
    Forbidden,
    InvalidName,
    NotFound,
    ServiceStatus,
    VpnClient,
    VpnConnection,
    VpnError,
)
from ..backends.openvpn import OpenVpnBackend
from ..config import settings

_UI_INDEX = Path(__file__).resolve().parent.parent / "ui" / "index.html"


def _openvpn() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=settings.sandbox,
    )


def _http(exc: VpnError) -> HTTPException:
    """Traduce un error de dominio al código HTTP correcto."""
    code = {
        InvalidName: 422,
        NotFound: 404,
        AlreadyExists: 409,
        Forbidden: 403,
    }.get(type(exc), 400)
    return HTTPException(status_code=code, detail=str(exc))


class CreateClient(BaseModel):
    name: str = Field(min_length=1, max_length=64)


app = FastAPI(title="VPN Manager", version="0.2.0")


@app.get("/", response_class=HTMLResponse)
def ui() -> str:
    return _UI_INDEX.read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "sandbox": settings.sandbox}


# ── Lectura ────────────────────────────────────────────────────────────────
@app.get("/api/openvpn/status", response_model=ServiceStatus)
def openvpn_status() -> ServiceStatus:
    return _openvpn().status()


@app.get("/api/openvpn/clients", response_model=list[VpnClient])
def openvpn_clients() -> list[VpnClient]:
    return _openvpn().clients()


@app.get("/api/openvpn/connections", response_model=list[VpnConnection])
def openvpn_connections() -> list[VpnConnection]:
    return _openvpn().connections()


# ── Escritura ──────────────────────────────────────────────────────────────
@app.post("/api/openvpn/clients", response_model=VpnClient, status_code=201)
def openvpn_create(body: CreateClient) -> VpnClient:
    try:
        return _openvpn().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e


@app.post("/api/openvpn/clients/{name}/revoke", response_model=VpnClient)
def openvpn_revoke(name: str) -> VpnClient:
    try:
        return _openvpn().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e


@app.get("/api/openvpn/clients/{name}/config", response_class=PlainTextResponse)
def openvpn_config(name: str) -> Response:
    try:
        text = _openvpn().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'},
    )
