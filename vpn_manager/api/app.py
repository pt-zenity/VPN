"""API FastAPI del VPN Manager.

Fase 1: lectura de OpenVPN (estado, clientes, conexiones).
Fase 2: escritura de OpenVPN (alta, revocación, descarga de configuración).
Autenticación: login con sesión en cookie firmada; todo protegido salvo /login
y /health.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .. import auth
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

_UI = Path(__file__).resolve().parent.parent / "ui"

# Credenciales y clave de sesión resueltas una vez al arrancar.
_ADMIN_USER, _ADMIN_HASH = auth.resolve_credentials(
    settings.admin_user, settings.admin_password_hash, settings.sandbox
)
_throttle = auth.LoginThrottle()


def _openvpn() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=settings.sandbox,
    )


def _http(exc: VpnError) -> HTTPException:
    code = {InvalidName: 422, NotFound: 404, AlreadyExists: 409, Forbidden: 403}.get(
        type(exc), 400
    )
    return HTTPException(status_code=code, detail=str(exc))


def require_user(request: Request) -> str:
    """Dependencia: exige sesión iniciada (401 si no)."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    return user


class CreateClient(BaseModel):
    name: str = Field(min_length=1, max_length=64)


app = FastAPI(title="VPN Manager", version="0.3.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=auth.resolve_secret(settings.secret_key),
    session_cookie="vpnm_session",
    max_age=settings.session_max_age,
    same_site="strict",
    https_only=settings.cookie_secure,
)

_PROTECTED = [Depends(require_user)]


# ── Páginas ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def ui(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse((_UI / "index.html").read_text(encoding="utf-8"))


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(_render_login(error))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    if _throttle.is_blocked(ip):
        return HTMLResponse(
            _render_login("Demasiados intentos. Espera unos minutos."), status_code=429
        )
    ok = hmac_user(username) and auth.verify_password(password, _ADMIN_HASH)
    if not ok:
        _throttle.record_failure(ip)
        return HTMLResponse(
            _render_login("Usuario o contraseña incorrectos."), status_code=401
        )
    _throttle.reset(ip)
    request.session.clear()
    request.session["user"] = _ADMIN_USER
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "sandbox": settings.sandbox}


@app.get("/api/me", dependencies=_PROTECTED)
def me(user: str = Depends(require_user)) -> dict:
    return {"user": user}


# ── Lectura (protegida) ──────────────────────────────────────────────────────
@app.get("/api/openvpn/status", response_model=ServiceStatus, dependencies=_PROTECTED)
def openvpn_status() -> ServiceStatus:
    return _openvpn().status()


@app.get("/api/openvpn/clients", response_model=list[VpnClient], dependencies=_PROTECTED)
def openvpn_clients() -> list[VpnClient]:
    return _openvpn().clients()


@app.get(
    "/api/openvpn/connections", response_model=list[VpnConnection], dependencies=_PROTECTED
)
def openvpn_connections() -> list[VpnConnection]:
    return _openvpn().connections()


# ── Escritura (protegida) ────────────────────────────────────────────────────
@app.post(
    "/api/openvpn/clients", response_model=VpnClient, status_code=201, dependencies=_PROTECTED
)
def openvpn_create(body: CreateClient) -> VpnClient:
    try:
        return _openvpn().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e


@app.post(
    "/api/openvpn/clients/{name}/revoke", response_model=VpnClient, dependencies=_PROTECTED
)
def openvpn_revoke(name: str) -> VpnClient:
    try:
        return _openvpn().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e


@app.get(
    "/api/openvpn/clients/{name}/config",
    response_class=PlainTextResponse,
    dependencies=_PROTECTED,
)
def openvpn_config(name: str) -> Response:
    try:
        text = _openvpn().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    return PlainTextResponse(
        text, headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'}
    )


# ── Utilidades ───────────────────────────────────────────────────────────────
def hmac_user(username: str) -> bool:
    """Comparación de usuario en tiempo constante."""
    import hmac

    return hmac.compare_digest(username or "", _ADMIN_USER)


def _render_login(error: str = "") -> str:
    html = (_UI / "login.html").read_text(encoding="utf-8")
    block = (
        f'<div class="error">{_escape(error)}</div>' if error else ""
    )
    return html.replace("<!--ERROR-->", block)


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
