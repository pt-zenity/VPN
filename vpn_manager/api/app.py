"""API FastAPI del VPN Manager.

Fase 1: lectura de OpenVPN (estado, clientes, conexiones).
Fase 2: escritura de OpenVPN (alta, revocación, descarga de configuración).
Autenticación: login con sesión en cookie firmada; todo protegido salvo /login
y /health.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .. import auth, delivery, users
from ..backends.base import (
    AlreadyExists,
    Forbidden,
    InvalidName,
    NotFound,
    ServerInfo,
    ServiceStatus,
    VpnClient,
    VpnConnection,
    VpnError,
)
from ..backends.openvpn import OpenVpnBackend
from ..backends.wireguard import WireGuardBackend
from ..config import settings

_UI = Path(__file__).resolve().parent.parent / "ui"
log = logging.getLogger("vpn_manager.audit")

# Cabeceras de seguridad aplicadas a toda respuesta.
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",  # anti-clickjacking
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
}

# Credenciales y clave de sesión resueltas una vez al arrancar.
_ADMIN_USER, _ADMIN_HASH = auth.resolve_credentials(
    settings.admin_user, settings.admin_password_hash, settings.sandbox
)
_throttle = auth.LoginThrottle()
# Almacén de usuarios del panel (multiusuario + roles); siembra el admin de config.
_users = users.UserStore(settings.users_file, _ADMIN_USER, _ADMIN_HASH, "admin")


def _openvpn() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=settings.sandbox,
        log_file=settings.openvpn_log_file,
        server_conf=settings.openvpn_server_conf,
        public_endpoint=settings.openvpn_public_endpoint,
    )


def _wireguard() -> WireGuardBackend:
    return WireGuardBackend(
        conf=settings.wireguard_conf,
        show_file=settings.wireguard_show_file,
        service=f"wg-quick@{settings.wireguard_interface}",
        sandbox=settings.sandbox,
        interface=settings.wireguard_interface,
        log_file=settings.wireguard_log_file,
        public_endpoint=settings.wireguard_public_endpoint,
        dns=settings.wireguard_dns,
    )


def _http(exc: VpnError) -> HTTPException:
    code = {InvalidName: 422, NotFound: 404, AlreadyExists: 409, Forbidden: 403}.get(
        type(exc), 400
    )
    return HTTPException(status_code=code, detail=str(exc))


def require_user(request: Request) -> str:
    """Dependencia: exige sesión iniciada y que el usuario siga existiendo."""
    user = request.session.get("user")
    if not user or not _users.exists(user):
        raise HTTPException(status_code=401, detail="No autenticado")
    return user


def require_perm(perm: str):
    """Factoría de dependencia: exige sesión + un permiso concreto."""
    def dep(request: Request) -> str:
        user = require_user(request)
        if not _users.has_perm(user, perm):
            raise HTTPException(status_code=403, detail="No tienes permiso para esta acción.")
        return user
    return dep


class CreateClient(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class Directive(BaseModel):
    key: str = Field(min_length=1, max_length=41)
    value: str = Field(default="", max_length=512)


class ServerConfigUpdate(BaseModel):
    directives: list[Directive] = Field(max_length=200)


class SavePath(BaseModel):
    path: str = Field(min_length=1, max_length=512)


class SendEmail(BaseModel):
    email: str = Field(min_length=3, max_length=254)


def _deliver_save(backend, name: str, ext: str, dest: str, user: str) -> dict:
    try:
        content = backend.client_config(name)
        path = delivery.save_to_server(
            content, f"{name}.{ext}", dest, settings.export_dir
        )
    except VpnError as e:
        raise _http(e) from e
    except delivery.DeliveryError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("config de «%s» guardada en %s por %s", name, path, user)
    return {"saved": True, "path": str(path)}


def _deliver_email(backend, name: str, ext: str, email: str, user: str) -> dict:
    try:
        content = backend.client_config(name)
        result = delivery.send_email(content, f"{name}.{ext}", email, settings, settings.sandbox)
    except VpnError as e:
        raise _http(e) from e
    except delivery.DeliveryError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("config de «%s» enviada por correo a %s por %s", name, result["to"], user)
    return result


app = FastAPI(title="VPN Manager", version="0.3.0")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    # Nunca cachear el panel ni la API (pueden contener datos sensibles).
    if request.url.path != "/health":
        response.headers["Cache-Control"] = "no-store"
    return response


app.add_middleware(
    SessionMiddleware,
    secret_key=auth.resolve_secret(settings.secret_key, settings.sandbox),
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
        log.warning("login bloqueado por exceso de intentos desde %s", ip)
        return HTMLResponse(
            _render_login("Demasiados intentos. Espera unos minutos."), status_code=429
        )
    if not _users.verify(username, password):
        _throttle.record_failure(ip)
        log.warning("login fallido (usuario=%r) desde %s", username[:32], ip)
        return HTMLResponse(
            _render_login("Usuario o contraseña incorrectos."), status_code=401
        )
    _throttle.reset(ip)
    request.session.clear()
    request.session["user"] = username
    log.info("login correcto (%s) desde %s", username, ip)
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
    role = _users.role(user)
    return {
        "user": user,
        "role": role,
        "role_label": users.ROLE_LABELS.get(role, role),
        "permissions": sorted(users.role_permissions(role)),
    }


# ── Gestión de usuarios (rol admin) ──────────────────────────────────────────
class CreateUser(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    password: str = Field(min_length=8, max_length=256)
    role: str


class UpdateUser(BaseModel):
    role: str | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


@app.get("/api/users", dependencies=[Depends(require_perm("users:manage"))])
def users_list() -> dict:
    return {
        "users": _users.list(),
        "roles": [{"id": r, "label": users.ROLE_LABELS[r]} for r in users.ROLES],
    }


@app.post("/api/users", status_code=201)
def users_create(body: CreateUser, admin: str = Depends(require_perm("users:manage"))) -> dict:
    try:
        _users.add(body.username, body.password, body.role)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» (rol %s) creado por %s", body.username, body.role, admin)
    return {"created": body.username}


@app.put("/api/users/{username}")
def users_update(username: str, body: UpdateUser, admin: str = Depends(require_perm("users:manage"))) -> dict:
    try:
        _users.update(username, role=body.role, password=body.password)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» modificado por %s", username, admin)
    return {"updated": username}


@app.delete("/api/users/{username}")
def users_delete(username: str, admin: str = Depends(require_perm("users:manage"))) -> dict:
    if username == admin:
        raise HTTPException(status_code=422, detail="No puedes borrar tu propia cuenta.")
    try:
        _users.delete(username)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» borrado por %s", username, admin)
    return {"deleted": username}


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


@app.get("/api/openvpn/server", response_model=ServerInfo, dependencies=_PROTECTED)
def openvpn_server() -> ServerInfo:
    return _openvpn().server_info()


@app.get("/api/openvpn/server/schema", dependencies=_PROTECTED)
def openvpn_server_schema() -> dict:
    from ..backends.openvpn_schema import FIELDS

    return {"fields": FIELDS}


@app.put("/api/openvpn/server", response_model=ServerInfo, dependencies=_PROTECTED)
def openvpn_server_update(body: ServerConfigUpdate, user: str = Depends(require_perm("server:write"))) -> ServerInfo:
    try:
        info = _openvpn().update_server_config([(d.key, d.value) for d in body.directives])
    except VpnError as e:
        raise _http(e) from e
    log.info("configuración del servidor OpenVPN modificada por %s", user)
    return info


@app.get("/api/openvpn/logs", dependencies=_PROTECTED)
def openvpn_logs(lines: int = 80) -> dict:
    return {"lines": _openvpn().logs(lines)}


@app.post(
    "/api/openvpn/service/{action}", response_model=ServiceStatus, dependencies=_PROTECTED
)
def openvpn_service_action(action: str, user: str = Depends(require_perm("service:control"))) -> ServiceStatus:
    try:
        status = _openvpn().service_action(action)
    except VpnError as e:
        raise _http(e) from e
    log.info("acción de servicio «%s» por %s -> activo=%s", action, user, status.active)
    return status


# ── WireGuard ────────────────────────────────────────────────────────────────
@app.get("/api/wireguard/status", response_model=ServiceStatus, dependencies=_PROTECTED)
def wg_status() -> ServiceStatus:
    return _wireguard().status()


@app.get("/api/wireguard/clients", response_model=list[VpnClient], dependencies=_PROTECTED)
def wg_clients() -> list[VpnClient]:
    return _wireguard().clients()


@app.get(
    "/api/wireguard/connections", response_model=list[VpnConnection], dependencies=_PROTECTED
)
def wg_connections() -> list[VpnConnection]:
    return _wireguard().connections()


@app.get("/api/wireguard/server", response_model=ServerInfo, dependencies=_PROTECTED)
def wg_server() -> ServerInfo:
    return _wireguard().server_info()


@app.get("/api/wireguard/server/schema", dependencies=_PROTECTED)
def wg_server_schema() -> dict:
    from ..backends.wireguard_schema import FIELDS

    return {"fields": FIELDS}


@app.put("/api/wireguard/server", response_model=ServerInfo, dependencies=_PROTECTED)
def wg_server_update(body: ServerConfigUpdate, user: str = Depends(require_perm("server:write"))) -> ServerInfo:
    try:
        info = _wireguard().update_server_config([(d.key, d.value) for d in body.directives])
    except VpnError as e:
        raise _http(e) from e
    log.info("configuración del servidor WireGuard modificada por %s", user)
    return info


@app.get("/api/wireguard/logs", dependencies=_PROTECTED)
def wg_logs(lines: int = 80) -> dict:
    return {"lines": _wireguard().logs(lines)}


@app.post(
    "/api/wireguard/clients", response_model=VpnClient, status_code=201, dependencies=_PROTECTED
)
def wg_create(body: CreateClient, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _wireguard().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e
    log.info("alta de dispositivo WireGuard «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/wireguard/clients/{name}/revoke", response_model=VpnClient, dependencies=_PROTECTED
)
def wg_revoke(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _wireguard().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("baja de dispositivo WireGuard «%s» por %s", client.name, user)
    return client


@app.get(
    "/api/wireguard/clients/{name}/config",
    response_class=PlainTextResponse,
    dependencies=_PROTECTED,
)
def wg_config(name: str) -> Response:
    try:
        text = _wireguard().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    return PlainTextResponse(
        text, headers={"Content-Disposition": f'attachment; filename="{name}.conf"'}
    )


@app.get("/api/wireguard/clients/{name}/qr", dependencies=_PROTECTED)
def wg_qr(name: str) -> Response:
    try:
        svg = _wireguard().client_qr_svg(name)
    except VpnError as e:
        raise _http(e) from e
    return Response(content=svg, media_type="image/svg+xml")


@app.post("/api/wireguard/clients/{name}/save", dependencies=_PROTECTED)
def wg_save(name: str, body: SavePath, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_save(_wireguard(), name, "conf", body.path, user)


@app.post("/api/wireguard/clients/{name}/email", dependencies=_PROTECTED)
def wg_email(name: str, body: SendEmail, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_email(_wireguard(), name, "conf", body.email, user)


@app.post(
    "/api/wireguard/service/{action}", response_model=ServiceStatus, dependencies=_PROTECTED
)
def wg_service_action(action: str, user: str = Depends(require_perm("service:control"))) -> ServiceStatus:
    try:
        status = _wireguard().service_action(action)
    except VpnError as e:
        raise _http(e) from e
    log.info("acción de servicio WireGuard «%s» por %s -> activo=%s", action, user, status.active)
    return status


# ── Escritura (protegida) ────────────────────────────────────────────────────
@app.post(
    "/api/openvpn/clients", response_model=VpnClient, status_code=201, dependencies=_PROTECTED
)
def openvpn_create(body: CreateClient, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e
    log.info("alta de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/clients/{name}/revoke", response_model=VpnClient, dependencies=_PROTECTED
)
def openvpn_revoke(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("revocación de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/clients/{name}/renew", response_model=VpnClient, dependencies=_PROTECTED
)
def openvpn_renew(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().renew_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("renovación de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/connections/{name}/disconnect", status_code=204, dependencies=_PROTECTED
)
def openvpn_disconnect(name: str, user: str = Depends(require_perm("clients:write"))) -> Response:
    try:
        _openvpn().disconnect(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("desconexión de «%s» por %s", name, user)
    return Response(status_code=204)


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


@app.post("/api/openvpn/clients/{name}/save", dependencies=_PROTECTED)
def openvpn_save(name: str, body: SavePath, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_save(_openvpn(), name, "ovpn", body.path, user)


@app.post("/api/openvpn/clients/{name}/email", dependencies=_PROTECTED)
def openvpn_email(name: str, body: SendEmail, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_email(_openvpn(), name, "ovpn", body.email, user)


# ── Utilidades ───────────────────────────────────────────────────────────────
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
