"""Usuarios, roles y permisos del panel.

- Almacén de usuarios en un fichero JSON (contraseñas con PBKDF2, nunca en claro).
- Tres roles con conjuntos de permisos. El backend exige el permiso en cada endpoint;
  la UI solo adapta lo que muestra.
- Seguro por defecto: si no hay fichero de usuarios, se siembra (en memoria) el admin
  de la configuración; al crear/editar usuarios se persiste.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import auth

# ── Roles y permisos ───────────────────────────────────────────────────────
PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "clients:read", "clients:write", "service:control", "server:read", "server:write",
        "logs:read", "users:manage", "system:install", "audit:read",
    },
    "operator": {
        "clients:read", "clients:write", "service:control", "server:read", "logs:read",
    },
    "viewer": {"clients:read", "server:read", "logs:read"},
}
ROLES = list(PERMISSIONS)
ROLE_LABELS = {"admin": "Administrator", "operator": "Operator", "viewer": "Read only"}

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")
# Hash de relleno para igualar tiempos cuando el usuario no existe (anti-enumeración).
_DUMMY_HASH = auth.hash_password("x")


class UserError(Exception):
    """Error de negocio en la gestión de usuarios."""


def role_permissions(role: str) -> set[str]:
    return PERMISSIONS.get(role, set())


class UserStore:
    def __init__(self, path: Path, seed_user: str, seed_hash: str, seed_role: str = "admin") -> None:
        self.path = path
        self.users: dict[str, dict] = {}
        if path and path.exists():
            try:
                self.users = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self.users = {}
        if not self.users:
            self.users = {seed_user: {"password_hash": seed_hash, "role": seed_role}}

    # ── Persistencia ────────────────────────────────────────────────────────
    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.users, indent=2), encoding="utf-8")

    # ── Consulta ──────────────────────────────────────────────────────────
    def exists(self, username: str) -> bool:
        return username in self.users

    def role(self, username: str) -> str | None:
        u = self.users.get(username)
        return u["role"] if u else None

    def has_perm(self, username: str, perm: str) -> bool:
        role = self.role(username)
        return bool(role) and perm in role_permissions(role)

    def verify(self, username: str, password: str) -> bool:
        u = self.users.get(username)
        if not u:
            auth.verify_password(password, _DUMMY_HASH)  # iguala el tiempo
            return False
        return auth.verify_password(password, u["password_hash"])

    def list(self) -> list[dict]:
        return [
            {"username": k, "role": v["role"], "role_label": ROLE_LABELS.get(v["role"], v["role"]),
             "totp": bool(v.get("totp_enabled"))}
            for k, v in sorted(self.users.items())
        ]

    # ── Verificación en dos pasos (TOTP) ──────────────────────────────────
    def totp_enabled(self, username: str) -> bool:
        u = self.users.get(username)
        return bool(u and u.get("totp_enabled"))

    def totp_secret(self, username: str) -> str | None:
        u = self.users.get(username)
        return u.get("totp_secret") if u else None

    def set_totp_secret(self, username: str, secret: str) -> None:
        """Saves a pending secret (not yet active)."""
        if username not in self.users:
            raise UserError(f"User \u00ab{username}\u00bb does not exist.")
        self.users[username]["totp_secret"] = secret
        self.users[username]["totp_enabled"] = False
        self._save()

    def enable_totp(self, username: str) -> None:
        if not self.users.get(username, {}).get("totp_secret"):
            raise UserError("Generate the QR code first (setup).")
        self.users[username]["totp_enabled"] = True
        self._save()

    def disable_totp(self, username: str) -> None:
        if username in self.users:
            self.users[username].pop("totp_secret", None)
            self.users[username]["totp_enabled"] = False
            self._save()

    def _admins(self) -> list[str]:
        return [k for k, v in self.users.items() if v["role"] == "admin"]

    # ── Mutación ──────────────────────────────────────────────────────────
    @staticmethod
    def _check(username: str, role: str | None, password: str | None) -> None:
        if not _USERNAME_RE.match(username or ""):
            raise UserError(
                "Username may only contain letters, numbers and . _ - (2 to 32 characters)."
            )
        if role is not None and role not in ROLES:
            raise UserError(f"Invalid role. Use one of: {', '.join(ROLES)}.")
        if password is not None and len(password) < 8:
            raise UserError("Password must be at least 8 characters.")

    def add(self, username: str, password: str, role: str) -> None:
        self._check(username, role, password)
        if username in self.users:
            raise UserError(f"User \u00ab{username}\u00bb already exists.")
        self.users[username] = {"password_hash": auth.hash_password(password), "role": role}
        self._save()

    def update(self, username: str, role: str | None = None, password: str | None = None) -> None:
        if username not in self.users:
            raise UserError(f"User \u00ab{username}\u00bb does not exist.")
        self._check(username, role, password)
        if role is not None:
            # Do not leave the system without administrators.
            if self.users[username]["role"] == "admin" and role != "admin" and self._admins() == [username]:
                raise UserError("You cannot remove the last administrator.")
            self.users[username]["role"] = role
        if password is not None:
            self.users[username]["password_hash"] = auth.hash_password(password)
        self._save()

    def delete(self, username: str) -> None:
        if username not in self.users:
            raise UserError(f"User \u00ab{username}\u00bb does not exist.")
        if self.users[username]["role"] == "admin" and self._admins() == [username]:
            raise UserError("You cannot delete the last administrator.")
        del self.users[username]
        self._save()
