"""Modelo común y contrato de los backends VPN (OpenVPN / WireGuard).

La API y la UI hablan solo este lenguaje; cada backend traduce sus detalles.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class VpnClient(BaseModel):
    """Un cliente/peer dado de alta en el servidor."""

    name: str
    status: str  # valid | revoked | expired | disabled
    serial: str | None = None
    expires_at: datetime | None = None


class VpnConnection(BaseModel):
    """Una conexión activa en este momento."""

    name: str
    real_address: str | None = None
    virtual_address: str | None = None
    bytes_received: int = 0
    bytes_sent: int = 0
    connected_since: datetime | None = None


class ServiceStatus(BaseModel):
    backend: str  # openvpn | wireguard
    active: bool
    detail: str = ""


# ── Errores de dominio (la API los traduce a códigos HTTP) ─────────────────────
class VpnError(Exception):
    """Error de negocio del backend."""


class InvalidName(VpnError):
    """Nombre de cliente no válido (caracteres no permitidos)."""


class NotFound(VpnError):
    """No existe ningún cliente con ese nombre."""


class AlreadyExists(VpnError):
    """Ya existe un cliente con ese nombre."""


class Forbidden(VpnError):
    """Operación no permitida (p. ej. tocar el certificado del servidor)."""


class VpnBackend(ABC):
    """Contrato común a OpenVPN y WireGuard."""

    name: str

    # ── Lectura ────────────────────────────────────────────────────────────
    @abstractmethod
    def status(self) -> ServiceStatus: ...

    @abstractmethod
    def clients(self) -> list[VpnClient]: ...

    @abstractmethod
    def connections(self) -> list[VpnConnection]: ...

    # ── Escritura (Fase 2) ─────────────────────────────────────────────────
    def create_client(self, name: str) -> VpnClient:
        """Da de alta una persona/dispositivo (genera su certificado)."""
        raise NotImplementedError

    def revoke_client(self, name: str) -> VpnClient:
        """Retira el acceso de un cliente (revoca su certificado + CRL)."""
        raise NotImplementedError

    def client_config(self, name: str) -> str:
        """Devuelve el fichero de configuración del cliente para descargar."""
        raise NotImplementedError
