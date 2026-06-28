"""Esquema de las directivas del [Interface] de WireGuard para el formulario.

Solo se editan los parámetros del servidor ([Interface]); la clave privada y los
peers (dispositivos) se preservan y NO se tocan desde este formulario.
"""
from __future__ import annotations

import re

FIELDS: list[dict] = [
    {"key": "Address", "label": "Rango de IPs (VPN)", "type": "text",
     "pattern": r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$",
     "desc": "IP y máscara del servidor en la VPN. Ej.: 10.9.0.1/24"},
    {"key": "ListenPort", "label": "Puerto", "type": "number", "min": 1, "max": 65535,
     "desc": "Puerto UDP en el que escucha WireGuard (por defecto 51820)."},
    {"key": "MTU", "label": "MTU", "type": "number", "min": 1280, "max": 1500,
     "desc": "Tamaño máximo de paquete. Déjalo vacío salvo que sepas que lo necesitas."},
    {"key": "PostUp", "label": "Comando al levantar", "type": "text",
     "desc": "Se ejecuta al activar la interfaz (p. ej. reglas de iptables)."},
    {"key": "PostDown", "label": "Comando al bajar", "type": "text",
     "desc": "Se ejecuta al desactivar la interfaz."},
]

FIELDS_BY_KEY = {f["key"]: f for f in FIELDS}

_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,30}$")


def validate_directive(key: str, value: str) -> str | None:
    if not _KEY_RE.match(key):
        return f"Directiva no válida: «{key}»."
    if "\n" in value or "\r" in value:
        return f"El valor de «{key}» no puede tener saltos de línea."
    field = FIELDS_BY_KEY.get(key)
    if not field:
        return None
    if field["type"] == "number":
        if not value.strip().isdigit():
            return f"«{field['label']}» debe ser un número."
        n = int(value)
        if "min" in field and n < field["min"]:
            return f"«{field['label']}» debe ser ≥ {field['min']}."
        if "max" in field and n > field["max"]:
            return f"«{field['label']}» debe ser ≤ {field['max']}."
    elif field["type"] == "text" and field.get("pattern") and value:
        if not re.match(field["pattern"], value.strip()):
            return f"«{field['label']}» no tiene el formato esperado."
    return None
