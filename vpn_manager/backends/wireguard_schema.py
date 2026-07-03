"""Esquema de las directivas del [Interface] de WireGuard para el formulario.

Solo se editan los parámetros del servidor ([Interface]); la clave privada y los
peers (dispositivos) se preservan y NO se tocan desde este formulario.
"""
from __future__ import annotations

import re

FIELDS: list[dict] = [
    {"key": "Address", "label": "IP Range (VPN)", "type": "text",
     "pattern": r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$",
     "desc": "Server IP and mask in the VPN. e.g.: 10.9.0.1/24"},
    {"key": "ListenPort", "label": "Port", "type": "number", "min": 1, "max": 65535,
     "desc": "UDP port WireGuard listens on (default 51820)."},
    {"key": "MTU", "label": "MTU", "type": "number", "min": 1280, "max": 1500,
     "desc": "Maximum packet size. Leave blank unless you need to change it."},
    {"key": "DNS", "label": "DNS", "type": "text",
     "desc": "DNS servers (comma-separated) offered to clients."},
    {"key": "Table", "label": "Routing table", "type": "text",
     "desc": "Routing table. 'auto' (default) or 'off' to leave routes untouched."},
    {"key": "FwMark", "label": "Firewall mark", "type": "text",
     "desc": "fwmark for outgoing packets. Advanced; normally blank."},
    {"key": "SaveConfig", "label": "Save live changes", "type": "select",
     "options": ["", "true", "false"],
     "desc": "If true, wg-quick saves live changes back to the config file."},
    {"key": "PreUp", "label": "Pre-up command", "type": "text",
     "desc": "Runs just before the interface is brought up."},
    {"key": "PostUp", "label": "Post-up command", "type": "text",
     "desc": "Runs when the interface comes up (e.g. iptables rules)."},
    {"key": "PreDown", "label": "Pre-down command", "type": "text",
     "desc": "Runs just before the interface is brought down."},
    {"key": "PostDown", "label": "Post-down command", "type": "text",
     "desc": "Runs when the interface goes down."},
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
