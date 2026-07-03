"""Esquema de las directivas de OpenVPN para el formulario de configuración.

Each field describes: key, label, description, control type (text/number/
select/toggle), opciones (si es desplegable) y validación mínima. La UI lo usa para
pintar el formulario; el backend lo usa para validar antes de escribir el server.conf.
"""
from __future__ import annotations

import re

# type: text | number | select | toggle
FIELDS: list[dict] = [
    {"key": "port", "label": "Port", "type": "number", "min": 1, "max": 65535,
     "desc": "Port the server listens on (default 1194)."},
    {"key": "proto", "label": "Protocol", "type": "select",
     "options": ["udp", "tcp", "udp6", "tcp6"],
     "desc": "Transport protocol. UDP is standard (faster)."},
    {"key": "dev", "label": "Device", "type": "select", "options": ["tun", "tap"],
     "desc": "tun = routed (layer 3, default); tap = bridged (layer 2)."},
    {"key": "server", "label": "IP Range (VPN)", "type": "text",
     "pattern": r"^\d{1,3}(\.\d{1,3}){3}\s+\d{1,3}(\.\d{1,3}){3}$",
     "desc": "Network and mask assigned by the VPN. e.g.: 10.8.0.0 255.255.255.0"},
    {"key": "topology", "label": "Topology", "type": "select",
     "options": ["subnet", "net30", "p2p"],
     "desc": "subnet is recommended for modern clients."},
    {"key": "data-ciphers", "label": "Data ciphers", "type": "text",
     "desc": "Allowed ciphers, colon-separated. e.g.: AES-256-GCM:AES-128-GCM"},
    {"key": "data-ciphers-fallback", "label": "Fallback cipher", "type": "text",
     "desc": "Cipher for legacy clients that do not negotiate. e.g.: AES-256-GCM"},
    {"key": "auth", "label": "Auth (HMAC)", "type": "select",
     "options": ["SHA256", "SHA512", "SHA1"],
     "desc": "Packet integrity algorithm."},
    {"key": "tls-version-min", "label": "Minimum TLS", "type": "select",
     "options": ["1.2", "1.3"],
     "desc": "Minimum TLS version accepted on the control channel."},
    {"key": "max-clients", "label": "Max. devices", "type": "number", "min": 1, "max": 100000,
     "desc": "Maximum number of clients connected at once."},
    {"key": "keepalive", "label": "Keepalive", "type": "text",
     "pattern": r"^\d+\s+\d+$",
     "desc": "Ping and timeout in seconds. e.g.: 10 120"},
    {"key": "user", "label": "Process user", "type": "text",
     "desc": "User the daemon drops privileges to. e.g.: nobody"},
    {"key": "group", "label": "Process group", "type": "text",
     "desc": "Group the daemon drops privileges to. e.g.: nogroup"},
    {"key": "persist-key", "label": "Persist keys", "type": "toggle",
     "desc": "Do not re-read keys when the tunnel restarts."},
    {"key": "persist-tun", "label": "Persist tunnel", "type": "toggle",
     "desc": "Do not close the tun/tap device on restart."},
    {"key": "crl-verify", "label": "Revocation list (CRL)", "type": "text",
     "desc": "Path to the CRL file to reject revoked certificates."},
    {"key": "verb", "label": "Log level", "type": "number", "min": 0, "max": 11,
     "desc": "Log verbosity (0 = none, 3 = normal, 9 = debug)."},
]

FIELDS_BY_KEY = {f["key"]: f for f in FIELDS}

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,40}$")


def validate_directive(key: str, value: str) -> str | None:
    """Devuelve un mensaje de error si la directiva no es válida, o None si lo es."""
    if not _KEY_RE.match(key):
        return f"Invalid directive: '{key}'."
    if "\n" in value or "\r" in value:
        return f"The value of '{key}' cannot contain newlines."
    field = FIELDS_BY_KEY.get(key)
    if not field:
        return None  # directiva avanzada/desconocida: se acepta tal cual
    t = field["type"]
    if t == "number":
        if not value.strip().lstrip("-").isdigit():
            return f"'{field['label']}' must be a number."
        n = int(value)
        if "min" in field and n < field["min"]:
            return f"'{field['label']}' must be ≥ {field['min']}."
        if "max" in field and n > field["max"]:
            return f"'{field['label']}' must be ≤ {field['max']}."
    elif t == "select" and value and value not in field["options"]:
        return f"'{field['label']}' must be one of: {', '.join(field['options'])}."
    elif t == "text" and field.get("pattern") and value:
        if not re.match(field["pattern"], value.strip()):
            return f"'{field['label']}' does not match the expected format."
    return None
