"""Auditoría persistida.

El panel ya registra cada acción sensible con `log.info(...)` en el logger
«vpn_manager.audit». Aquí añadimos un handler que **persiste** esos registros en un
fichero JSON-Lines (una entrada por línea), para poder consultarlos desde el panel.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class JsonlAuditHandler(logging.Handler):
    """Escribe cada registro como una línea JSON (con rotación simple por tamaño)."""

    def __init__(self, path: Path, max_bytes: int = 2_000_000) -> None:
        super().__init__()
        self.path = Path(path)
        self.max_bytes = max_bytes

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                self.path.replace(self.path.with_name(self.path.name + ".1"))
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "level": record.levelname,
                "message": record.getMessage(),
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            self.handleError(record)


def attach(logger_name: str, path: Path) -> JsonlAuditHandler:
    """Engancha el handler al logger (sin duplicarlo)."""
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    for h in logger.handlers:
        if isinstance(h, JsonlAuditHandler):
            h.path = Path(path)
            return h
    handler = JsonlAuditHandler(path)
    logger.addHandler(handler)
    return handler


def recent(path: Path, limit: int = 100) -> list[dict]:
    """Últimas `limit` entradas, de la más reciente a la más antigua."""
    path = Path(path)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[dict] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    out.reverse()
    return out
