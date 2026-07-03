"""Client configuration delivery: save to server or send by email.

Security:
- Save: the destination path must remain INSIDE the allowed directory
  (`export_dir`) — prevents arbitrary writes and *path traversal*.
- Email: the address is validated; SMTP credentials come from configuration
  (never hard-coded). Warning: email is not a secure channel for keys.
"""
from __future__ import annotations

import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")


class DeliveryError(Exception):
    """Business error when delivering a configuration."""


def save_to_server(content: str, filename: str, dest: str, allowed_base: Path) -> Path:
    """Saves `content` as `filename` inside `dest`, which must be under `allowed_base`."""
    if not _SAFE_NAME_RE.match(filename):
        raise DeliveryError("Invalid filename.")
    allowed_base = allowed_base.resolve()
    # `dest` may be relative (to base) or absolute; in both cases it must fall inside.
    target_dir = (allowed_base / dest).resolve() if not Path(dest).is_absolute() else Path(dest).resolve()
    if target_dir != allowed_base and allowed_base not in target_dir.parents:
        raise DeliveryError(
            f"Path must be within the allowed directory: {allowed_base}"
        )
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def validate_email(addr: str) -> str:
    addr = (addr or "").strip()
    if not _EMAIL_RE.match(addr):
        raise DeliveryError("Invalid email address.")
    return addr


def send_email(content: str, filename: str, to_addr: str, settings, sandbox: bool) -> dict:
    """Sends the config as an attachment. Without SMTP configured: simulates in sandbox, error in prod."""
    to_addr = validate_email(to_addr)
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_addr
    msg["Subject"] = f"Your VPN configuration: {filename}"
    msg.set_content(
        "We have attached your configuration for connecting to the VPN.\n\n"
        "Important: treat it like a credential; do not forward it."
    )
    msg.add_attachment(
        content.encode("utf-8"), maintype="application", subtype="octet-stream",
        filename=filename,
    )

    if not settings.smtp_host:
        if sandbox:
            outbox = (settings.export_dir / "outbox")
            outbox.mkdir(parents=True, exist_ok=True)
            eml = outbox / f"{filename}.{to_addr}.eml"
            eml.write_bytes(bytes(msg))
            return {"sent": True, "simulated": True, "to": to_addr}
        raise DeliveryError("SMTP not configured: set VPNM_SMTP_HOST to send emails.")

    try:  # pragma: no cover - requires a real SMTP server
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    except Exception as e:  # noqa: BLE001
        raise DeliveryError(f"Could not send email: {e}") from e
    return {"sent": True, "simulated": False, "to": to_addr}
