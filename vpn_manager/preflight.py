"""Security / production-readiness checks.

Reviews the current configuration and warns about insecure settings (development
credentials, ephemeral session key, cookies without Secure behind HTTPS, installation
enabled…). Designed so the administrator can see at a glance what needs attention
before exposing the panel.
"""
from __future__ import annotations

# level: ok | info | warn
def checks(settings) -> list[dict]:
    out: list[dict] = []

    def add(level: str, message: str) -> None:
        out.append({"level": level, "message": message})

    if settings.sandbox:
        add("info", "Sandbox mode: the panel works with demo data and does NOT touch the "
                    "real VPN server.")
    else:
        add("ok", "Production mode: managing the real VPN server.")

    # Administrator password.
    if settings.admin_password_hash:
        add("ok", "Administrator password configured (hash).")
    elif settings.sandbox:
        add("warn", "Using development credentials «admin/admin». Set "
                    "VPNM_ADMIN_PASSWORD_HASH (generate with «python -m vpn_manager.hashpw»).")

    # Session key.
    if settings.secret_key:
        add("ok", "Persistent session key configured.")
    else:
        add("warn", "Ephemeral session key: sessions are lost on restart. "
                    "Set VPNM_SECRET_KEY.")

    # Secure cookies / HTTPS.
    if settings.cookie_secure:
        add("ok", "Secure cookies (Secure + HSTS) enabled; always serve behind HTTPS.")
    elif settings.sandbox:
        add("info", "Cookies without «Secure» (acceptable locally). Enable VPNM_COOKIE_SECURE=true "
                    "when serving behind HTTPS.")
    else:
        add("warn", "Production WITHOUT «Secure» cookies: enable VPNM_COOKIE_SECURE=true and serve "
                    "behind HTTPS.")

    # Service installation.
    if settings.allow_install:
        add("warn", "Service installation enabled (VPNM_ALLOW_INSTALL=true): the panel "
                    "can install packages as root. Leave it false unless actively using it.")

    return out


def summary_level(items: list[dict]) -> str:
    """Worst level in the set: warn > info > ok."""
    levels = {item["level"] for item in items}
    if "warn" in levels:
        return "warn"
    if "info" in levels:
        return "info"
    return "ok"
