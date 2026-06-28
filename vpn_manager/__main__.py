"""Arranque: `python -m vpn_manager`."""
import uvicorn

from .config import settings


def main() -> None:
    print(f"VPN Manager — sandbox={settings.sandbox}  ·  {settings.host}:{settings.port}")
    uvicorn.run("vpn_manager.api.app:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    main()
