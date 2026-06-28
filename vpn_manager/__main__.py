"""Arranque: `python -m vpn_manager`."""
import uvicorn

from .config import settings


def main() -> None:
    print(f"VPN Manager — sandbox={settings.sandbox}  ·  http://127.0.0.1:8200")
    uvicorn.run("vpn_manager.api.app:app", host="127.0.0.1", port=8200, reload=False)


if __name__ == "__main__":
    main()
