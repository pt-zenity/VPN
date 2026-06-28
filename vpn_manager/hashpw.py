"""Genera el hash de una contraseña para VPNM_ADMIN_PASSWORD_HASH.

Uso:
    python -m vpn_manager.hashpw
    # te pide la contraseña (no se muestra) e imprime el hash a poner en el .env
"""
import getpass

from .auth import hash_password


def main() -> None:
    pw = getpass.getpass("Contraseña del panel: ")
    if not pw:
        print("Contraseña vacía, cancelado.")
        return
    if pw != getpass.getpass("Repite la contraseña: "):
        print("No coinciden, cancelado.")
        return
    print("\nAñade esta línea a tu .env (o expórtala como variable de entorno):\n")
    print(f"VPNM_ADMIN_PASSWORD_HASH={hash_password(pw)}")


if __name__ == "__main__":
    main()
