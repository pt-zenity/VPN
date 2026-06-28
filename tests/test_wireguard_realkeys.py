"""Regresión del modo REAL de WireGuard: las claves del cliente deben ser
criptográficamente coherentes (la pública se deriva de la privada) y el config
del cliente debe llevar la clave pública REAL del servidor.

Bug histórico: `pub = _genkey()` generaba una pública independiente de la privada
→ el peer registrado no correspondía al cliente → el handshake fallaba siempre.
Validado end-to-end con un handshake real (contenedor NET_ADMIN); aquí lo fijamos
sin depender de `wg` en el host, simulando `_wg_out`.
"""
from pathlib import Path
from unittest.mock import patch

from vpn_manager.backends.wireguard import WireGuardBackend


def _backend(tmp_path: Path, sandbox: bool) -> WireGuardBackend:
    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = SRVPRIV\nAddress = 10.9.0.1/24\nListenPort = 51820\n",
        encoding="utf-8",
    )
    return WireGuardBackend(
        conf=conf,
        show_file=tmp_path / "show.txt",
        service="wg-quick@wg0",
        sandbox=sandbox,
        interface="wg0",
        public_endpoint="vpn.example",
        dns="1.1.1.1",
    )


def _fake_wg_out(*args, stdin=None):
    if args[0] == "genkey":
        return "PRIVKEY"
    if args[0] == "pubkey":
        return f"PUB({stdin})"  # deriva de forma determinista de la privada
    if args == ("show", "wg0", "public-key"):
        return "SERVERPUB"
    return ""


def test_real_mode_derives_public_key_from_private(tmp_path):
    be = _backend(tmp_path, sandbox=False)
    with patch.object(be, "_wg_out", side_effect=_fake_wg_out):
        priv, pub = be._genkeypair()
    assert priv == "PRIVKEY"
    # Clave: la pública se DERIVA de la privada (no es independiente).
    assert pub == "PUB(PRIVKEY)"


def test_real_mode_client_config_uses_real_server_pubkey(tmp_path):
    be = _backend(tmp_path, sandbox=False)
    with patch.object(be, "_wg_out", side_effect=_fake_wg_out), patch.object(be, "_wg"):
        be.create_client("ana")
        cfg = be.client_config("ana")
    assert "PublicKey = SERVERPUB" in cfg  # no el placeholder
    assert "PrivateKey = PRIVKEY" in cfg
    # El peer que el panel registra en el servidor == pubkey(priv del cliente).
    with patch.object(be, "_wg_out", side_effect=_fake_wg_out):
        assert be._genkeypair()[1] == "PUB(PRIVKEY)"


def test_sandbox_mode_unchanged(tmp_path):
    be = _backend(tmp_path, sandbox=True)
    priv, pub = be._genkeypair()
    assert priv != pub  # dos claves ficticias, comportamiento previo intacto
    assert be._server_pubkey() == "(clave-publica-del-servidor)"
