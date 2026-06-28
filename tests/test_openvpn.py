import shutil

import pytest
from fastapi.testclient import TestClient

from vpn_manager.api.app import app
from vpn_manager.backends.base import AlreadyExists, Forbidden, InvalidName, NotFound
from vpn_manager.backends.openvpn import OpenVpnBackend
from vpn_manager.config import settings


def _backend() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=True,
    )


@pytest.fixture
def tmp_backend(tmp_path) -> OpenVpnBackend:
    """Backend sobre una copia temporal de la PKI (no toca los fixtures)."""
    pki = tmp_path / "pki"
    pki.mkdir()
    shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
    status = tmp_path / "openvpn-status.log"
    shutil.copy(settings.openvpn_status_file, status)
    return OpenVpnBackend(
        pki_index=pki / "index.txt", status_file=status,
        service="x", sandbox=True,
    )


class TestOpenVpnParsing:
    def test_clients_excluye_servidor_y_lee_estados(self):
        clients = {c.name: c for c in _backend().clients()}
        assert "server" not in clients  # el cert del servidor no es cliente
        assert clients["alice-laptop"].status == "valid"
        assert clients["bob-phone"].status == "valid"
        assert clients["carol-old"].status == "revoked"
        assert clients["dave-expired"].status == "expired"
        assert clients["alice-laptop"].serial == "02"
        assert clients["alice-laptop"].expires_at is not None

    def test_connections_lee_status_con_bytes_y_virtual(self):
        conns = {c.name: c for c in _backend().connections()}
        assert set(conns) == {"alice-laptop", "bob-phone"}
        assert conns["alice-laptop"].bytes_received == 1048576
        assert conns["alice-laptop"].bytes_sent == 2097152
        assert conns["alice-laptop"].virtual_address == "10.8.0.2"
        assert conns["alice-laptop"].connected_since is not None

    def test_status_sandbox_no_toca_el_sistema(self):
        s = _backend().status()
        assert s.backend == "openvpn"
        assert s.active is True
        assert s.detail == "sandbox"


class TestApi:
    client = TestClient(app)

    def test_health(self):
        r = self.client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["sandbox"] is True

    def test_clients_endpoint(self):
        r = self.client.get("/api/openvpn/clients")
        assert r.status_code == 200
        assert len(r.json()) == 4  # 4 clientes (sin el servidor)

    def test_connections_endpoint(self):
        r = self.client.get("/api/openvpn/connections")
        assert r.status_code == 200
        assert len(r.json()) == 2


class TestOpenVpnWrite:
    def test_alta_crea_cliente_valido_y_config(self, tmp_backend):
        c = tmp_backend.create_client("nuevo-pc")
        assert c.status == "valid"
        assert c.serial == "06"  # siguiente serie tras 05
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["nuevo-pc"] == "valid"
        cfg = tmp_backend.client_config("nuevo-pc")
        assert "nuevo-pc" in cfg
        assert (tmp_backend.client_dir / "nuevo-pc.ovpn").exists()

    def test_alta_duplicada_falla(self, tmp_backend):
        with pytest.raises(AlreadyExists):
            tmp_backend.create_client("alice-laptop")

    @pytest.mark.parametrize("bad", ["", "  ", "../etc", "con espacio", "a/b", "x;rm", "@evil"])
    def test_nombres_invalidos(self, tmp_backend, bad):
        with pytest.raises(InvalidName):
            tmp_backend.create_client(bad)

    def test_no_se_puede_crear_ni_revocar_el_servidor(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.create_client("server")
        with pytest.raises(Forbidden):
            tmp_backend.revoke_client("server")

    def test_revocar_marca_revocado_y_bloquea_config(self, tmp_backend):
        r = tmp_backend.revoke_client("alice-laptop")
        assert r.status == "revoked"
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["alice-laptop"] == "revoked"
        with pytest.raises(Forbidden):  # ya no se descarga su config
            tmp_backend.client_config("alice-laptop")

    def test_revocar_inexistente_falla(self, tmp_backend):
        with pytest.raises(NotFound):
            tmp_backend.revoke_client("fantasma")

    def test_config_de_caducado_bloqueada(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.client_config("dave-expired")


class TestWriteApi:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        pki = tmp_path / "pki"
        pki.mkdir()
        shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
        status = tmp_path / "openvpn-status.log"
        shutil.copy(settings.openvpn_status_file, status)
        monkeypatch.setattr(settings, "openvpn_pki_index", pki / "index.txt")
        monkeypatch.setattr(settings, "openvpn_status_file", status)
        self.client = TestClient(app)

    def test_alta_revoca_y_descarga_por_api(self):
        r = self.client.post("/api/openvpn/clients", json={"name": "tablet-jose"})
        assert r.status_code == 201
        assert r.json()["status"] == "valid"

        r = self.client.get("/api/openvpn/clients/tablet-jose/config")
        assert r.status_code == 200
        assert "tablet-jose" in r.text
        assert "attachment" in r.headers["content-disposition"]

        r = self.client.post("/api/openvpn/clients/tablet-jose/revoke")
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

        # tras revocar, la descarga se bloquea
        assert self.client.get("/api/openvpn/clients/tablet-jose/config").status_code == 403

    def test_codigos_de_error(self):
        assert self.client.post("/api/openvpn/clients", json={"name": "alice-laptop"}).status_code == 409
        assert self.client.post("/api/openvpn/clients", json={"name": "a b"}).status_code == 422
        assert self.client.post("/api/openvpn/clients/server/revoke").status_code == 403
        assert self.client.post("/api/openvpn/clients/fantasma/revoke").status_code == 404
