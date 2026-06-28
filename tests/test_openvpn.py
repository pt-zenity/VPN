import shutil

import pytest
from fastapi.testclient import TestClient

from vpn_manager.api.app import app
from vpn_manager.backends.base import AlreadyExists, Forbidden, InvalidName, NotFound
from vpn_manager.backends.openvpn import OpenVpnBackend
from vpn_manager.backends.wireguard import WireGuardBackend
from vpn_manager.config import settings


@pytest.fixture
def tmp_wg(tmp_path) -> WireGuardBackend:
    """Backend WireGuard sobre una copia temporal del wg0.conf."""
    conf = tmp_path / "wg0.conf"
    shutil.copy(settings.wireguard_conf, conf)
    show = tmp_path / "wg-show.txt"
    shutil.copy(settings.wireguard_show_file, show)
    log = tmp_path / "wireguard.log"
    shutil.copy(settings.wireguard_log_file, log)
    return WireGuardBackend(
        conf=conf, show_file=show, service="wg-quick@wg0", sandbox=True,
        interface="wg0", log_file=log, public_endpoint="vpn.miempresa.com",
    )


def _backend() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=True,
        log_file=settings.openvpn_log_file,
        server_conf=settings.openvpn_server_conf,
        public_endpoint=settings.openvpn_public_endpoint,
    )


@pytest.fixture
def tmp_backend(tmp_path) -> OpenVpnBackend:
    """Backend sobre una copia temporal de la PKI (no toca los fixtures)."""
    pki = tmp_path / "pki"
    pki.mkdir()
    shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
    status = tmp_path / "openvpn-status.log"
    shutil.copy(settings.openvpn_status_file, status)
    log = tmp_path / "openvpn.log"
    shutil.copy(settings.openvpn_log_file, log)
    conf = tmp_path / "server.conf"
    shutil.copy(settings.openvpn_server_conf, conf)
    return OpenVpnBackend(
        pki_index=pki / "index.txt", status_file=status,
        service="x", sandbox=True, log_file=log, server_conf=conf,
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


def _login(client: TestClient) -> None:
    r = client.post("/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 200  # sigue la redirección al panel


class TestApi:
    @pytest.fixture(autouse=True)
    def _auth(self):
        self.client = TestClient(app)
        _login(self.client)

    def test_health_es_publico(self):
        r = TestClient(app).get("/health")  # sin login
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


class TestAuth:
    def test_api_sin_login_devuelve_401(self):
        c = TestClient(app)
        assert c.get("/api/openvpn/clients").status_code == 401
        assert c.get("/api/openvpn/status").status_code == 401
        assert c.post("/api/openvpn/clients", json={"name": "x"}).status_code == 401

    def test_panel_sin_login_redirige_a_login(self):
        c = TestClient(app)
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_login_incorrecto_devuelve_401(self):
        c = TestClient(app)
        r = c.post("/login", data={"username": "admin", "password": "malo"})
        assert r.status_code == 401

    def test_login_correcto_y_logout(self):
        c = TestClient(app)
        _login(c)
        assert c.get("/api/openvpn/clients").status_code == 200
        assert c.get("/api/me").json()["user"] == "admin"
        c.post("/logout")
        assert c.get("/api/openvpn/clients").status_code == 401


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


class TestServiceAndLogs:
    def test_acciones_validas_en_sandbox(self, tmp_backend):
        for action in ("start", "restart", "reload"):
            assert tmp_backend.service_action(action).active is True
        assert tmp_backend.service_action("stop").active is False

    def test_accion_invalida_falla(self, tmp_backend):
        with pytest.raises(InvalidName):
            tmp_backend.service_action("rm -rf")

    def test_logs_devuelve_lineas(self, tmp_backend):
        out = tmp_backend.logs(5)
        assert isinstance(out, list)
        assert 1 <= len(out) <= 5
        assert any("OpenVPN" in line or "alice" in line for line in tmp_backend.logs(100))

    def test_logs_acota_el_numero(self, tmp_backend):
        assert len(tmp_backend.logs(99999)) <= 1000

    def test_renovar_caducado_lo_reactiva(self, tmp_backend):
        c = tmp_backend.renew_client("dave-expired")
        assert c.status == "valid"
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["dave-expired"] == "valid"

    def test_no_se_renueva_un_retirado(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.renew_client("carol-old")

    def test_desconectar_quita_la_conexion(self, tmp_backend):
        assert "alice-laptop" in {c.name for c in tmp_backend.connections()}
        tmp_backend.disconnect("alice-laptop")
        assert "alice-laptop" not in {c.name for c in tmp_backend.connections()}

    def test_desconectar_sin_conexion_falla(self, tmp_backend):
        with pytest.raises(NotFound):
            tmp_backend.disconnect("dave-expired")


class TestServerInfo:
    def test_lee_configuracion_completa(self):
        info = _backend().server_info()
        assert info.port == "1194"
        assert info.proto == "udp"
        assert info.subnet == "10.8.0.0 255.255.255.0"
        assert "AES-256-GCM" in (info.cipher or "")
        assert info.auth == "SHA256"
        assert info.max_clients == "50"
        assert info.crl_enabled is True
        assert "1.1.1.1" in info.dns_servers
        assert any("192.168.1.0" in r for r in info.routes)
        assert len(info.directives) > 10  # todas las directivas, sin filtrar

    def test_endpoint_publico_configurable(self):
        b = OpenVpnBackend(
            pki_index=settings.openvpn_pki_index, status_file=settings.openvpn_status_file,
            service="x", sandbox=True, server_conf=settings.openvpn_server_conf,
            public_endpoint="vpn.miempresa.com",
        )
        assert b.server_info().public_endpoint == "vpn.miempresa.com"
        assert "vpn.miempresa.com" in b.client_config("alice-laptop")

    def test_editar_configuracion(self, tmp_backend):
        info = tmp_backend.update_server_config(
            [("port", "1195"), ("proto", "tcp"), ("server", "10.20.0.0 255.255.255.0"),
             ("persist-key", "")]
        )
        assert info.port == "1195" and info.proto == "tcp"
        assert info.subnet == "10.20.0.0 255.255.255.0"

    def test_editar_rechaza_valores_malos(self, tmp_backend):
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("port", "noesnumero")])
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("proto", "ftp")])  # no está en opciones
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("mal nombre", "x")])

    def test_schema_tiene_campos_con_tipos(self):
        from vpn_manager.backends.openvpn_schema import FIELDS, FIELDS_BY_KEY

        assert FIELDS_BY_KEY["proto"]["type"] == "select"
        assert "udp" in FIELDS_BY_KEY["proto"]["options"]
        assert all("desc" in f and "label" in f for f in FIELDS)


class TestWireGuard:
    def test_clients_lee_peers(self, tmp_wg):
        names = {c.name for c in tmp_wg.clients()}
        assert names == {"ana-portatil", "luis-movil", "tablet-almacen"}
        assert all(c.status == "valid" and c.expires_at is None for c in tmp_wg.clients())

    def test_connections_solo_con_handshake(self, tmp_wg):
        conns = {c.name: c for c in tmp_wg.connections()}
        assert set(conns) == {"ana-portatil", "luis-movil"}  # tablet sin handshake
        assert conns["ana-portatil"].virtual_address == "10.9.0.2"
        assert conns["ana-portatil"].bytes_received == int(1.05 * 1024**2)
        assert conns["ana-portatil"].connected_since is not None

    def test_alta_asigna_ip_y_guarda_config(self, tmp_wg):
        c = tmp_wg.create_client("nuevo-pc")
        assert c.status == "valid"
        cfg = tmp_wg.client_config("nuevo-pc")
        assert "10.9.0.5/32" in cfg  # .2,.3,.4 ocupadas → siguiente .5
        assert "vpn.miempresa.com:51820" in cfg
        assert "nuevo-pc" in {p.name for p in tmp_wg.clients()}

    def test_alta_duplicada_falla(self, tmp_wg):
        with pytest.raises(AlreadyExists):
            tmp_wg.create_client("ana-portatil")

    def test_baja_quita_el_peer(self, tmp_wg):
        tmp_wg.revoke_client("luis-movil")
        assert "luis-movil" not in {p.name for p in tmp_wg.clients()}

    def test_server_info_no_expone_clave_privada(self, tmp_wg):
        info = tmp_wg.server_info()
        assert info.port == "51820"
        assert info.subnet == "10.9.0.1/24"
        assert info.cipher == "ChaCha20-Poly1305"
        priv = [d for d in info.directives if d.key == "PrivateKey"]
        assert priv and priv[0].value == "(oculta)"  # nunca se expone

    def test_qr_genera_svg(self, tmp_wg):
        svg = tmp_wg.client_qr_svg("ana-portatil")
        assert svg.lstrip().startswith("<svg")

    def test_nombre_invalido(self, tmp_wg):
        with pytest.raises(InvalidName):
            tmp_wg.create_client("mal nombre/..")


class TestWireGuardApi:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        conf = tmp_path / "wg0.conf"
        shutil.copy(settings.wireguard_conf, conf)
        show = tmp_path / "wg-show.txt"
        shutil.copy(settings.wireguard_show_file, show)
        monkeypatch.setattr(settings, "wireguard_conf", conf)
        monkeypatch.setattr(settings, "wireguard_show_file", show)
        self.client = TestClient(app)
        _login(self.client)

    def test_flujo_wireguard_por_api(self):
        assert len(self.client.get("/api/wireguard/clients").json()) == 3
        assert len(self.client.get("/api/wireguard/connections").json()) == 2
        r = self.client.post("/api/wireguard/clients", json={"name": "movil-jose"})
        assert r.status_code == 201
        r = self.client.get("/api/wireguard/clients/movil-jose/qr")
        assert r.status_code == 200 and "svg" in r.headers["content-type"]
        assert self.client.post("/api/wireguard/clients/movil-jose/revoke").status_code == 200

    def test_server_y_login(self):
        d = self.client.get("/api/wireguard/server").json()
        assert d["port"] == "51820" and d["cipher"] == "ChaCha20-Poly1305"
        assert TestClient(app).get("/api/wireguard/clients").status_code == 401


class TestDelivery:
    def test_guardar_dentro_del_base(self, tmp_path):
        from vpn_manager.delivery import save_to_server

        p = save_to_server("contenido", "alice.ovpn", "subcarpeta", tmp_path)
        assert p.read_text() == "contenido"
        assert tmp_path in p.parents

    def test_guardar_fuera_del_base_falla(self, tmp_path):
        from vpn_manager.delivery import DeliveryError, save_to_server

        with pytest.raises(DeliveryError):
            save_to_server("x", "a.ovpn", "../../etc", tmp_path)

    def test_email_invalido(self):
        from vpn_manager.delivery import DeliveryError, validate_email

        with pytest.raises(DeliveryError):
            validate_email("no-es-un-email")

    def test_email_simulado_en_sandbox(self, tmp_path, monkeypatch):
        from vpn_manager.delivery import send_email

        monkeypatch.setattr(settings, "export_dir", tmp_path)
        monkeypatch.setattr(settings, "smtp_host", "")
        res = send_email("config", "ana.conf", "ana@empresa.com", settings, sandbox=True)
        assert res["simulated"] is True and res["to"] == "ana@empresa.com"
        assert list((tmp_path / "outbox").glob("*.eml"))


class TestWriteApi:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        pki = tmp_path / "pki"
        pki.mkdir()
        shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
        status = tmp_path / "openvpn-status.log"
        shutil.copy(settings.openvpn_status_file, status)
        conf = tmp_path / "server.conf"
        shutil.copy(settings.openvpn_server_conf, conf)
        monkeypatch.setattr(settings, "openvpn_pki_index", pki / "index.txt")
        monkeypatch.setattr(settings, "openvpn_status_file", status)
        monkeypatch.setattr(settings, "openvpn_server_conf", conf)
        monkeypatch.setattr(settings, "export_dir", tmp_path / "exports")
        self.client = TestClient(app)
        _login(self.client)

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

    def test_control_servicio_y_logs(self):
        assert self.client.post("/api/openvpn/service/restart").json()["active"] is True
        assert self.client.post("/api/openvpn/service/stop").json()["active"] is False
        assert self.client.post("/api/openvpn/service/bogus").status_code == 422
        r = self.client.get("/api/openvpn/logs")
        assert r.status_code == 200
        assert isinstance(r.json()["lines"], list)

    def test_servicio_requiere_login(self):
        c = TestClient(app)
        assert c.post("/api/openvpn/service/restart").status_code == 401
        assert c.get("/api/openvpn/logs").status_code == 401

    def test_renovar_y_desconectar_por_api(self):
        r = self.client.post("/api/openvpn/clients/dave-expired/renew")
        assert r.status_code == 200 and r.json()["status"] == "valid"
        r = self.client.post("/api/openvpn/connections/alice-laptop/disconnect")
        assert r.status_code == 204
        # ya no aparece como conectada
        names = [c["name"] for c in self.client.get("/api/openvpn/connections").json()]
        assert "alice-laptop" not in names

    def test_info_servidor_por_api(self):
        r = self.client.get("/api/openvpn/server")
        assert r.status_code == 200
        d = r.json()
        assert d["port"] == "1194"
        assert d["public_endpoint"]
        assert len(d["directives"]) > 10

    def test_guardar_y_enviar_config_por_api(self):
        r = self.client.post("/api/openvpn/clients/alice-laptop/save", json={"path": "equipo-ana"})
        assert r.status_code == 200 and r.json()["saved"] is True
        # ruta fuera del directorio permitido → 422
        r = self.client.post("/api/openvpn/clients/alice-laptop/save", json={"path": "/etc"})
        assert r.status_code == 422
        # email simulado en sandbox
        r = self.client.post("/api/openvpn/clients/alice-laptop/email", json={"email": "ana@empresa.com"})
        assert r.status_code == 200 and r.json()["simulated"] is True
        # email inválido → 422
        r = self.client.post("/api/openvpn/clients/alice-laptop/email", json={"email": "malo"})
        assert r.status_code == 422

    def test_editar_config_servidor_por_api(self):
        sc = self.client.get("/api/openvpn/server/schema").json()
        assert any(f["key"] == "proto" and f["type"] == "select" for f in sc["fields"])
        r = self.client.put("/api/openvpn/server", json={"directives": [
            {"key": "port", "value": "1200"}, {"key": "proto", "value": "udp"},
        ]})
        assert r.status_code == 200 and r.json()["port"] == "1200"
        # valor inválido → 422
        r = self.client.put("/api/openvpn/server", json={"directives": [
            {"key": "port", "value": "abc"}]})
        assert r.status_code == 422


class TestAuthModule:
    def test_hash_y_verify(self):
        from vpn_manager.auth import hash_password, verify_password

        h = hash_password("s3creto", iterations=1000)  # iteraciones bajas: test rápido
        assert verify_password("s3creto", h)
        assert not verify_password("otra", h)
        assert not verify_password("s3creto", "formato-malo")

    def test_produccion_sin_password_no_arranca(self):
        from vpn_manager.auth import resolve_credentials

        with pytest.raises(RuntimeError):
            resolve_credentials("admin", "", sandbox=False)

    def test_sandbox_sin_password_usa_dev(self):
        from vpn_manager.auth import resolve_credentials, verify_password

        user, h = resolve_credentials("admin", "", sandbox=True)
        assert user == "admin"
        assert verify_password("admin", h)

    def test_throttle_bloquea_tras_n_intentos(self):
        from vpn_manager.auth import LoginThrottle

        t = LoginThrottle(max_attempts=3, lock_seconds=300)
        assert not t.is_blocked("1.2.3.4")
        for _ in range(3):
            t.record_failure("1.2.3.4")
        assert t.is_blocked("1.2.3.4")
        t.reset("1.2.3.4")
        assert not t.is_blocked("1.2.3.4")

    def test_secret_key_obligatoria_en_produccion(self):
        from vpn_manager.auth import resolve_secret

        with pytest.raises(RuntimeError):
            resolve_secret("", sandbox=False)
        assert resolve_secret("una-clave", sandbox=False) == "una-clave"
        assert len(resolve_secret("", sandbox=True)) == 64  # efímera en dev


class TestSecurityHeaders:
    def test_cabeceras_de_seguridad(self):
        r = TestClient(app).get("/health")
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["referrer-policy"] == "no-referrer"

    def test_api_no_se_cachea(self):
        c = TestClient(app)
        _login(c)
        r = c.get("/api/openvpn/clients")
        assert r.headers["cache-control"] == "no-store"
