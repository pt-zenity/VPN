"""Endpoint /metrics (Prometheus): público y con el formato esperado."""
from fastapi.testclient import TestClient

from vpn_manager.api.app import app


def test_metrics_es_publico_y_formato_prometheus():
    c = TestClient(app)
    c.get("/health")  # genera al menos una petición que se contabiliza
    r = c.get("/metrics")
    assert r.status_code == 200          # accesible SIN login
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "vpnmanager_up 1" in body
    assert "vpnmanager_uptime_seconds" in body
    assert "# TYPE vpnmanager_http_requests_total counter" in body
    # La petición GET previa quedó contabilizada como 2xx.
    assert 'vpnmanager_http_requests_total{method="GET",status="2xx"}' in body


def test_metrics_no_requiere_autenticacion():
    # Sin cookie de sesión: /metrics responde 200 (a diferencia de las rutas /api/*).
    assert TestClient(app).get("/metrics").status_code == 200
