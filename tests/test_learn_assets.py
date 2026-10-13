from fastapi.testclient import TestClient

from sentinelgate.api import app
from sentinelgate.marketing import app as marketing_app


def test_gateway_serves_public_technical_tour():
    with TestClient(app) as client:
        response = client.get("/learn")
        assert response.status_code == 200
        assert "TWO-MINUTE DEMONSTRATION" in response.text
        assert "What it protects—and what it cannot" in response.text
        assert "default-src 'none'" in response.headers["content-security-policy"]


def test_marketing_process_serves_tour_and_threat_model():
    with TestClient(marketing_app) as client:
        tour = client.get("/learn")
        threat_model = client.get("/assets/sentinelgate-threat-model.md")
        assert tour.status_code == 200
        assert "EXPLANATORY SIMULATION" in tour.text
        assert threat_model.status_code == 200
        assert "Calls made directly to a tool" in threat_model.text
