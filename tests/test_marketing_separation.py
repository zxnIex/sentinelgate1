from fastapi.testclient import TestClient

from sentinelgate.marketing import app


def test_public_marketing_process_exposes_no_control_plane():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["service"] == "marketing"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/v1/agents").status_code == 404
