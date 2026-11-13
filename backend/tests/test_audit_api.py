import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_healthcheck():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "PasswordAudit"

def test_stats_endpoint():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "totalAudits" in data
    assert "complianceRate" in data

def test_audit_single_password():
    payload = {
        "password": "UltraStrong#Passphrase2026!",
        "identifier": "test-engineer"
    }
    res = client.post("/api/audit", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["identifier"] == "test-engineer"
    assert data["entropy_bits"] > 80.0
    assert data["nist_compliant"] is True
    assert "crack_times" in data
    assert "offline_gpu_cluster" in data["crack_times"]

def test_audit_batch_passwords():
    payload = {
        "passwords": [
            "123456",
            "qwerty",
            "Winter2026!",
            "xK9#mQ2$vL8*zP4!"
        ]
    }
    res = client.post("/api/audit/batch", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["total_evaluated"] == 4
    assert len(data["results"]) == 4
    assert data["critical_risk_count"] >= 1

def test_list_logs():
    res = client.get("/api/logs")
    assert res.status_code == 200
    data = res.json()
    assert "logs" in data
    assert len(data["logs"]) >= 1
