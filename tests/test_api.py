import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "MailTrail API v1"}

def test_login_success():
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "secret123"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_fail():
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    
def test_protected_route_without_token():
    response = client.get("/api/v1/emails")
    assert response.status_code == 401

def test_analyze_email_with_token():
    login_response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "secret123"}
    )
    token = login_response.json()["access_token"]
    
    payload = {
        "subject": "URGENT",
        "sender_email": "badguy@suspicious.com",
        "recipient_email": "user@example.com",
        "body_text": "Click this link immediately!"
    }
    
    response = client.post(
        "/api/v1/analyze",
        json=payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "risk_score" in response.json()
