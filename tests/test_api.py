import pytest
from fastapi.testclient import TestClient
from main import app
from config import settings

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_docs_page(client):
    response = client.get("/docs")
    assert response.status_code == 200

def test_login_success_admin(client):
    response = client.post("/api/v1/auth/token", data={
        "username": settings.admin_username,
        "password": "admin123"
    })
    assert response.status_code == 200
    assert response.cookies.get("access_token") is not None

def test_login_success_analyst(client):
    response = client.post("/api/v1/auth/token", data={
        "username": settings.analyst_username,
        "password": "analyst123"
    })
    assert response.status_code == 200
    assert response.cookies.get("access_token") is not None

def test_login_failure(client):
    response = client.post("/api/v1/auth/token", data={
        "username": "fakeuser",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_rbac_analyst_cannot_delete(client):
    login_resp = client.post("/api/v1/auth/token", data={
        "username": settings.analyst_username,
        "password": "analyst123"
    })
    cookie = login_resp.cookies.get("access_token")
    del_resp = client.delete("/api/v1/investigations", cookies={"access_token": cookie})
    assert del_resp.status_code == 403

def test_rbac_admin_can_delete(client):
    login_resp = client.post("/api/v1/auth/token", data={
        "username": settings.admin_username,
        "password": "admin123"
    })
    cookie = login_resp.cookies.get("access_token")
    del_resp = client.delete("/api/v1/investigations", cookies={"access_token": cookie})
    assert del_resp.status_code == 200
    assert del_resp.json() == {"message": "Vault cleared"}
