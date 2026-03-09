"""Integration tests for the AP2 commerce mandate API endpoints."""
from __future__ import annotations


SAMPLE_INTENT = {
    "agent_did": "did:web:example.com:agents:shopping-bot",
    "intent": {
        "description": "Find running shoes under $120",
        "max_amount": 12000,
        "currency": "USD",
        "merchants": ["*"],
        "categories": ["footwear"],
    },
    "ttl_seconds": 3600,
}

SAMPLE_CART = {
    "items": [{"name": "Nike Air Max", "sku": "NK-AM-001", "quantity": 1, "price": 8999}],
    "total": {"currency": "USD", "value": 8999},
    "merchant_did": "did:web:merchant.example",
    "payment_method_type": "CARD",
}


def test_intent_endpoint(client, authz_headers):
    """POST /v1/commerce/mandates/intent returns 200 with mandate_jwt."""
    r = client.post("/v1/commerce/mandates/intent", json=SAMPLE_INTENT, headers=authz_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "mandate_jwt" in data
    assert data["mandate_jwt"].count(".") == 2  # valid 3-part JWT
    assert "mandate_id" in data
    assert "issuer_did" in data
    assert data["issuer_did"].startswith("did:")


def test_cart_endpoint(client, authz_headers):
    """POST /v1/commerce/mandates/cart succeeds when cart is within intent budget."""
    # First create an intent mandate via the API
    intent_r = client.post("/v1/commerce/mandates/intent", json=SAMPLE_INTENT, headers=authz_headers)
    assert intent_r.status_code == 200, intent_r.text
    intent_jwt = intent_r.json()["mandate_jwt"]

    cart_body = {
        "agent_did": SAMPLE_INTENT["agent_did"],
        "cart": SAMPLE_CART,
        "intent_mandate_jwt": intent_jwt,
        "ttl_seconds": 300,
    }
    r = client.post("/v1/commerce/mandates/cart", json=cart_body, headers=authz_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "mandate_jwt" in data
    assert data["mandate_jwt"].count(".") == 2
    assert "mandate_id" in data


def test_verify_endpoint(client, authz_headers):
    """POST /v1/commerce/mandates/verify correctly verifies an intent mandate."""
    # Issue an intent mandate
    intent_r = client.post("/v1/commerce/mandates/intent", json=SAMPLE_INTENT, headers=authz_headers)
    assert intent_r.status_code == 200, intent_r.text
    intent_jwt = intent_r.json()["mandate_jwt"]

    # Verify it
    verify_r = client.post(
        "/v1/commerce/mandates/verify",
        json={"jwt": intent_jwt, "mandate_type": "AP2IntentMandate"},
        headers=authz_headers,
    )
    assert verify_r.status_code == 200, verify_r.text
    data = verify_r.json()
    assert data["verified"] is True
    assert data["mandate_type"] == "AP2IntentMandate"
    assert data["scope"].get("max_amount") == 12000
    assert data["scope"].get("currency") == "USD"
    assert data["reason"] is None


def test_commerce_audit_trail(client, authz_headers):
    """Creating an intent mandate generates an audit event."""
    import core.auth.jwt_auth as jwt_auth

    # Issue a mandate to generate an audit event
    r = client.post("/v1/commerce/mandates/intent", json=SAMPLE_INTENT, headers=authz_headers)
    assert r.status_code == 200, r.text

    # Audit requires tenant:admin scope
    admin_token = jwt_auth.issue_admin_token(scopes=["tenant:admin"], tenant_id="default")
    audit_r = client.get("/v1/audit?limit=100", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_r.status_code == 200, audit_r.text

    data = audit_r.json()
    events = data.get("events") or []
    event_types = [e.get("event_type") for e in events]
    assert "commerce.mandate.intent.created" in event_types
