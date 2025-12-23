
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}


def test_create_agent_contract(client, authz_headers_agents):
    r = client.post("/v1/agents", json={"name": "test-agent"}, headers=authz_headers_agents)
    assert r.status_code == 200
    data = r.json()

    assert "id" in data
    assert data["name"] == "test-agent"
    assert data["did"].startswith("did:web:")
    assert "did_document" in data
    assert "did_document_url" in data


def test_issue_verify_revoke_flow(client, authz_headers):
    issuer = client.post("/v1/agents", json={"name": "issuer"}, headers=authz_headers).json()

    issued = client.post(
        "/v1/credentials/issue",
        headers=authz_headers,
        json={
            "issuer_agent_id": issuer["id"],
            "subject_did": "did:web:example.com:subject:123",
            "credential_type": "AgentCredential",
        },
    )
    assert issued.status_code == 200
    issued_data = issued.json()
    assert issued_data["jwt"].count(".") == 2

    verified = client.post("/v1/credentials/verify", json={"jwt": issued_data["jwt"]})
    assert verified.status_code == 200
    v = verified.json()
    assert v["verified"] is True

    revoked = client.post(f"/v1/credentials/{issued_data['credential_id']}/revoke", json={}, headers=authz_headers)
    assert revoked.status_code == 200

    verified2 = client.post("/v1/credentials/verify", json={"jwt": issued_data["jwt"]})
    assert verified2.status_code == 200
    v2 = verified2.json()
    assert v2["verified"] is False
    assert v2.get("reason") == "revoked"
