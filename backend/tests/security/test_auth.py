import pytest


@pytest.mark.security
def test_agents_create_requires_token(client):
    r = client.post('/v1/agents', json={'name': 'noauth'})
    assert r.status_code in (401, 403)


@pytest.mark.security
def test_revoke_requires_token(client):
    # Without auth this would be 404 (credential not found). With auth it should be blocked.
    r = client.post('/v1/credentials/00000000-0000-0000-0000-000000000000/revoke', json={})
    assert r.status_code in (401, 403)


@pytest.mark.security
def test_verify_remains_public(client):
    r = client.post('/v1/credentials/verify', json={'jwt': 'not.a.jwt'})
    assert r.status_code in (400, 422)
