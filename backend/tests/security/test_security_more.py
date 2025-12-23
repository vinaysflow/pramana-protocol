import pytest


@pytest.mark.security
def test_hs256_is_rejected(client):
    import jwt as pyjwt

    token = pyjwt.encode(
        {'iss': 'did:web:example.com', 'sub': 'x', 'iat': 0, 'jti': 'x'},
        'secret',
        algorithm='HS256',
    )
    r = client.post('/v1/credentials/verify', json={'jwt': token})
    assert r.status_code == 400


@pytest.mark.security
def test_path_traversal_in_did_resolution_is_not_500(client):
    r = client.get('/v1/dids/../../../etc/passwd/did.json')
    assert r.status_code in (400, 404)


@pytest.mark.security
def test_large_payload_issue_rejected_413(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-large'}, headers=authz_headers).json()

    big = {'data': 'x' * (2 * 1024 * 1024)}
    r = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
            'subject_claims': big,
        },
    )
    assert r.status_code == 413
