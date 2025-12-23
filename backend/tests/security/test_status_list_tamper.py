import pytest


def _tamper_jwt(jwt_str: str) -> str:
    parts = jwt_str.split('.')
    assert len(parts) == 3
    sig = parts[2]
    if len(sig) < 12:
        # fallback: tamper payload
        payload = parts[1]
        i = 5
        payload = payload[:i] + ('a' if payload[i] != 'a' else 'b') + payload[i+1:]
        parts[1] = payload
        return '.'.join(parts)

    i = 10
    sig = sig[:i] + ('a' if sig[i] != 'a' else 'b') + sig[i+1:]
    parts[2] = sig
    return '.'.join(parts)


@pytest.mark.security
def test_tampered_status_list_jwt_fails_verification(client, monkeypatch, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-tamper'}, headers=authz_headers).json()

    issued = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()

    import api.routes.verify as verify_mod

    real_issue = verify_mod.issue_status_list_vc_jwt

    def fake_issue(status_list_id):
        jwt_str, vc = real_issue(status_list_id)
        return _tamper_jwt(jwt_str), vc

    monkeypatch.setattr(verify_mod, 'issue_status_list_vc_jwt', fake_issue)

    resp = client.post('/v1/credentials/verify', json={'jwt': issued['jwt']})
    assert resp.status_code == 400
