import jwt

import core.auth.jwt_auth as jwt_auth


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_key_rotation_keeps_old_vcs_verifiable(client):
    t_user = jwt_auth.issue_admin_token(scopes=["agents:create", "credentials:issue"], tenant_id="demo")
    t_admin = jwt_auth.issue_admin_token(scopes=["tenant:admin"], tenant_id="demo")

    issuer = client.post('/v1/agents', json={'name': 'issuer-rot'}, headers=_hdr(t_user)).json()

    issued1 = client.post(
        '/v1/credentials/issue',
        headers=_hdr(t_user),
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()
    kid1 = jwt.get_unverified_header(issued1['jwt']).get('kid')

    rrot = client.post(f"/v1/agents/{issuer['id']}/keys/rotate", headers=_hdr(t_admin), json={})
    assert rrot.status_code == 200

    issued2 = client.post(
        '/v1/credentials/issue',
        headers=_hdr(t_user),
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:456',
            'credential_type': 'AgentCredential',
        },
    ).json()
    kid2 = jwt.get_unverified_header(issued2['jwt']).get('kid')

    assert kid1 != kid2

    v1 = client.post('/v1/credentials/verify', json={'jwt': issued1['jwt']}).json()
    assert v1['verified'] is True

    v2 = client.post('/v1/credentials/verify', json={'jwt': issued2['jwt']}).json()
    assert v2['verified'] is True
