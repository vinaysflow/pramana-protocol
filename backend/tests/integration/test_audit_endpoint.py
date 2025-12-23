import core.auth.jwt_auth as jwt_auth


def test_audit_endpoint_returns_events(client):
    # create data with normal scopes
    token_user = jwt_auth.issue_admin_token(scopes=['agents:create','credentials:issue','credentials:revoke'], tenant_id='default')
    token_admin = jwt_auth.issue_admin_token(scopes=['tenant:admin'], tenant_id='default')

    issuer = client.post('/v1/agents', json={'name': 'issuer-audit'}, headers={'Authorization': f'Bearer {token_user}'}).json()
    issued = client.post(
        '/v1/credentials/issue',
        headers={'Authorization': f'Bearer {token_user}'},
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()

    client.post(
        f"/v1/credentials/{issued['credential_id']}/revoke",
        json={},
        headers={'Authorization': f'Bearer {token_user}'},
    )

    r = client.get('/v1/audit?limit=50', headers={'Authorization': f'Bearer {token_admin}'})
    assert r.status_code == 200
    data = r.json()
    assert 'events' in data
    types = {e['event_type'] for e in data['events']}
    assert 'credential.issued' in types
    assert 'credential.revoked' in types
