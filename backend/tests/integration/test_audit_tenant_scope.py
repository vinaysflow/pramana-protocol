import core.auth.jwt_auth as jwt_auth


def test_audit_is_tenant_scoped_and_requires_admin(client):
    t_user = jwt_auth.issue_admin_token(scopes=['agents:create','credentials:issue'], tenant_id='demo')
    t_admin = jwt_auth.issue_admin_token(scopes=['tenant:admin'], tenant_id='demo')
    t_other_admin = jwt_auth.issue_admin_token(scopes=['tenant:admin'], tenant_id='acme')

    # create issuer + issue to generate tenant-scoped audit events
    issuer = client.post('/v1/agents', json={'name': 'issuer-a'}, headers={'Authorization': f'Bearer {t_user}'}).json()

    client.post(
        '/v1/credentials/issue',
        headers={'Authorization': f'Bearer {t_user}'},
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    )

    # non-admin cannot read audit
    r0 = client.get('/v1/audit?limit=10', headers={'Authorization': f'Bearer {t_user}'})
    assert r0.status_code in (401, 403)

    # demo admin can read and should see at least one event
    r1 = client.get('/v1/audit?limit=10', headers={'Authorization': f'Bearer {t_admin}'})
    assert r1.status_code == 200
    events = r1.json().get('events', [])
    assert len(events) >= 1

    # other tenant admin should not see demo's issuer id
    r2 = client.get('/v1/audit?limit=50', headers={'Authorization': f'Bearer {t_other_admin}'})
    assert r2.status_code == 200
    events2 = r2.json().get('events', [])
    assert all(issuer['id'] not in (ev.get('actor','') + ev.get('resource_id','')) for ev in events2)
