import core.auth.jwt_auth as jwt_auth


def test_workflow_drift_demo_single_call(client):
    token = jwt_auth.issue_admin_token(
        scopes=['agents:create', 'credentials:issue', 'credentials:revoke'],
        tenant_id='demo',
    )

    r = client.post('/v1/workflows/drift-demo', headers={'Authorization': f'Bearer {token}'}, json={})
    assert r.status_code == 200
    data = r.json()

    assert data['tenant_id'] == 'demo'
    assert data['verify_before']['verified'] is True
    assert data['verify_after']['verified'] is False
    assert data['verify_after'].get('reason') == 'revoked'
