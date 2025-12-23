import pytest


@pytest.mark.e2e
def test_drift_breach_scenario_minimal(client, authz_headers):
    walmart = client.post('/v1/agents', json={'name': 'walmart-procurement'}, headers=authz_headers).json()

    cred = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': walmart['id'],
            'subject_did': 'did:web:example.com:supplier:api',
            'credential_type': 'CapabilityCredential',
            'subject_claims': {
                'capability': 'negotiate_contracts',
                'max_amount_usd': 100000,
                'severity': 'normal',
            },
        },
    ).json()

    verify_before = client.post('/v1/credentials/verify', json={'jwt': cred['jwt']}).json()
    assert verify_before['verified'] is True

    revoke = client.post(f"/v1/credentials/{cred['credential_id']}/revoke", json={}, headers=authz_headers).json()
    assert revoke['revoked'] is True

    verify_after = client.post('/v1/credentials/verify', json={'jwt': cred['jwt']}).json()
    assert verify_after['verified'] is False
    assert verify_after.get('reason') == 'revoked'
