import jwt


def test_status_endpoint_returns_vc_jwt_by_default(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-status'}, headers=authz_headers).json()

    issued = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()

    sl_id = issued['status_list_id']
    r = client.get(f"/v1/status/{sl_id}")
    assert r.status_code == 200
    data = r.json()

    assert 'jwt' in data
    payload = jwt.decode(data['jwt'], options={'verify_signature': False})
    assert 'vc' in payload
    vc = payload['vc']
    assert 'BitstringStatusListCredential' in vc['type']
    assert 'encodedList' in vc['credentialSubject']


def test_status_endpoint_raw_format_still_available(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-status-raw'}, headers=authz_headers).json()

    issued = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()

    sl_id = issued['status_list_id']
    r = client.get(f"/v1/status/{sl_id}?format=raw")
    assert r.status_code == 200
    data = r.json()

    assert data['id'] == sl_id
    assert 'bitstring' in data
