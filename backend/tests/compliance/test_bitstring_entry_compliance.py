import pytest
import jwt


@pytest.mark.compliance
def test_vc_contains_bitstring_status_list_entry(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer-comp'}, headers=authz_headers).json()
    issued = client.post(
        '/v1/credentials/issue',
        headers=authz_headers,
        json={
            'issuer_agent_id': issuer['id'],
            'subject_did': 'did:web:example.com:subject:123',
            'credential_type': 'AgentCredential',
        },
    ).json()

    payload = jwt.decode(issued['jwt'], options={'verify_signature': False})
    vc = payload['vc']
    cs = vc['credentialStatus']

    assert cs['type'] == 'BitstringStatusListEntry'
    assert cs['statusPurpose'] == 'revocation'
    assert isinstance(cs['statusListIndex'], str)
    int(cs['statusListIndex'])
    assert cs['statusListCredential'].endswith(issued['status_list_id'])
