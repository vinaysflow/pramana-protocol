import pytest
import jwt


@pytest.mark.compliance
def test_did_document_has_required_fields(client, authz_headers):
    agent = client.post('/v1/agents', json={'name': 'compliance-agent'}, headers=authz_headers).json()
    r = client.get(f"/agents/{agent['id']}/did.json")
    assert r.status_code == 200
    doc = r.json()

    assert doc.get('@context') == ['https://www.w3.org/ns/did/v1']
    assert doc.get('id') == agent['did']
    assert 'verificationMethod' in doc


@pytest.mark.compliance
def test_vc_jwt_has_vc_claim_and_context(client, authz_headers):
    issuer = client.post('/v1/agents', json={'name': 'issuer'}, headers=authz_headers).json()

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
    assert 'vc' in payload
    vc = payload['vc']
    assert 'https://www.w3.org/ns/credentials/v2' in vc['@context']
    assert 'credentialStatus' in vc
