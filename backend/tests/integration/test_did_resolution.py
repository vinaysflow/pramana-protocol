
def test_agent_did_doc_is_resolvable(client, authz_headers):
    agent = client.post('/v1/agents', json={'name': 'resolver-agent'}, headers=authz_headers).json()

    r = client.get(f"/agents/{agent['id']}/did.json")
    assert r.status_code == 200
    doc = r.json()

    assert doc['id'] == agent['did']
    assert doc['@context'] == ['https://www.w3.org/ns/did/v1']
    assert 'verificationMethod' in doc
