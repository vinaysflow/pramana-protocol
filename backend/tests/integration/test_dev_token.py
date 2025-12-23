
def test_dev_token_endpoint_disabled_by_default(client):
    r = client.post('/v1/auth/dev-token', json={'subject': 'x', 'scopes': ['agents:create']})
    assert r.status_code == 404
