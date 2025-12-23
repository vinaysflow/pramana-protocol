import pytest
import jwt as pyjwt


@pytest.mark.security
def test_none_alg_rejected(client):
    # header.payload. with alg=none
    token = pyjwt.encode({"iss": "did:web:example.com", "sub": "x", "iat": 0, "jti": "x"}, key=None, algorithm=None)
    r = client.post("/v1/credentials/verify", json={"jwt": token})
    assert r.status_code in (400, 422)


@pytest.mark.security
def test_garbage_jwt_rejected(client):
    r = client.post("/v1/credentials/verify", json={"jwt": "not.a.jwt"})
    assert r.status_code in (400, 422)
