from core.status_issuer import ensure_status_issuer


def test_status_issuer_idempotent():
    a1, k1 = ensure_status_issuer()
    a2, k2 = ensure_status_issuer()
    assert a1.id == a2.id
    assert k1.kid == k2.kid
