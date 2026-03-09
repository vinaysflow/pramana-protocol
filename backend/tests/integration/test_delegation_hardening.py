"""Functional tests for delegation register and cascade revocation.

Tests the hardening feature: delegations can be registered in a backend registry
and revoked individually or with cascade (all children recursively revoked).
"""
from __future__ import annotations

import pytest
import sqlalchemy as sa

import core.auth.jwt_auth as jwt_auth
from core.db import engine


@pytest.fixture(autouse=True)
def _ensure_delegation_registry():
    """Create the delegation_registry table if it doesn't exist (migration-only table)."""
    meta = sa.MetaData()
    meta.reflect(bind=engine)
    if "delegation_registry" not in meta.tables:
        tbl = sa.Table(
            "delegation_registry", meta,
            sa.Column("jti", sa.String(255), primary_key=True),
            sa.Column("tenant_id", sa.String(100), nullable=False, index=True),
            sa.Column("issuer_did", sa.String(500), nullable=False),
            sa.Column("subject_did", sa.String(500), nullable=False),
            sa.Column("parent_jti", sa.String(255), nullable=True, index=True),
            sa.Column("status_list_id", sa.String(36), nullable=True),
            sa.Column("status_list_index", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        tbl.create(bind=engine)


def _headers(scopes=None, tenant_id="default"):
    scopes = scopes or ["agents:create", "credentials:issue", "credentials:revoke"]
    token = jwt_auth.issue_admin_token(scopes=scopes, tenant_id=tenant_id)
    return {"Authorization": f"Bearer {token}"}


def test_register_delegation(client, authz_headers):
    """POST /v1/delegations/register stores a delegation in the registry."""
    import uuid
    jti = f"urn:uuid:{uuid.uuid4()}"
    r = client.post(
        "/v1/delegations/register",
        json={
            "jti": jti,
            "issuer_did": "did:key:zAlice",
            "subject_did": "did:key:zBob",
            "parent_jti": None,
        },
        headers=authz_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["registered"] is True


def test_register_duplicate_jti_rejected(client, authz_headers):
    """Registering the same JTI twice returns registered=False."""
    import uuid as _uuid
    jti = f"urn:uuid:{_uuid.uuid4()}"
    client.post(
        "/v1/delegations/register",
        json={"jti": jti, "issuer_did": "did:key:z1", "subject_did": "did:key:z2"},
        headers=authz_headers,
    )
    r2 = client.post(
        "/v1/delegations/register",
        json={"jti": jti, "issuer_did": "did:key:z1", "subject_did": "did:key:z2"},
        headers=authz_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["registered"] is False


def test_revoke_single_delegation(client, authz_headers):
    """POST /v1/delegations/revoke revokes a single delegation."""
    import uuid as _uuid
    jti = f"urn:uuid:{_uuid.uuid4()}"
    client.post(
        "/v1/delegations/register",
        json={"jti": jti, "issuer_did": "did:key:z1", "subject_did": "did:key:z2"},
        headers=authz_headers,
    )
    r = client.post(
        "/v1/delegations/revoke",
        json={"jti": jti, "cascade": False},
        headers=authz_headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["revoked"] is True
    assert data["cascaded_count"] == 0
    assert data["all_revoked"] == [jti]


def test_revoke_nonexistent_jti_404(client, authz_headers):
    """Revoking a JTI not in the registry returns 404."""
    import uuid as _uuid
    r = client.post(
        "/v1/delegations/revoke",
        json={"jti": f"urn:uuid:{_uuid.uuid4()}", "cascade": False},
        headers=authz_headers,
    )
    assert r.status_code == 404


def test_cascade_revocation(client, authz_headers):
    """Revoking a parent with cascade=True also revokes its children."""
    import uuid as _uuid
    suffix = _uuid.uuid4().hex[:8]
    parent_jti = f"urn:uuid:cascade-parent-{suffix}"
    child1_jti = f"urn:uuid:cascade-child-1-{suffix}"
    child2_jti = f"urn:uuid:cascade-child-2-{suffix}"
    grandchild_jti = f"urn:uuid:cascade-grandchild-{suffix}"

    client.post(
        "/v1/delegations/register",
        json={"jti": parent_jti, "issuer_did": "did:key:zRoot", "subject_did": "did:key:zA"},
        headers=authz_headers,
    )
    client.post(
        "/v1/delegations/register",
        json={"jti": child1_jti, "issuer_did": "did:key:zA", "subject_did": "did:key:zB", "parent_jti": parent_jti},
        headers=authz_headers,
    )
    client.post(
        "/v1/delegations/register",
        json={"jti": child2_jti, "issuer_did": "did:key:zA", "subject_did": "did:key:zC", "parent_jti": parent_jti},
        headers=authz_headers,
    )
    client.post(
        "/v1/delegations/register",
        json={"jti": grandchild_jti, "issuer_did": "did:key:zB", "subject_did": "did:key:zD", "parent_jti": child1_jti},
        headers=authz_headers,
    )

    r = client.post(
        "/v1/delegations/revoke",
        json={"jti": parent_jti, "cascade": True},
        headers=authz_headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["revoked"] is True
    assert data["cascade"] is True
    assert data["cascaded_count"] >= 3
    all_revoked = set(data["all_revoked"])
    assert parent_jti in all_revoked
    assert child1_jti in all_revoked
    assert child2_jti in all_revoked
    assert grandchild_jti in all_revoked


def test_cascade_revocation_creates_audit_event(client, authz_headers):
    """Cascade revocation writes an audit event with revoked JTI list."""
    import uuid as _uuid
    suffix = _uuid.uuid4().hex[:8]
    jti = f"urn:uuid:cascade-audit-parent-{suffix}"
    child_jti = f"urn:uuid:cascade-audit-child-{suffix}"

    client.post(
        "/v1/delegations/register",
        json={"jti": jti, "issuer_did": "did:key:z1", "subject_did": "did:key:z2"},
        headers=authz_headers,
    )
    client.post(
        "/v1/delegations/register",
        json={"jti": child_jti, "issuer_did": "did:key:z2", "subject_did": "did:key:z3", "parent_jti": jti},
        headers=authz_headers,
    )

    client.post(
        "/v1/delegations/revoke",
        json={"jti": jti, "cascade": True},
        headers=authz_headers,
    )

    admin_token = jwt_auth.issue_admin_token(scopes=["tenant:admin"], tenant_id="default")
    audit_r = client.get("/v1/audit?limit=50", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_r.status_code == 200
    events = audit_r.json()["events"]
    revoke_events = [e for e in events if e["event_type"] == "delegation.revoked"]
    assert len(revoke_events) >= 1
