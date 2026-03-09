"""Functional tests for atomic status list index allocation and JTI dedup unit logic."""
from __future__ import annotations


# ── Atomic index allocation ───────────────────────────────────────────────────

def test_allocate_index_returns_sequential_indices():
    """allocate_index returns distinct sequential indices."""
    from core.status_list import allocate_index, get_or_create_default_list

    sl = get_or_create_default_list(tenant_id="index-test")
    indices = []
    for _ in range(5):
        idx = allocate_index(sl.id)
        indices.append(idx)

    # All indices must be distinct
    assert len(set(indices)) == 5, f"Got duplicate indices: {indices}"
    # They should be sequential (0, 1, 2, 3, 4 or similar)
    assert sorted(indices) == list(range(indices[0], indices[0] + 5))


def test_allocate_index_nonexistent_list_raises():
    """allocate_index raises when the status list doesn't exist."""
    import uuid
    import pytest
    from core.status_list import allocate_index

    fake_id = str(uuid.uuid4())
    with pytest.raises(Exception):
        allocate_index(fake_id)


# ── JTI dedup unit tests ─────────────────────────────────────────────────────

def test_jti_dedup_fresh_jti_accepted():
    """A fresh JTI passes dedup check (returns None)."""
    from core.jti_dedup import check_and_record_jti, clear_dedup_store

    clear_dedup_store()
    result = check_and_record_jti("urn:uuid:fresh-001", endpoint="test")
    assert result is None


def test_jti_dedup_duplicate_rejected():
    """A duplicate JTI is rejected with a reason string."""
    from core.jti_dedup import check_and_record_jti, clear_dedup_store

    clear_dedup_store()
    check_and_record_jti("urn:uuid:dup-001", endpoint="test")
    result = check_and_record_jti("urn:uuid:dup-001", endpoint="test")
    assert result is not None
    assert "replay" in result.lower()


def test_jti_dedup_expired_entries_evicted():
    """JTIs with exp in the past are evicted and can be re-presented."""
    import time
    from core.jti_dedup import check_and_record_jti, clear_dedup_store

    clear_dedup_store()
    # Record with exp already in the past
    past_exp = int(time.time()) - 10
    check_and_record_jti("urn:uuid:expire-001", endpoint="test", exp=past_exp)

    # Should be evicted on next check
    result = check_and_record_jti("urn:uuid:expire-001", endpoint="test")
    assert result is None  # accepted (expired entry was evicted)


def test_jti_dedup_empty_jti_ignored():
    """Empty JTI string is not tracked."""
    from core.jti_dedup import check_and_record_jti, clear_dedup_store

    clear_dedup_store()
    assert check_and_record_jti("", endpoint="test") is None
    assert check_and_record_jti("", endpoint="test") is None  # still None
