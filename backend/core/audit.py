from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import desc, select

from core.db import db_session
from models import AuditEvent

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def _normalize_timestamp(dt) -> str:
    """Return a timezone-aware UTC isoformat string regardless of input.

    datetime.utcnow() produces naive datetimes, but Postgres returns
    timezone-aware ones.  This ensures the hash input is identical at
    write time (pre-commit, naive) and read time (post-commit, aware).
    """
    if dt is None:
        return ""
    from datetime import timezone
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _compute_event_hash(evt: AuditEvent, prev_hash: str) -> str:
    """SHA-256 over deterministic event fields + prev_hash."""
    payload_str = json.dumps(evt.payload_json, sort_keys=True, separators=(",", ":"))
    created_at_iso = _normalize_timestamp(evt.created_at)
    raw = (
        f"{evt.id}|{evt.event_type}|{evt.actor}|{evt.resource_id}"
        f"|{payload_str}|{created_at_iso}|{prev_hash}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_audit(
    *,
    tenant_id: str,
    event_type: str,
    actor: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
) -> AuditEvent:
    if not tenant_id:
        tenant_id = "default"

    with db_session() as db:
        # Fetch the last event's hash for this tenant to build the chain
        last = (
            db.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == tenant_id)
                .order_by(desc(AuditEvent.created_at))
                .limit(1)
            )
            .scalars()
            .first()
        )
        prev_hash = last.event_hash if (last and last.event_hash) else GENESIS_HASH

        evt = AuditEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_json=payload,
            prev_hash=prev_hash,
        )
        db.add(evt)
        db.flush()  # get auto-generated id + created_at from DB defaults

        # Compute event hash after flush so id/created_at are populated
        evt.event_hash = _compute_event_hash(evt, prev_hash)
        db.commit()
        db.refresh(evt)
        return evt


def verify_chain(tenant_id: str) -> dict[str, Any]:
    """Walk the full audit chain for a tenant and verify hash integrity.

    Returns a dict with:
      - valid: bool
      - events_checked: int
      - first_broken_at: str | None (event id where chain breaks)
      - reason: str | None
    """
    if not tenant_id:
        tenant_id = "default"

    with db_session() as db:
        events = (
            db.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == tenant_id)
                .order_by(AuditEvent.created_at.asc())
            )
            .scalars()
            .all()
        )

    if not events:
        return {"valid": True, "events_checked": 0, "first_broken_at": None, "reason": None}

    prev_hash = GENESIS_HASH
    for idx, evt in enumerate(events):
        if evt.event_hash is None:
            # Legacy event before hardening — skip chain check
            prev_hash = evt.event_hash or GENESIS_HASH
            continue

        if evt.prev_hash != prev_hash:
            return {
                "valid": False,
                "events_checked": idx,
                "first_broken_at": str(evt.id),
                "reason": f"prev_hash mismatch at event {evt.id}: expected {prev_hash}, got {evt.prev_hash}",
            }

        expected_hash = _compute_event_hash(evt, prev_hash)
        if evt.event_hash != expected_hash:
            return {
                "valid": False,
                "events_checked": idx,
                "first_broken_at": str(evt.id),
                "reason": f"event_hash mismatch at event {evt.id}: record was tampered",
            }

        prev_hash = evt.event_hash

    return {
        "valid": True,
        "events_checked": len(events),
        "first_broken_at": None,
        "reason": None,
    }
