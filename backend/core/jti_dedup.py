"""JTI deduplication — prevents JWT replay attacks.

Uses an in-memory dict as a fast hot-path (evicted by TTL on access), with a
DB write-through to the `seen_jtis` table for persistence across restarts.

On startup, `warm_jti_cache()` loads non-expired JTIs from the DB so replay
protection is active immediately without any warm-up window.

Usage:
    from core.jti_dedup import check_and_record_jti

    err = check_and_record_jti(jti, endpoint="verify", exp=payload_exp)
    if err:
        raise HTTPException(status_code=409, detail=err)
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from core.settings import settings

logger = logging.getLogger(__name__)

# Thread-safe in-memory dedup store: jti -> (endpoint, first_seen_ts, expires_ts)
_store: dict[str, tuple[str, float, float]] = {}
_lock = threading.Lock()


def _evict_expired() -> None:
    """Remove expired JTI entries. Called on every check to bound memory usage."""
    now = time.time()
    expired = [k for k, (_, _, exp) in _store.items() if exp < now]
    for k in expired:
        del _store[k]


def _db_record_jti(jti: str, endpoint: str, expires_at: float) -> bool:
    """Insert JTI into DB. Returns True if inserted (new), False if already present."""
    try:
        from sqlalchemy import text
        from core.db import db_session

        first_seen = datetime.now(timezone.utc)
        exp_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)

        with db_session() as db:
            # Try INSERT; if the JTI already exists, the unique constraint fires and
            # we catch IntegrityError to distinguish new vs replay without a pre-select.
            db.execute(
                text(
                    "INSERT INTO seen_jtis (jti, endpoint, first_seen_at, expires_at)"
                    " VALUES (:jti, :endpoint, :first_seen_at, :expires_at)"
                    " ON CONFLICT (jti) DO NOTHING"
                ),
                {
                    "jti": jti,
                    "endpoint": endpoint[:100],
                    "first_seen_at": first_seen,
                    "expires_at": exp_dt,
                },
            )
            # Check if our insert actually landed (rowcount may not be reliable across
            # all drivers for ON CONFLICT DO NOTHING, so we verify with a select).
            row = db.execute(
                text("SELECT endpoint, first_seen_at FROM seen_jtis WHERE jti = :jti"),
                {"jti": jti},
            ).fetchone()
            db.commit()

        if row and row[0] != endpoint:
            # Row existed before our insert — this is a replay
            return False
        return True
    except Exception:
        # If the DB table doesn't exist yet (pre-migration), fall back silently.
        logger.debug("seen_jtis DB write failed — falling back to in-memory only", exc_info=True)
        return True  # Optimistic: let in-memory store handle it


def warm_jti_cache() -> int:
    """Load non-expired JTIs from DB into in-memory cache. Call on startup."""
    if not settings.jti_dedup_enabled:
        return 0
    try:
        from sqlalchemy import text
        from core.db import db_session

        now = datetime.now(timezone.utc)
        with db_session() as db:
            rows = db.execute(
                text(
                    "SELECT jti, endpoint, first_seen_at, expires_at"
                    " FROM seen_jtis WHERE expires_at > :now"
                ),
                {"now": now},
            ).fetchall()

        loaded = 0
        with _lock:
            for row in rows:
                jti = row[0]
                endpoint = row[1]
                first_seen_ts = row[2].timestamp() if hasattr(row[2], "timestamp") else float(row[2])
                expires_ts = row[3].timestamp() if hasattr(row[3], "timestamp") else float(row[3])
                if jti not in _store:
                    _store[jti] = (endpoint, first_seen_ts, expires_ts)
                    loaded += 1

        logger.info("Warmed JTI dedup cache from DB: %d entries loaded", loaded)
        return loaded
    except Exception:
        logger.debug("JTI cache warm from DB failed — starting cold", exc_info=True)
        return 0


def check_and_record_jti(
    jti: str,
    endpoint: str,
    exp: Optional[int] = None,
) -> Optional[str]:
    """Check if a JTI has been seen before. If not, record it and return None.
    If yes, return a reason string describing the replay attempt.

    First checks the in-memory store (fast path). If not found in memory,
    attempts a DB insert to persist across restarts. The in-memory entry is
    written regardless so subsequent in-process checks are fast.

    Args:
        jti: The JWT ID claim to check.
        endpoint: The endpoint name (used for logging/audit, not dedup key).
        exp: The JWT exp (Unix timestamp). Used to set the dedup window.
             Falls back to settings.jti_dedup_window_seconds if not provided.

    Returns:
        None if JTI is fresh (not seen before).
        A reason string if JTI is a duplicate.
    """
    if not settings.jti_dedup_enabled:
        return None

    if not jti:
        return None

    now = time.time()
    expires_at = float(exp) if exp else (now + settings.jti_dedup_window_seconds)

    with _lock:
        _evict_expired()

        if jti in _store:
            seen_endpoint, first_seen, _ = _store[jti]
            return (
                f"JWT replay detected: JTI '{jti}' was already presented to "
                f"'{seen_endpoint}' at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(first_seen))}"
            )

        # Not in memory: try DB write-through (returns False if already in DB)
        is_new = _db_record_jti(jti, endpoint, expires_at)
        if not is_new:
            # Already in DB — add to memory cache and report replay
            _store[jti] = (endpoint, now, expires_at)
            return (
                f"JWT replay detected: JTI '{jti}' was previously recorded "
                f"(persisted across restart)"
            )

        # Fresh — record in memory
        _store[jti] = (endpoint, now, expires_at)
        return None


def clear_dedup_store() -> None:
    """Clear the in-memory dedup store. Useful for testing."""
    with _lock:
        _store.clear()
