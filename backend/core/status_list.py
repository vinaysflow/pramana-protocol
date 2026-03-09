from __future__ import annotations

import base64
import uuid
from datetime import datetime

from sqlalchemy import select, update

from core.db import db_session
from models import StatusList

DEFAULT_LIST_SIZE = 16384


def _normalize_id(status_list_id):
    if isinstance(status_list_id, uuid.UUID):
        return status_list_id
    try:
        return uuid.UUID(str(status_list_id))
    except Exception:
        return status_list_id


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _ensure_list(*, tenant_id: str, purpose: str = "revocation", size: int = DEFAULT_LIST_SIZE) -> StatusList:
    if not tenant_id:
        tenant_id = 'default'

    with db_session() as db:
        row = (
            db.execute(select(StatusList).where(StatusList.tenant_id == tenant_id).where(StatusList.purpose == purpose))
            .scalars()
            .first()
        )
        if row:
            return row

        raw = bytes(size // 8)
        sl = StatusList(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            purpose=purpose,
            bitstring=_b64url(raw),
            size=size,
            updated_at=datetime.utcnow(),
        )
        db.add(sl)
        db.commit()
        db.refresh(sl)
        return sl


def allocate_index(status_list_id) -> int:
    """Atomically reserve the next available status list index.

    Uses an UPDATE ... RETURNING pattern (or equivalent) so that concurrent
    callers always receive distinct indices — no linear scan, no race condition.
    """
    norm_id = _normalize_id(status_list_id)
    with db_session() as db:
        # Atomic increment: fetch-and-increment next_index in a single statement.
        # SQLite serializes writes so this is safe there too.
        stmt = (
            update(StatusList)
            .where(StatusList.id == norm_id)
            .values(next_index=StatusList.next_index + 1, updated_at=datetime.utcnow())
            .returning(StatusList.next_index, StatusList.size)
        )
        row = db.execute(stmt).fetchone()
        if row is None:
            raise ValueError(f"Status list {status_list_id} not found")
        # next_index is the NEW value (post-increment), so the allocated slot is new_val - 1
        allocated = row[0] - 1
        size = row[1]
        if allocated >= size:
            raise ValueError("Status list is full")
        db.commit()
        return allocated


def set_revoked(status_list_id, index: int) -> None:
    with db_session() as db:
        sl = db.query(StatusList).filter(StatusList.id == _normalize_id(status_list_id)).one()
        if index < 0 or index >= sl.size:
            raise ValueError("Index out of bounds")
        bits = bytearray(_b64url_decode(sl.bitstring))
        byte_i = index // 8
        bit_i = index % 8
        bits[byte_i] |= 1 << bit_i
        sl.bitstring = _b64url(bytes(bits))
        sl.updated_at = datetime.utcnow()
        db.add(sl)
        db.commit()


def is_revoked(status_list_id, index: int) -> bool:
    with db_session() as db:
        sl = db.query(StatusList).filter(StatusList.id == _normalize_id(status_list_id)).one()
        bits = _b64url_decode(sl.bitstring)
        if index < 0 or index >= sl.size:
            return False
        byte_i = index // 8
        bit_i = index % 8
        return (bits[byte_i] & (1 << bit_i)) != 0


def get_or_create_default_list(*, tenant_id: str = 'default') -> StatusList:
    return _ensure_list(tenant_id=tenant_id)
