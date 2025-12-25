from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class RequirementIntent(Base):
    __tablename__ = "requirement_intents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="default", index=True)

    # Stripe-like state machine (minimal)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="requires_input", index=True)

    # Request inputs
    subject_did: Mapped[Optional[str]] = mapped_column(String(600), nullable=True)
    issuer_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    subject_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    requirements: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Idempotency
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)
    request_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    confirm_idempotency_key: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)
    confirm_request_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Outputs
    decision: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    proof_bundle: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


