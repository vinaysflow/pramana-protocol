from __future__ import annotations

import time
import uuid
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization

from core.crypto import decrypt_text
from core.did import public_key_from_jwk
from core.db import db_session
from models import Agent, Key


def _now() -> int:
    return int(time.time())


def issue_vc_jwt(
    *,
    issuer_agent_id: uuid.UUID,
    subject_did: str,
    credential_type: str,
    status_list_url: str,
    status_list_index: int,
    ttl_seconds: Optional[int] = None,
    extra_claims: Optional[dict[str, Any]] = None,
) -> tuple[str, str, int, Optional[int]]:
    with db_session() as db:
        agent = db.query(Agent).filter(Agent.id == issuer_agent_id).one()
        key = db.query(Key).filter(Key.agent_id == agent.id).filter(Key.active == True).order_by(Key.created_at.desc()).first()  # noqa: E712
        if not key:
            key = db.query(Key).filter(Key.agent_id == agent.id).order_by(Key.created_at.desc()).first()
        if not key:
            raise ValueError("No key for agent")

    private_pem = decrypt_text(key.private_key_enc)
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)

    jti = str(uuid.uuid4())
    iat = _now()
    exp = iat + ttl_seconds if ttl_seconds else None

    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", credential_type],
        "issuer": agent.did,
        "validFrom": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(iat)),
        "credentialSubject": {"id": subject_did},
        "credentialStatus": {
            "id": f"{status_list_url}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_list_index),
            "statusListCredential": status_list_url,
        },
    }

    if extra_claims:
        # merge into credentialSubject for MVP
        cs = vc.get("credentialSubject") or {}
        cs.update(extra_claims)
        vc["credentialSubject"] = cs

    payload: dict[str, Any] = {
        "iss": agent.did,
        "sub": subject_did,
        "jti": jti,
        "iat": iat,
        "vc": vc,
    }
    if exp:
        payload["exp"] = exp

    token = jwt.encode(payload, key=private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "JWT"})
    return token, jti, iat, exp


def verify_vc_jwt(*, token: str, resolve_did_document: Any, status_check: Any) -> dict[str, Any]:
    # decode header to find kid -> issuer DID
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    decoded = jwt.decode(token, options={"verify_signature": False})

    issuer = decoded.get("iss")
    if not issuer or not isinstance(issuer, str):
        raise ValueError("Missing iss")

    did_doc = resolve_did_document(issuer)

    # find verification method with matching kid (fallback first)
    vms = did_doc.get("verificationMethod") or []
    vm = None
    if kid:
        for m in vms:
            if m.get("id") == kid:
                vm = m
                break
    if vm is None and vms:
        vm = vms[0]

    if not vm:
        raise ValueError("No verification method")

    jwk = vm.get("publicKeyJwk")
    pub = public_key_from_jwk(jwk)

    payload = jwt.decode(token, key=pub, algorithms=["EdDSA"], options={"require": ["iss", "sub", "iat", "jti"]})

    # status check
    vc = payload.get("vc") or {}
    cs = vc.get("credentialStatus") or {}
    status_list_cred = cs.get("statusListCredential")
    status_list_index = cs.get("statusListIndex")

    status = {"present": False}
    if status_list_cred and status_list_index is not None:
        status["present"] = True
        status["revoked"] = bool(status_check(status_list_cred, int(status_list_index)))

    return {"payload": payload, "status": status}
