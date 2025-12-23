from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx


@dataclass
class PramanaClient:
    base_url: str = "http://localhost:8000"

    def create_agent(self, name: str) -> dict[str, Any]:
        return self._post("/v1/agents", {"name": name})

    def issue_credential(
        self,
        issuer_agent_id: str,
        subject_did: str,
        credential_type: str = "AgentCredential",
        ttl_seconds: Optional[int] = None,
        subject_claims: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "issuer_agent_id": issuer_agent_id,
            "subject_did": subject_did,
            "credential_type": credential_type,
        }
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if subject_claims is not None:
            body["subject_claims"] = subject_claims
        return self._post("/v1/credentials/issue", body)

    def verify_credential(self, jwt: str) -> dict[str, Any]:
        return self._post("/v1/credentials/verify", {"jwt": jwt})

    def revoke_credential(self, credential_id: str) -> dict[str, Any]:
        return self._post(f"/v1/credentials/{credential_id}/revoke", {})

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=20.0) as client:
            r = client.post(self.base_url + path, json=body)
            r.raise_for_status()
            return r.json()
