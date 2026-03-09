"""
Tests for pramana.integrations.langchain — LangChain integration.

PramanaVerifierTool requires langchain-core.  If it is not installed in the
current environment, tests 3 and 4 skip instantiation via BaseTool and
exercise _run directly on a subclass that bypasses the guard — but the
guard itself is tested in test 5 via monkeypatching.
"""
from __future__ import annotations

import pytest

from pramana.credentials import issue_vc
from pramana.identity import AgentIdentity
from pramana.integrations.langchain import (
    HAS_LANGCHAIN,
    LangChainNotInstalled,
    PramanaAgentContext,
    PramanaVerifierTool,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def identity() -> AgentIdentity:
    return AgentIdentity.create("test-agent")


@pytest.fixture()
def issuer() -> AgentIdentity:
    return AgentIdentity.create("issuer")


@pytest.fixture()
def subject() -> AgentIdentity:
    return AgentIdentity.create("subject")


@pytest.fixture()
def verifier() -> AgentIdentity:
    return AgentIdentity.create("verifier")


@pytest.fixture()
def sample_vc(issuer: AgentIdentity, subject: AgentIdentity) -> str:
    return issue_vc(
        issuer=issuer,
        subject_did=subject.did,
        credential_type="CapabilityCredential",
        claims={"capability": "read"},
    )


# ---------------------------------------------------------------------------
# Helper: construct PramanaVerifierTool regardless of whether langchain
# is installed, so we can test _run logic.
# ---------------------------------------------------------------------------

def _make_tool() -> PramanaVerifierTool:
    """
    Instantiate PramanaVerifierTool, bypassing the HAS_LANGCHAIN guard.
    Works whether or not langchain-core is installed.
    """
    import pramana.integrations.langchain as lc_mod
    original = lc_mod.HAS_LANGCHAIN
    lc_mod.HAS_LANGCHAIN = True
    try:
        tool = object.__new__(PramanaVerifierTool)
        # Call object.__init__ to avoid BaseTool's __init__ when not installed
        object.__init__(tool)
        return tool
    finally:
        lc_mod.HAS_LANGCHAIN = original


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPramanaAgentContext:
    def test_agent_context_system_prompt(self, identity: AgentIdentity, sample_vc: str) -> None:
        """System prompt addition must contain the agent's DID."""
        ctx = PramanaAgentContext(identity=identity, credentials=[sample_vc])
        prompt = ctx.get_system_prompt_addition()
        assert identity.did in prompt

    def test_agent_context_auth_headers(
        self,
        identity: AgentIdentity,
        sample_vc: str,
        verifier: AgentIdentity,
    ) -> None:
        """get_auth_headers must return dict with Authorization: Bearer <jwt>."""
        ctx = PramanaAgentContext(identity=identity, credentials=[sample_vc])
        headers = ctx.get_auth_headers(audience=verifier.did)
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")
        # The Bearer value must look like a JWT (3 segments)
        token = headers["Authorization"][len("Bearer "):]
        assert token.count(".") == 2


class TestPramanaVerifierTool:
    def test_verifier_tool_valid_credential(
        self, issuer: AgentIdentity, subject: AgentIdentity, sample_vc: str
    ) -> None:
        """_run on a valid VC must return a string containing 'VERIFIED'."""
        tool = _make_tool()
        output = tool._run(sample_vc)
        assert "VERIFIED" in output

    def test_verifier_tool_invalid_credential(self) -> None:
        """_run on a garbage token must return a string containing 'FAILED'."""
        tool = _make_tool()
        output = tool._run("not.a.valid.jwt.token")
        assert "FAILED" in output

    def test_langchain_not_installed_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Constructing PramanaVerifierTool when HAS_LANGCHAIN=False raises LangChainNotInstalled."""
        import pramana.integrations.langchain as lc_mod
        monkeypatch.setattr(lc_mod, "HAS_LANGCHAIN", False)

        with pytest.raises(LangChainNotInstalled):
            PramanaVerifierTool()
