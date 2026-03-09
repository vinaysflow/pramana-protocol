---
title: Pramana Protocol
sdk: docker
pinned: false
---

# Pramana Protocol

**Zero-Trust Identity for AI Agents** — W3C DIDs, Verifiable Credentials, AP2 Commerce, SPIFFE bridge, and tamper-evident audit trails for autonomous agent systems.

> Pramana answers the question every enterprise deploying AI agents needs to answer: *"How do you know what an agent is, what it's authorized to do, and what it actually did?"*

---

## What it does

| Problem | Pramana answer |
|---|---|
| Agent has no cryptographic identity | `did:web` / `did:key` — every agent gets a W3C DID with an Ed25519 keypair |
| No way to authorize what an agent can do | W3C Verifiable Credentials with typed claims (`TaskAuthorizationCredential`, etc.) |
| Sub-agents can claim more authority than delegated | Delegation chains with **scope narrowing** — child scope is always a strict subset of parent |
| Agents exceed spending budgets | AP2 Mandates — cumulative budget enforcement with replay protection and `FOR UPDATE` locks |
| No audit trail | SHA-256 hash-chained immutable audit log with integrity verification |
| Infrastructure identity doesn't translate to app authority | SPIFFE bridge — present an SVID, receive a W3C VC |
| Compliance teams need evidence | Live compliance reports: SOC2, HIPAA, EU AI Act, ISO 42001 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Pramana Protocol                         │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Identity     │  │ Authority    │  │ Commerce         │  │
│  │              │  │              │  │                  │  │
│  │ did:web      │  │ VC issuance  │  │ AP2 Intent       │  │
│  │ did:key      │  │ Delegation   │  │ AP2 Cart         │  │
│  │ SPIFFE SVID  │  │ chain verify │  │ Budget enforce   │  │
│  │ → W3C VC     │  │ Scope narrow │  │ Replay protect   │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Audit        │  │ Trust        │  │ Compliance       │  │
│  │              │  │              │  │                  │  │
│  │ Hash-chained │  │ Score events │  │ SOC2 / HIPAA     │  │
│  │ tamper-proof │  │ Risk tiers   │  │ EU AI Act        │  │
│  │ JSONL export │  │ Anomaly det. │  │ ISO 42001        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  SDKs: Python · TypeScript · React hooks           │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Stack:** FastAPI · PostgreSQL · SQLAlchemy · Alembic · Next.js 14 · Tailwind CSS · Ed25519 · PyJWT · W3C VC-JOSE

---

## Demo dashboard

The interactive demo runs all scenarios against a live backend:

```
http://localhost:3001/demo-dashboard
```

Six tabs:

| Tab | What it shows |
|---|---|
| **Scenarios** | Happy path, unhappy path (attacks blocked), edge cases |
| **SPIFFE Bridge** | SVID → W3C VC attestation flow |
| **Compliance** | SOC2 / HIPAA / EU AI Act / ISO 42001 scorecards |
| **Marketplace** | Verified merchant agents + AP2 transaction history |
| **Risk** | Fleet-level trust tiers + indicative insurance premium |
| **Anomalies** | Behavioral anomaly detection — rapid drops, scope violations |

**To use:** click "Load Demo Data" in the System State bar, then explore any tab.

---

## Quickstart (local dev)

### Prerequisites
- Python 3.9+
- Node 18+
- PostgreSQL 15 (or Docker)

### 1. Clone and set up

```bash
git clone https://github.com/vinaysflow/pramana-protocol.git
cd pramana-protocol
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — set these three at minimum:
# API_SECRET_KEY=<32+ random chars>
# AUTH_JWT_SECRET=<32+ random chars>
# POSTGRES_PASSWORD=<your choice>
```

Generate secrets:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Start

```bash
# Option A — Docker (Postgres + Backend + Frontend)
make dev

# Option B — Manual
cd backend && uvicorn main:app --host 0.0.0.0 --port 5051 --reload
cd frontend && npm install && npm run dev -- -p 3001
```

### 4. Verify

```bash
curl http://localhost:5051/health
# → {"status":"healthy"}
```

Open: `http://localhost:3001/demo-dashboard`

---

## API reference

All endpoints require `Authorization: Bearer <token>`.

Get a token (demo mode):
```bash
TOKEN=$(curl -s -X POST http://localhost:5051/v1/demo/session \
  -H 'content-type: application/json' -d '{}' | jq -r '.token')
```

### Identity

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/agents` | Register an AI agent — returns DID + DID document |
| `POST` | `/v1/agents/{id}/keys/rotate` | Rotate the agent's signing key |
| `POST` | `/v1/identity/attest` | SPIFFE SVID → W3C WorkloadAttestationCredential |
| `GET` | `/v1/identity/{did}/spiffe` | Get SPIFFE binding for a DID |
| `GET` | `/v1/identity/spiffe/{spiffe_id}` | Get agent by SPIFFE ID |
| `GET` | `/agents/{id}/did.json` | Resolve DID document |

### Credentials

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/credentials/issue` | Issue a W3C VC-JOSE/JWT |
| `POST` | `/v1/credentials/verify` | Cryptographically verify a VC |
| `POST` | `/v1/credentials/{id}/revoke` | Revoke via Bitstring Status List |
| `GET` | `/v1/status/{status_list_id}` | Fetch status list VC |

### Delegation

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/delegations/register` | Register a delegation VC |
| `POST` | `/v1/delegations/verify` | Server-side chain + scope narrowing check |
| `POST` | `/v1/delegations/revoke` | Revoke a delegation |

### Commerce (AP2)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/commerce/mandates/intent` | Create intent mandate (total budget authorization) |
| `POST` | `/v1/commerce/mandates/cart` | Create cart mandate (specific transaction) |
| `POST` | `/v1/commerce/mandates/verify` | Verify cart — checks budget, replay, scope |
| `GET` | `/v1/commerce/mandates/{jti}/spend` | Get spend history for an intent mandate |

### Trust & Risk

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/trust/score` | Record a trust event for an agent |
| `GET` | `/v1/trust/agent/{did}` | Get trust history for a specific agent |
| `GET` | `/v1/trust/risk-dashboard` | Fleet-level risk tiers + insurance premium |
| `GET` | `/v1/trust/anomalies` | Agents with anomalous trust behavior |

### Compliance

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/compliance/controls` | List supported frameworks |
| `GET` | `/v1/compliance/report?framework=SOC2` | Live compliance report with automated evidence |

Supported frameworks: `SOC2`, `HIPAA`, `EU AI Act`, `ISO 42001`

### Marketplace

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/marketplace/merchants` | Verified merchant agents |
| `GET` | `/v1/marketplace/merchants/{did}/transactions` | Transaction history for a merchant |

### Audit

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/audit` | Tenant-scoped audit log |
| `GET` | `/v1/audit/export` | JSONL export |
| `GET` | `/v1/audit/verify` | Verify hash chain integrity |

### Webhooks

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/webhooks` | Register a webhook |
| `GET` | `/v1/webhooks` | List webhooks |
| `POST` | `/v1/webhooks/{id}/test` | Send a test event |

Full interactive docs: `http://localhost:5051/docs`

---

## Python SDK

```bash
pip install pramana-sdk
# or from source:
pip install "git+https://github.com/vinaysflow/pramana-protocol.git#subdirectory=sdk/python"
```

```python
from pramana import AgentIdentity, issue_vc, verify_vc, issue_delegation, verify_delegation_chain

# 1. Create agent identity (offline, no server needed)
agent = AgentIdentity.generate()
print(agent.did)  # did:key:z6Mk...

# 2. Issue a Verifiable Credential
vc_jwt = issue_vc(
    issuer=agent,
    subject_did=agent.did,
    credential_type="TaskAuthorizationCredential",
    claims={"maxBudgetUSD": 500, "allowedTools": ["web_search", "code_exec"]},
)

# 3. Verify it
result = verify_vc(vc_jwt)
print(result.valid)   # True
print(result.claims)  # {"maxBudgetUSD": 500, ...}

# 4. Delegate authority to a sub-agent (scope-narrowed)
sub_agent = AgentIdentity.generate()
delegation = issue_delegation(
    issuer=agent,
    subject_did=sub_agent.did,
    parent_vc_jwt=vc_jwt,
    scope={"maxBudgetUSD": 50, "allowedTools": ["web_search"]},  # narrowed
    ttl_seconds=3600,
)

# 5. Verify the chain — child scope must be subset of parent
chain_result = verify_delegation_chain([delegation])
print(chain_result.valid)           # True
print(chain_result.effective_scope) # {"maxBudgetUSD": 50, ...}
```

### AP2 Commerce

```python
from pramana import issue_intent_mandate, issue_cart_mandate, verify_mandate

# Authorize total budget
intent = issue_intent_mandate(issuer=buyer, max_amount=200.00, currency="USD", payee_did=merchant.did)

# Authorize a specific cart
cart = issue_cart_mandate(issuer=buyer, intent_jwt=intent, cart_value=45.00, currency="USD")

# Merchant verifies — checks budget, replay protection, scope
result = verify_mandate(cart, expected_payee_did=merchant.did)
print(result.authorized)       # True
print(result.remaining_budget) # 155.00
```

---

## TypeScript SDK

```bash
npm install @pramana/sdk
```

```typescript
import { AgentIdentity, issueVC, verifyVC, issueDelegation, verifyDelegationChain } from "@pramana/sdk";

const agent = await AgentIdentity.generate();
const { jwt } = await issueVC(agent, {
  subjectDid: agent.did,
  credentialType: "TaskAuthorizationCredential",
  claims: { maxBudgetUSD: 500, allowedTools: ["web_search"] },
});

const result = await verifyVC(jwt);
console.log(result.valid);  // true
```

---

## React hooks

```bash
npm install @pramana/react @pramana/sdk react
```

```tsx
import { PramanaProvider, useIdentity, useCredential, useDelegation } from "@pramana/react";

function App() {
  return (
    <PramanaProvider apiUrl="https://your-pramana.company.com" authToken={token}>
      <AgentDashboard />
    </PramanaProvider>
  );
}

function AgentDashboard() {
  const { identity, generate } = useIdentity();
  const { issue, verify } = useCredential();
  const { delegate, verifyChain } = useDelegation();

  return <button onClick={generate}>Create Agent Identity</button>;
}
```

### Available hooks

| Hook | Description |
|---|---|
| `useIdentity` | Create/restore AgentIdentity, resolve did:key |
| `useCredential` | Issue and verify VCs and Verifiable Presentations |
| `useDelegation` | Issue and verify delegation chains |
| `useTrustScore` | POST /v1/trust/score |
| `useAuditLog` | GET /v1/audit |
| `useMandate` | AP2 intent, cart, and verify |

---

## SPIFFE bridge

Connects infrastructure identity (SPIRE/SPIFFE) to application-layer authority (W3C VCs):

```
SPIFFE SVID (JWT) → POST /v1/identity/attest → W3C WorkloadAttestationCredential
```

```bash
curl -X POST http://localhost:5051/v1/identity/attest \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "svid_jwt": "<SPIRE-issued JWT SVID>",
    "agent_name": "payment-processor",
    "initial_scope": {"allowedOperations": ["payment:read", "payment:write"]}
  }'
```

Returns a `WorkloadAttestationCredential` VC that the workload can use for delegation and commerce flows. Supports RS256, ES256, ES384, and EdDSA algorithm SVIDs.

**Why this matters:** SPIFFE proves *who the workload is* at the infrastructure layer. Pramana proves *what it's authorized to do* at the application layer. The bridge connects them without requiring agents to manage separate key material.

---

## Security model

### What's enforced at the protocol level

| Control | Mechanism |
|---|---|
| **Replay prevention** | JTI deduplication — write-through to DB, warmed from DB on restart |
| **Budget enforcement** | Cumulative `MandateSpend` totals with `SELECT FOR UPDATE` locks |
| **Scope escalation** | Server-side scope narrowing verification — child ⊆ parent enforced |
| **Credential revocation** | W3C Bitstring Status List — instant, privacy-preserving |
| **Audit integrity** | SHA-256 hash chain — any tampering detectable via `/v1/audit/verify` |
| **Race conditions** | `IntegrityError` catch on double-spend — returns 409, never silent pass |
| **Key management** | Private keys encrypted at rest with Fernet; pluggable KMS backend |
| **Multi-tenant isolation** | Every query filtered by `tenant_id` from JWT claims |

### Auth modes

| Mode | When to use |
|---|---|
| `hs256` (default) | Local dev and demo — tokens via `/v1/demo/session` |
| `oidc` | Production — delegate to Keycloak or any OIDC provider |

---

## Self-hosting

### Docker Compose (recommended)

```bash
cp .env.example .env
# Edit .env: set API_SECRET_KEY, AUTH_JWT_SECRET, POSTGRES_PASSWORD
docker compose up -d
curl http://localhost:5051/health
```

### Required environment variables

| Variable | Description |
|---|---|
| `API_SECRET_KEY` | 32+ char secret for Fernet key encryption — **must change** |
| `AUTH_JWT_SECRET` | JWT signing secret for hs256 mode — **must change** |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `PRAMANA_DOMAIN` | Your public domain (URL-encoded), e.g. `api.company.com` |
| `PRAMANA_SCHEME` | `https` in production |
| `ENV` | Set to `production` to enforce PostgreSQL and disable dev shortcuts |
| `AUTH_MODE` | `hs256` (dev) or `oidc` (production) |

Full reference: [`.env.example`](.env.example)

### Hugging Face Spaces

This repo deploys to HF Spaces automatically. Set these Space secrets:
- `API_SECRET_KEY`
- `DEMO_JWT_SECRET`
- `AUTH_JWT_SECRET`

The backend auto-detects the HF environment, enables demo mode, and uses SQLite (no Postgres required on Spaces).

---

## Database migrations

```bash
cd backend
alembic upgrade head       # apply all migrations
alembic current            # check current revision
alembic history            # see all migrations
```

Migrations: `0001_initial` → `0002_tenancy` → `0003_key_rotation` → `0004_audit_hash_chain` → `0005_trust_events` → `0006_webhooks` → `0007_security_hardening` → `0008_spiffe_agent_id`

---

## Tests

```bash
# Backend unit + integration tests
cd backend && pytest tests/ -v

# Python SDK tests
cd sdk/python && pytest tests/ -v

# TypeScript SDK tests
cd sdk/typescript && npm test

# React SDK tests
cd sdk/react && npm test

# Full ecosystem e2e
cd tests/e2e && pytest test_full_ecosystem.py -v
```

---

## Repository structure

```
pramana-protocol/
├── backend/
│   ├── api/routes/          # FastAPI route handlers
│   │   ├── agents.py        # Agent registration + key rotation
│   │   ├── credentials.py   # VC issuance
│   │   ├── verify.py        # VC verification
│   │   ├── revoke.py        # Revocation
│   │   ├── delegations.py   # Delegation chains
│   │   ├── commerce.py      # AP2 mandates + budget enforcement
│   │   ├── spiffe_bridge.py # SPIFFE SVID → VC bridge
│   │   ├── trust.py         # Trust scoring, risk dashboard, anomalies
│   │   ├── compliance.py    # Compliance reports
│   │   ├── marketplace.py   # Agent marketplace
│   │   ├── audit.py         # Audit log
│   │   └── webhooks.py      # Webhook subscriptions
│   ├── core/
│   │   ├── did.py           # DID creation, resolution, SPIFFE parsing
│   │   ├── vc.py            # VC-JOSE/JWT issuance + multi-alg verification
│   │   ├── audit.py         # Hash-chained audit writer
│   │   ├── jti_dedup.py     # Persistent JTI replay prevention
│   │   ├── seed.py          # Realistic synthetic demo data
│   │   ├── trust_score.py   # Trust score computation
│   │   └── settings.py      # Pydantic settings
│   ├── models/              # SQLAlchemy ORM models
│   ├── migrations/          # Alembic migrations (0001–0008)
│   └── tests/               # Unit + integration tests
├── frontend/
│   └── app/demo-dashboard/  # Interactive demo UI
│       ├── page.tsx          # 6-tab dashboard shell
│       ├── scenarios.ts      # Scenario definitions (happy/unhappy/edge)
│       └── components/       # ScenarioRunner, ComplianceTab, RiskDashboardTab, ...
├── sdk/
│   ├── python/pramana/      # Python SDK (pip install pramana-sdk)
│   │   ├── identity.py      # AgentIdentity, DID keypairs
│   │   ├── credentials.py   # issue_vc, verify_vc, VP
│   │   ├── delegation.py    # Delegation chains
│   │   ├── commerce.py      # AP2 mandates
│   │   └── integrations/    # LangChain, MCP, A2A adapters
│   ├── typescript/src/      # TypeScript SDK (npm install @pramana/sdk)
│   └── react/src/           # React hooks (npm install @pramana/react)
├── docs/
│   ├── architecture.md
│   ├── quickstart.md
│   └── guides/              # delegation, commerce, MCP integration, deployment
├── tests/
│   ├── e2e/                 # Full ecosystem tests
│   ├── interop/             # Cross-SDK compatibility tests
│   └── synthetic/           # Synthetic data generation
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Compliance mapping

| Framework | Pramana controls |
|---|---|
| **SOC2** | Logical access (VCs), audit log (hash-chained), revocation, multi-tenant isolation |
| **HIPAA** | Access controls, audit trail, credential-based authorization, key management |
| **EU AI Act** | Transparency (VC-based audit), human oversight hooks, risk-tier classification |
| **ISO 42001** | AI governance controls, delegation chains for human-in-the-loop, incident audit |

Live evidence for all controls: `GET /v1/compliance/report?framework=<name>`

---

## Roadmap

- [ ] KMS backends: AWS KMS, Azure Key Vault, HashiCorp Vault
- [ ] `did:ion` and `did:cheqd` DID method support
- [ ] OpenID4VC / OID4VP wallet protocol
- [ ] SPIRE Workload API direct integration (gRPC)
- [ ] Prometheus metrics + OpenTelemetry tracing (production-grade)
- [ ] PyPI and npm registry publish pipeline

---

## Links

- **Live demo**: https://aurviaglobal-pramana-demo.hf.space/demo-dashboard
- **API docs**: https://aurviaglobal-pramana-demo.hf.space/docs
- **GitHub**: https://github.com/vinaysflow/pramana-protocol
- **HF Space**: https://huggingface.co/spaces/aurviaglobal/pramana-demo
- **Discussions**: https://github.com/vinaysflow/pramana-protocol/discussions

---

## License

MIT — see [LICENSE](LICENSE)
