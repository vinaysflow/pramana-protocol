# Pramana Protocol

**Portable AI Agent Identity Infrastructure**

W3C DIDs + Verifiable Credentials · Scoped Authorization · Instant Revocation

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 81%](https://img.shields.io/badge/python-81%25-blue)](https://github.com/vinaysflow/pramana-protocol)
[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://aurviaglobal-pramana-demo.hf.space/demo)

-----

## The Problem

AI agents are being deployed across enterprise boundaries — negotiating contracts, processing claims, coordinating supply chains. But when Agent A from Company X needs to act inside Company Y’s systems, there’s no standardized way to answer three questions:

1. **Who authorized this agent?** (Identity)
1. **What is it allowed to do?** (Scoped permissions)
1. **Can we revoke access instantly if something goes wrong?** (Revocation)

Today’s solutions are proprietary and siloed. Microsoft Entra Agent ID works inside Microsoft’s ecosystem. AWS AgentCore Identity works inside AWS. Neither solves the cross-organizational case — and that’s where the real coordination happens.

**The market signal:** Machine identities outnumber humans 17:1 to 100:1. The AI agent market is projected at $52.6B by 2030 (46% CAGR). NIST’s NCCoE published a concept paper on AI identity in February 2026. This isn’t a future problem — it’s an infrastructure gap that’s widening right now.

## The Hypothesis

Cross-organizational agent authorization is the defensible whitespace that proprietary platforms structurally cannot solve. An open protocol built on W3C standards (DIDs + Verifiable Credentials) can become the trust layer between enterprise policy engines and autonomous agent execution — the way Let’s Encrypt became the trust layer for HTTPS.

**The core architectural insight:** Authorization credentials must be *portable* (travel with the agent), *scoped* (monotonically decreasing authority through delegation chains), and *instantly revocable* (without requiring the verifier to call home to the issuer).

## What Pramana Does

Pramana is an intent-scoped authorization adapter. It sits between enterprise policy engines (OPA, AWS Cedar) and autonomous agent execution, issuing verifiable, portable credentials that agents carry across trust boundaries.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Enterprise  │────▶│     Pramana       │────▶│   Agent Runtime  │
│ Policy Engine│     │  VC-JWT Issuance  │     │  (carries creds) │
│ (OPA/Cedar)  │◀────│  Scope Narrowing  │     │                  │
└─────────────┘     │  Revocation Check │     └─────────────────┘
                    └──────────────────┘
                           │
                    ┌──────▼──────┐
                    │  Verifier   │
                    │ (stateless, │
                    │  portable)  │
                    └─────────────┘
```

### Key Capabilities

- **DID-based issuer identity** — `did:web` with Ed25519 key pairs. Each agent/issuer gets a resolvable DID document
- **VC-JWT credential issuance** — W3C Verifiable Credentials in JWT format (VC-JOSE/JWT, EdDSA signatures). Scoped to specific intents and operations
- **Delegation chains with scope intersection** — Authority narrows monotonically. A delegator cannot grant more permission than they hold. Enforced server-side, not just at issuance
- **Instant revocation** — Signed Bitstring Status List (VC-JWT). Verifiers check revocation without calling the issuer’s database. Privacy-preserving: the status list reveals nothing about credential contents
- **Multi-tenant isolation** — Tenant derived from auth context. Complete data separation between organizations
- **Key rotation** — Multi-key DID documents with active `kid` for signing. Old keys remain for verification; new keys handle issuance
- **Stateless portable verifier** — HTTP-only CLI that verifies credentials without database access. Any party can verify without trusting the issuer’s infrastructure
- **Hash-chained audit trail** — SHA-256 linked audit log. Tenant-scoped. Tamper-evident by construction

## Architecture Decisions (and Why)

|Decision            |Choice                             |Why                                                                                                                                         |
|--------------------|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
|Credential format   |VC-JWT over VC-LD                  |JWT is universally parseable. JSON-LD requires context resolution and is brittle in production. Every enterprise system already handles JWTs|
|Signature algorithm |Ed25519 over RSA                   |Faster signing/verification, smaller keys (32 bytes vs 256+), constant-time operations reduce timing side-channels                          |
|Revocation mechanism|Bitstring Status List over CRL/OCSP|Privacy-preserving (credential index reveals nothing), no real-time issuer dependency, compact (one bit per credential)                     |
|DID method          |`did:web` initially                |Lowest adoption barrier — resolves via HTTPS. Bridge to `did:key` for offline/ephemeral agents                                              |
|Scope enforcement   |Server-side intersection           |Delegation chains are security-critical. Client-side enforcement is a vulnerability, not a feature                                          |
|Policy integration  |Adapter pattern (OPA/Cedar)        |Enterprises already have policy engines. Pramana doesn’t replace them — it translates their decisions into portable credentials             |

## What I’d Measure

If this were deployed at enterprise scale, these are the metrics that matter:

|Metric                                   |Why It Matters                                                                                      |
|-----------------------------------------|----------------------------------------------------------------------------------------------------|
|**Credential issuance latency (p50/p99)**|Must be under 100ms to not block agent workflows. Ed25519 helps here                                |
|**Verification latency (stateless)**     |The portable verifier must be fast enough for inline authorization checks                           |
|**Revocation propagation time**          |Time between revocation action and all verifiers recognizing it. Target: under 60 seconds           |
|**Delegation chain depth distribution**  |How deep are real-world chains? Informs performance optimization and security analysis              |
|**Cross-org credential acceptance rate** |What % of issued credentials are successfully verified by external parties? The core adoption metric|
|**False revocation rate**                |Bitstring index collisions or stale caches causing valid credentials to be rejected                 |

## What I Learned

**1. The real product isn’t the crypto — it’s the developer experience.** Ed25519 signatures and VC-JWT encoding are table stakes. The differentiator is whether a developer can integrate Pramana in an afternoon. The `RequirementIntent` API (create, confirm, retrieve — Stripe-like) exists because of this insight.

**2. Cross-org trust is a chicken-and-egg problem.** No one adopts a trust protocol without a second party to trust. The protocol adoption motion (open-source, standards-based) is a distribution strategy, not a philosophy choice. Let’s Encrypt succeeded because browsers already understood X.509 — Pramana succeeds if verifiers already understand VC-JWT.

**3. Single-tenant is where you build; multi-tenant is where you learn.** The multi-tenant isolation architecture revealed assumptions about key management, audit trail separation, and credential namespace collisions that didn’t surface in single-tenant testing.

**4. Revocation is the hardest UX problem, not the hardest crypto problem.** Bitstring Status List is elegant cryptography. But the product question — “who can revoke, under what conditions, with what notification?” — requires policy design that no standard addresses.

## Project Status

|Component                |Status |Detail                                                    |
|-------------------------|-------|----------------------------------------------------------|
|DID creation + resolution|Shipped|`did:web`, Ed25519, multi-key DID docs                    |
|VC-JWT issuance          |Shipped|EdDSA, scoped credentials, multicodec encoding            |
|Verification + revocation|Shipped|Signed Bitstring Status List VC-JWT                       |
|Delegation chains        |Shipped|Scope intersection with monotonically decreasing authority|
|Multi-tenant isolation   |Shipped|Auth-context-derived tenancy                              |
|Key rotation             |Shipped|Multi-key DID docs, active `kid` tracking                 |
|Portable verifier        |Shipped|HTTP-only CLI, no DB dependency                           |
|Audit trail              |Shipped|SHA-256 hash-chained, tenant-scoped                       |
|Workflow API             |Shipped|Stripe-like RequirementIntent flow                        |
|Human-agent binding      |Next   |Pending design partner for KYC integration                |
|Cross-org federation     |Planned|Deferred until second real tenant exists                  |
|Agent liveness proofs    |Planned|Uniquely differentiating; fully self-contained build      |

**Codebase:** ~10,700 lines Python backend · 33+ passing tests · 29 commits · CI via GitHub Actions

**Live demo:** [aurviaglobal-pramana-demo.hf.space/demo](https://aurviaglobal-pramana-demo.hf.space/demo)

-----

## Quick Start

### Live Demo (60 seconds)

1. Open [the demo](https://aurviaglobal-pramana-demo.hf.space/demo)
1. Click **Run Drift Demo**
1. Confirm `verify_before.verified=true` and `verify_after.reason=revoked`

### Developer Quickstart (RequirementIntent API)

See [`docs/guides/REQUIREMENT_INTENTS.md`](docs/guides/REQUIREMENT_INTENTS.md) for the Stripe-like flow:

```
POST /v1/intents              → Create intent
POST /v1/intents/:id/confirm  → Confirm with proof
GET  /v1/intents/:id          → Retrieve decision + proof bundle
```

### Local Development

```bash
# Clone and start (requires Docker)
git clone https://github.com/vinaysflow/pramana-protocol.git
cd pramana-protocol
cp .env.example .env  # Set API_SECRET_KEY (min 32 chars)
make dev
```

- **UI:** http://127.0.0.1:6080
- **API:** http://127.0.0.1:5051/health
- **Keycloak (OIDC):** http://127.0.0.1:8080 (realm: `pramana`)

### Portable Verifier (No DB Required)

```bash
cd backend && . .venv/bin/activate
python tools/verifier_cli.py --jwt "<VC_JWT>"
```

### Run Tests

```bash
pytest tests/ -v
```

-----

## Repository Structure

```
pramana-protocol/
├── backend/          # FastAPI backend (~10,700 lines Python)
│   ├── core/         # DID, VC, crypto, delegation, revocation
│   ├── api/          # REST endpoints, auth, middleware
│   └── models/       # Data models, tenant isolation
├── frontend/         # Demo UI (TypeScript)
├── sdk/              # Python SDK for integrators
├── tests/            # 33+ tests across identity, VC, delegation
├── scripts/          # Dev tooling, key generation
├── infra/keycloak/   # OIDC provider config
├── docs/guides/      # API guides, RequirementIntent flow
├── Dockerfile        # HF Spaces / production container
└── docker-compose.yml # Local dev stack
```

## Related

- **[The Trust Stack](https://vintrip.substack.com)** — Substack series on AI governance and agent identity infrastructure
- **[Trust Gap Assessment](https://trust-gap-assessment.vercel.app)** — Interactive diagnostic for enterprise AI trust gaps

## License

[MIT](LICENSE)

-----

Built by [Vinay Tripathi](https://github.com/vinaysflow) · [The Trust Stack](https://vintrip.substack.com) · vinay@aurviaglobal.com