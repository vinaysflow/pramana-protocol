---
title: Pramana Demo
sdk: docker
pinned: false
---

## Pramana Protocol

Portable AI agent identity using W3C DIDs + VCs with instant revocation.

### Links
- Live demo: https://aurviaglobal-pramana-demo.hf.space/demo
- One‑API docs: docs/guides/REQUIREMENT_INTENTS.md
- Feedback (HF): https://huggingface.co/spaces/aurviaglobal/pramana-demo/discussions
- Feedback (GitHub): https://github.com/vinaysflow/pramana-protocol/discussions

### HF reviewer quickstart (60 seconds)
- Open `/demo`
- Click **Run Drift Demo**
- Confirm `verify_before.verified=true` and `verify_after.reason=revoked`
- For feedback: https://huggingface.co/spaces/aurviaglobal/pramana-demo/discussions

### One-API (Stripe-like) developer quickstart
See `docs/guides/REQUIREMENT_INTENTS.md` for the `RequirementIntent` flow (create → confirm → retrieve) that returns a **decision** and optional **proof bundle**.
Start here: docs/guides/REQUIREMENT_INTENTS.md

### What’s implemented
- did:web issuer creation + DID document hosting (Ed25519)
- VC issuance (VC-JOSE/JWT, EdDSA)
- Verification with revocation enforcement via **signed** Bitstring Status List VC-JWT
- Multi-tenant isolation (tenant derived from auth context)
- Key rotation for issuer agents (multi-key DID docs, active `kid` for signing)
- Single-call workflow API: `POST /v1/workflows/drift-demo`
- Portable verifier CLI (HTTP-only; no DB)
- Audit trail (tenant-scoped)
- Guided demo UI at `/demo`

### Before first run

Copy `.env.example` to `.env` and set **`API_SECRET_KEY`** to a strong, unique value (min 32 chars). For Hugging Face Spaces, also set **`DEMO_JWT_SECRET`** in your Space secrets. Never commit real secrets to the repository.

---

## Local dev (Keycloak OIDC)

```bash
# from the repo root after cloning
make dev
```

- UI: `http://127.0.0.1:6080`
- API health: `http://127.0.0.1:5051/health`
- API ready: `http://127.0.0.1:5051/ready`
- Keycloak: `http://127.0.0.1:8080` (realm `pramana`)

Login (local): `http://127.0.0.1:6080/login`

---

## Hugging Face Spaces (Docker) — best-in-class demo mode

Spaces runs in **demo-session mode**:
- no Keycloak dependency
- each visitor gets an **isolated demo tenant**
- one-click guided demo

### Required Secrets (Spaces)
- `DEMO_JWT_SECRET` (required)

### Evaluator flow
- Open `/demo`
- Click **Run Drift Demo**
- Copy VC JWT and results
- Optionally click **Reset my demo**

### Local Spaces preflight

```bash
docker build -t pramana-spaces .
docker run --rm -p 7860:7860 -e PORT=7860 -e DEMO_JWT_SECRET=dev-demo-secret -v $(pwd)/.data:/data pramana-spaces
```

Then open `http://127.0.0.1:7860/demo`.

---

## Portable verifier (no DB)

```bash
cd backend
. .venv/bin/activate
python tools/verifier_cli.py --jwt "<VC_JWT>"
```
