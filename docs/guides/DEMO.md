## Demo

### Hugging Face / demo mode (recommended)

1) Open `/demo`
2) Click **Run Drift Demo**
3) Copy VC JWT and verify results
4) Click **Reset my demo** to clear your tenant data

### Local dev (OIDC)

```bash
cd /Users/vinaytripathi/Documents/pramana-protocol
make dev
```

- Use `http://127.0.0.1:6080/login` for Keycloak login.
- Or run the single-call API demo:

```bash
API_BASE=http://127.0.0.1:5051 ./scripts/demo_oidc.sh
```
