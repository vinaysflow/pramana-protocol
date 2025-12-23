## Test harness (project root)

This folder provides repeatable commands for running the Pramana test suites.

### Local (venv) backend tests

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt
pytest
```

### Docker (compose) backend tests

```bash
cd /Users/vinaytripathi/Documents/pramana-protocol
# Ensure stack is up
docker-compose up -d
# Run tests inside backend container
docker-compose exec backend pytest -q
```

### Reports
- HTML coverage (local): `backend/htmlcov/`
- HTML pytest report (local): `tests/reports/`
