#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../backend"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-test.txt

pytest -q --cov=. --cov-report=html:../tests/reports/htmlcov --html=../tests/reports/pytest-report.html --self-contained-html

echo "OK: reports written to tests/reports/"
