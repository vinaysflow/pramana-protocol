import re
import secrets
from pathlib import Path

p = Path(__file__).resolve().parent.parent / ".env"
if not p.exists():
    raise SystemExit(".env not found; copy .env.example to .env first")

s = p.read_text()
key = secrets.token_urlsafe(32)
if re.search(r"^API_SECRET_KEY=.*$", s, flags=re.M):
    s = re.sub(r"^API_SECRET_KEY=.*$", f"API_SECRET_KEY={key}", s, flags=re.M)
else:
    s += f"\nAPI_SECRET_KEY={key}\n"

p.write_text(s)
print("Set API_SECRET_KEY in .env")
