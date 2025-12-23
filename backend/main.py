from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.middleware.limits import MaxBodySizeMiddleware
from api.middleware.rate_limit import SimpleRateLimitMiddleware

from api.routes.agents import router as agents_router
from api.routes.audit import router as audit_router
from api.routes.auth import router as auth_router
from api.routes.workflows import router as workflows_router
from api.routes.keys import router as keys_router
from api.routes.demo import router as demo_router
from api.routes.credentials import router as credentials_router
from api.routes.dids import router as dids_router
from api.routes.revoke import router as revoke_router
from api.routes.status import router as status_router
from api.routes.verify import router as verify_router
from api.routes.static_ui import mount_ui
from core.settings import settings
from core.startup import init_db

app = FastAPI(
    title="Pramana Protocol API",
    description="Portable AI Agent Identity using W3C Standards",
    version="0.1.0",
)

if settings.cors_enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_body_bytes)
if settings.rate_limit_enabled:
    app.add_middleware(SimpleRateLimitMiddleware, max_requests=settings.rate_limit_per_minute, window_seconds=60)

app.include_router(agents_router)
app.include_router(dids_router)
app.include_router(credentials_router)
app.include_router(status_router)
app.include_router(verify_router)
app.include_router(revoke_router)
app.include_router(audit_router)
app.include_router(auth_router)
app.include_router(workflows_router)
app.include_router(keys_router)
app.include_router(demo_router)


@app.on_event("startup")
async def _startup():
    init_db()


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/ready")
async def ready():
    try:
        from core.db import engine
        from sqlalchemy import text as _text

        with engine.connect() as conn:
            conn.execute(_text("SELECT 1"))

            # migrations applied?
            try:
                conn.execute(_text("SELECT version_num FROM alembic_version"))
            except Exception:
                return {"ready": False, "error": "missing alembic_version (migrations not applied?)"}

            # writable?
            try:
                # works on sqlite and postgres
                conn.execute(_text("CREATE TABLE IF NOT EXISTS _pramana_readycheck (id INTEGER PRIMARY KEY)"))
                conn.execute(_text("INSERT INTO _pramana_readycheck(id) VALUES (1)"))
                conn.execute(_text("DELETE FROM _pramana_readycheck WHERE id=1"))
            except Exception as e:
                return {"ready": False, "error": f"db not writable: {e}"}

        return {"ready": True}
    except Exception as e:
        return {"ready": False, "error": str(e)}


@app.get("/api")
async def api_root():
    return {
        "name": "Pramana Protocol",
        "version": "0.1.0",
        "description": "Portable AI Agent Identity",
        "standards": [
            "W3C DID Core 1.0",
            "W3C VC 2.0",
            "VC-JOSE",
            "Bitstring Status List",
        ],
    }


# Mount UI last so API routes take precedence.
mount_ui(app)
