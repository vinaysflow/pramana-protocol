import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def test_demo_session_token_can_run_workflow_and_reset(tmp_path):
    orig_env = os.environ.copy()
    orig_modules = sys.modules.copy()
    orig_sys_path = list(sys.path)

    try:
        db_file = tmp_path / 'demo.db'
        os.environ['DATABASE_URL'] = f"sqlite:///{db_file}"

        os.environ['DEMO_MODE'] = 'true'
        os.environ['DEMO_JWT_SECRET'] = 'demo-test-secret'
        os.environ['DEMO_TOKEN_TTL_SECONDS'] = '3600'

        os.environ['AUTH_MODE'] = 'oidc'
        os.environ['OIDC_ISSUER'] = ''
        os.environ['OIDC_AUDIENCE'] = ''

        for name in list(sys.modules.keys()):
            if name == 'main' or name.startswith('core.') or name == 'core' or name.startswith('models.') or name == 'models' or name.startswith('api.') or name == 'api':
                del sys.modules[name]

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

        import main  # noqa

        with TestClient(main.app) as c:
            sess = c.post('/v1/demo/session', json={})
            assert sess.status_code == 200
            data = sess.json()

            token = data['token']
            tenant_id = data['tenant_id']

            r = c.post('/v1/workflows/drift-demo', headers={'Authorization': f'Bearer {token}'}, json={})
            assert r.status_code == 200

            # reset
            rr = c.post('/v1/demo/reset', headers={'Authorization': f'Bearer {token}'}, json={})
            assert rr.status_code == 200
            assert rr.json().get('reset') is True

            # audit should be empty after reset (tenant-scoped)
            ar = c.get('/v1/audit?limit=50', headers={'Authorization': f'Bearer {token}'})
            # demo token includes tenant:admin
            assert ar.status_code == 200
            assert ar.json().get('events') == []

            # run again after reset
            r2 = c.post('/v1/workflows/drift-demo', headers={'Authorization': f'Bearer {token}'}, json={})
            assert r2.status_code == 200
            out = r2.json()
            assert out['tenant_id'] == tenant_id

    finally:
        os.environ.clear()
        os.environ.update(orig_env)
        sys.modules.clear()
        sys.modules.update(orig_modules)
        sys.path[:] = orig_sys_path
