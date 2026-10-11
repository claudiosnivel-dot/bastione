# tests/test_server_exposure.py
from pathlib import Path
import pytest
from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, RunContext, TargetConfig


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


class _Resp:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _cfg():
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned", ownership_token="tok")


def _ctx(*, resolved_urls=None, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    fp = Fingerprint(target="t", resolved_urls=resolved_urls or ["https://staging.example.com"])
    return RunContext(target_cfg=_cfg(), fingerprint=fp, max_intrusion=max_intrusion,
                      run_dir=Path("."), ownership_verified=ownership_verified)


def test_module_name_and_intrusion():
    from bastione.modules.server_exposure.module import ServerExposureModule
    assert ServerExposureModule.name == "server_exposure"
    assert ServerExposureModule.max_intrusion == IntrusionLevel.PROBE


def test_read_only_skipped_no_requests(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    called = []
    monkeypatch.setattr(m, "_fetch", lambda *a, **k: called.append(a) or None)
    res = ServerExposureModule().run(_ctx(max_intrusion=IntrusionLevel.READ_ONLY,
                                          ownership_verified=False))
    assert len(res.findings) == 1 and res.findings[0].rule_id == "SERVER_EXPOSURE_SKIPPED"
    assert called == []


def test_sourcemap_with_service_role_is_critical(monkeypatch):
    """Una .js.map esposta che contiene una service_role -> SOURCEMAP_EXPOSED CRITICAL, P8 redatto."""
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    # un JWT service_role (header.payload.signature) con payload {"role":"service_role"}
    import base64, json as _j
    payload = base64.urlsafe_b64encode(_j.dumps({"role": "service_role", "ref": "abc"}).encode()).decode().rstrip("=")
    jwt = f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"
    base_html = '<script src="/assets/app.js"></script>'
    def fetch(method, url, *, headers=None):
        if url.endswith("/"):  # base page
            return _Resp(200, text=base_html)
        if url.endswith("app.js.map"):
            return _Resp(200, text=f'{{"sources":["x"],"key":"{jwt}"}}')
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    sm = [f for f in res.findings if f.rule_id == "SOURCEMAP_EXPOSED"]
    assert sm and sm[0].severity == Severity.CRITICAL
    # P8: il JWT in chiaro non compare nell'evidence
    assert jwt not in sm[0].evidence


def test_cors_misconfig_reflected_with_credentials(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    def fetch(method, url, *, headers=None):
        if url.rstrip("/").endswith("staging.example.com") or url.endswith("/"):
            org = (headers or {}).get("Origin", "")
            return _Resp(200, headers={"access-control-allow-origin": org,
                                       "access-control-allow-credentials": "true"})
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    assert "CORS_MISCONFIG" in {f.rule_id for f in res.findings}


def test_sensitive_endpoint_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, headers={"content-type": "text/plain"},
                         text="DB_PASSWORD=supersecret\nAPI_KEY=xyz")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    se = [f for f in res.findings if f.rule_id == "SENSITIVE_ENDPOINT_EXPOSED"]
    assert se and se[0].severity == Severity.HIGH
    # P8: il valore del segreto non finisce nell'evidence (solo il path)
    assert "supersecret" not in se[0].evidence


def test_hardened_app_no_findings(monkeypatch):
    """App hardened: tutto 404/sicuro -> nessun finding di esposizione (solo eventuali posture)."""
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    monkeypatch.setattr(m, "_fetch", lambda method, url, *, headers=None: _Resp(404))
    res = ServerExposureModule().run(_ctx())
    bad = {"SOURCEMAP_EXPOSED", "SENSITIVE_ENDPOINT_EXPOSED", "CORS_MISCONFIG", "VERBOSE_ERROR_LEAK"}
    assert not (bad & {f.rule_id for f in res.findings})


# ─── M5 Task 22 (§4.5): path estesi, DEV_SERVER/API_SPEC, body → detector L2 ───

def test_env_body_forwarded_to_detectors(monkeypatch):
    import bastione.modules.server_exposure.module as m
    import bastione.modules.secrets.detectors.stripe  # noqa: F401 — registra SECRET_STRIPE
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, {"content-type": "text/plain"}, text="STRIPE=sk_live_ABCdef0123456789XYZ")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert "SENSITIVE_ENDPOINT_EXPOSED" in rids and "SECRET_STRIPE" in rids
    secret = next(f for f in res.findings if f.rule_id == "SECRET_STRIPE")
    assert secret.severity == Severity.CRITICAL          # severity_override del match live
    assert secret.module == "server_exposure"
    for field in (secret.evidence, secret.title, secret.description):   # P8 redatto
        assert "sk_live_ABCdef0123456789XYZ" not in field


def test_env_body_same_secret_twice_is_one_finding(monkeypatch):
    """Due match dello stesso detector nello stesso file → un solo finding (stesso finding_id)."""
    import bastione.modules.server_exposure.module as m
    import bastione.modules.secrets.detectors.stripe  # noqa: F401
    body = "A=sk_live_ABCdef0123456789XYZ\nB=sk_live_ZZZdef0123456789XYZ"
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, {"content-type": "text/plain"}, text=body)
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    stripe = [f for f in res.findings if f.rule_id == "SECRET_STRIPE"]
    assert len(stripe) == 1


def test_env_variants_and_git_metadata_probed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    seen = []
    def fetch(method, url, *, headers=None):
        seen.append(url)
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    m.ServerExposureModule().run(_ctx())
    for path in ("/.env.local", "/.env.production", "/.git/HEAD"):
        assert "https://staging.example.com" + path in seen
    # owned-only: nessuna richiesta fuori dall'host del target
    assert all(u.startswith("https://staging.example.com") for u in seen)


def test_dev_server_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    def fetch(method, url, *, headers=None):
        if url.endswith("/@vite/client"):
            return _Resp(200, {"content-type": "application/javascript"}, text="export const x=1")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    dev = [f for f in res.findings if f.rule_id == "DEV_SERVER_EXPOSED"]
    assert len(dev) == 1 and dev[0].severity == Severity.HIGH


def test_spa_fallback_is_not_dev_server_or_api_spec(monkeypatch):
    """SPA con fallback: ogni path risponde 200 text/html → nessun DEV_SERVER/API_SPEC."""
    import bastione.modules.server_exposure.module as m
    monkeypatch.setattr(m, "_fetch", lambda method, url, *, headers=None:
                        _Resp(200, {"content-type": "text/html; charset=utf-8"}, text="<html></html>"))
    res = m.ServerExposureModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert not ({"DEV_SERVER_EXPOSED", "API_SPEC_EXPOSED", "SENSITIVE_ENDPOINT_EXPOSED"} & rids)


def test_api_spec_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    def fetch(method, url, *, headers=None):
        if url.endswith("/openapi.json"):
            return _Resp(200, {"content-type": "application/json"}, text='{"openapi":"3.0"}')
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    spec = [f for f in res.findings if f.rule_id == "API_SPEC_EXPOSED"]
    assert len(spec) == 1 and spec[0].severity == Severity.LOW


def test_body_detector_crash_does_not_break_module(monkeypatch):
    """Resilienza §4.7: un detector che solleva sul body non ferma il modulo."""
    import bastione.modules.server_exposure.module as m
    class _Boom:
        detector_id = "SECRET_BOOM"
        def scan(self, asset):
            raise RuntimeError("boom")
    monkeypatch.setattr(m, "DETECTORS", [_Boom()])
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, {"content-type": "text/plain"}, text="X=1")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    assert "SENSITIVE_ENDPOINT_EXPOSED" in {f.rule_id for f in res.findings}
