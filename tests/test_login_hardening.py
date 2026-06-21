# tests/test_login_hardening.py
from pathlib import Path
import pytest
from bastione.enums import IntrusionLevel, Severity
from bastione.models import (AuthConfig, Fingerprint, RunContext, TargetConfig, TestAccount)


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


class _Resp:
    def __init__(self, status_code=401, headers=None, payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._p = payload or {}
    def json(self):
        return self._p


def _acc():
    return TestAccount(label="A", mode="login_post",
                       login_url="https://staging.example.com/api/auth/login",
                       email="a@example.com", password_env="PW_A",
                       session_cookie="session")


def _cfg(cap=5):
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned", ownership_token="tok",
                        auth=AuthConfig(test_accounts=[_acc()], login_attempts_cap=cap))


def _ctx(*, cfg=None, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    cfg = cfg or _cfg()
    return RunContext(target_cfg=cfg, fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=max_intrusion, run_dir=Path("."),
                      ownership_verified=ownership_verified)


def test_module_name_and_intrusion():
    from bastione.modules.login_hardening.module import LoginHardeningModule
    assert LoginHardeningModule.name == "login_hardening"
    assert LoginHardeningModule.max_intrusion == IntrusionLevel.PROBE


def test_read_only_skipped_no_requests(monkeypatch):
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    called = []
    monkeypatch.setattr(m, "_login_request", lambda *a, **k: called.append(a) or None)
    res = LoginHardeningModule().run(_ctx(max_intrusion=IntrusionLevel.READ_ONLY,
                                          ownership_verified=False))
    assert len(res.findings) == 1 and res.findings[0].rule_id == "LOGIN_HARDENING_SKIPPED"
    assert called == []


def test_no_rate_limit_flagged(monkeypatch):
    """cap tentativi a pwd sbagliata senza 429 -> LOGIN_NO_RATE_LIMIT."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    # tutte le risposte 401 (auth fail), mai 429: niente rate-limit
    monkeypatch.setattr(m, "_login_request",
                        lambda url, **k: _Resp(401, headers={"set-cookie": "session=x; HttpOnly; Secure; SameSite=Lax"}))
    res = LoginHardeningModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert "LOGIN_NO_RATE_LIMIT" in rids
    assert next(f for f in res.findings if f.rule_id == "LOGIN_NO_RATE_LIMIT").severity == Severity.HIGH
    # P8: la password reale non compare
    for f in res.findings:
        assert "realpw" not in f.evidence and "realpw" not in f.description


def test_rate_limit_present_no_finding(monkeypatch):
    """un 429 entro il cap -> niente LOGIN_NO_RATE_LIMIT, posture pass."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    seq = [_Resp(401), _Resp(401), _Resp(429)]
    calls = {"n": 0}
    def router(url, **k):
        i = min(calls["n"], len(seq) - 1); calls["n"] += 1
        return seq[i]
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "LOGIN_NO_RATE_LIMIT" not in {f.rule_id for f in res.findings}
    assert any(p.check_id == "POSTURE_RATE_LIMIT" and p.passed for p in res.posture_checks)


def test_user_enumeration_flagged(monkeypatch):
    """status distinguibile email-esistente vs inesistente -> LOGIN_USER_ENUMERATION."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    def router(url, *, json=None, headers=None):
        # esistente -> 401, inesistente -> 404 (distinguibile)
        if json and json.get("email") == "a@example.com":
            return _Resp(401)
        return _Resp(404)
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "LOGIN_USER_ENUMERATION" in {f.rule_id for f in res.findings}


def test_insecure_session_cookie_flagged(monkeypatch):
    """Set-Cookie senza HttpOnly/Secure -> SESSION_COOKIE_INSECURE."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    def router(url, *, json=None, headers=None):
        pw = (json or {}).get("password")
        # login con pwd reale -> 200 + cookie insicuro; pwd sbagliata -> 401
        if pw == "realpw":
            return _Resp(200, headers={"set-cookie": "session=abc; Path=/"})
        return _Resp(401)
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "SESSION_COOKIE_INSECURE" in {f.rule_id for f in res.findings}


def test_enumeration_skips_when_no_email(monkeypatch):
    """Account login_post con login_url ma SENZA email (config valida: email è
    str | None): _enumeration deve saltare senza sollevare (AttributeError su
    None.split), e run() deve comunque produrre i finding di rate_limit/cookie
    già raccolti (§4.7/§28 'modulo mai crash')."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    # account login_post valido ma senza email (e senza password_env: niente cookie)
    acc = TestAccount(label="A", mode="login_post",
                      login_url="https://staging.example.com/api/auth/login",
                      session_cookie="session")
    cfg = TargetConfig(name="t", base_url="https://staging.example.com",
                       environment="staging", ownership="owned", ownership_token="tok",
                       auth=AuthConfig(test_accounts=[acc], login_attempts_cap=5))
    seen_emails = []
    def router(url, *, json=None, headers=None):
        seen_emails.append((json or {}).get("email"))
        # mai 429 -> niente rate-limit, ma nessun crash
        return _Resp(401, headers={"set-cookie": "session=x; Path=/"})
    monkeypatch.setattr(m, "_login_request", router)
    # non deve sollevare AttributeError
    res = LoginHardeningModule().run(_ctx(cfg=cfg))
    rids = {f.rule_id for f in res.findings}
    # i finding di rate_limit sopravvivono (l'oracolo enumeration è saltato)
    assert "LOGIN_NO_RATE_LIMIT" in rids
    # nessun finding di enumerazione (oracolo saltato per email mancante)
    assert "LOGIN_USER_ENUMERATION" not in rids
    # _enumeration non ha emesso richieste con email "nonexistent-bastione-probe@..."
    assert not any(e and "nonexistent-bastione-probe" in e for e in seen_emails)
    # posture di rate_limit presente (modulo non degradato a MODULE_ERROR)
    assert any(p.check_id == "POSTURE_RATE_LIMIT" for p in res.posture_checks)
