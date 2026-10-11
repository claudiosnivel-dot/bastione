from pathlib import Path
from types import SimpleNamespace
import bastione.modules.supabase.auth_posture as ap
from bastione.enums import IntrusionLevel, Severity
from bastione.models import RunContext, TargetConfig, Fingerprint, AuthExpectation

SUPA = "https://abcdefghijklmnopqrst.supabase.co"

def _cfg(**kw):
    return TargetConfig(name="t", base_url="https://staging.example", environment="staging",
                        ownership="owned", supabase_url=SUPA, **kw)

def _ctx(*, cfg=None):
    return RunContext(target_cfg=cfg or _cfg(), fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=IntrusionLevel.READ_ONLY, run_dir=Path("."), ownership_verified=False)

def _settings(**fields):
    return SimpleNamespace(status_code=200, json=lambda: fields)

def test_signup_open_violates_expectation(monkeypatch):
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=False))
    cfg = _cfg(expect_auth=AuthExpectation(signup_open=False))
    f, _ = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, "t")
    assert [x.rule_id for x in f] == ["SIGNUP_OPEN"] and f[0].severity == Severity.MEDIUM

def test_signup_open_expected_is_posture_pass(monkeypatch):
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=False))
    cfg = _cfg(expect_auth=AuthExpectation(signup_open=True))
    f, p = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, "t")
    assert not [x for x in f if x.rule_id == "SIGNUP_OPEN"]
    assert any(pc.check_id == "POSTURE_AUTH_AS_DECLARED" and pc.passed for pc in p)

def test_signup_open_undeclared_is_info(monkeypatch):   # R7
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=False))
    f, _ = ap.run_auth_posture_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert any(x.rule_id == "AUTH_EXPECTATION_UNDECLARED" and x.severity == Severity.INFO for x in f)

def test_autoconfirm_is_medium_always(monkeypatch):
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=True, mailer_autoconfirm=True))
    f, _ = ap.run_auth_posture_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert any(x.rule_id == "SIGNUP_NO_EMAIL_CONFIRM" and x.severity == Severity.MEDIUM for x in f)

def test_anon_signin_violation(monkeypatch):
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=True, external={"anonymous_users": True, "email": True}))
    cfg = _cfg(expect_auth=AuthExpectation(anonymous_signin=False))
    f, _ = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, "t")
    assert any(x.rule_id == "ANON_SIGNIN_ENABLED" for x in f)

def test_settings_unreadable_is_info(monkeypatch):      # R6
    monkeypatch.setattr(ap, "_get", lambda u,h: None)
    f, _ = ap.run_auth_posture_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert f and f[0].rule_id == "AUTH_SETTINGS_NOT_READABLE" and f[0].severity == Severity.INFO


def test_anon_signin_violation_lowers_as_declared(monkeypatch):
    """Forma reale di GoTrue: il flag sta in `external.anonymous_users`. Con attesa
    anonymous_signin=false violata, la posture NON può risultare conforme."""
    monkeypatch.setattr(ap, "_get", lambda u, h: _settings(
        disable_signup=True, external={"anonymous_users": True}))
    cfg = _cfg(expect_auth=AuthExpectation(anonymous_signin=False))
    _, p = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey": "k"}, "t")
    pc = next(x for x in p if x.check_id == "POSTURE_AUTH_AS_DECLARED")
    assert pc.passed is False


def test_anon_signin_off_no_finding(monkeypatch):
    monkeypatch.setattr(ap, "_get", lambda u, h: _settings(
        disable_signup=True, external={"anonymous_users": False}))
    cfg = _cfg(expect_auth=AuthExpectation(anonymous_signin=False))
    f, p = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey": "k"}, "t")
    assert not [x for x in f if x.rule_id == "ANON_SIGNIN_ENABLED"]
    assert next(x for x in p if x.check_id == "POSTURE_AUTH_AS_DECLARED").passed


def test_two_undeclared_have_distinct_finding_ids(monkeypatch):
    """Signup aperto E sign-in anonimo attivo, nessuna attesa: due INFO con
    finding_id DISTINTI (il dedup 'primo vince' non deve scartarne uno, R6)."""
    monkeypatch.setattr(ap, "_get", lambda u, h: _settings(
        disable_signup=False, external={"anonymous_users": True}))
    f, _ = ap.run_auth_posture_checks(_ctx(), SUPA, {"apikey": "k"}, "t")
    und = [x for x in f if x.rule_id == "AUTH_EXPECTATION_UNDECLARED"]
    assert len(und) == 2 and und[0].finding_id != und[1].finding_id
