from pathlib import Path
from types import SimpleNamespace
import pytest
import bastione.modules.supabase.storage as st
from bastione.enums import IntrusionLevel, Severity
from bastione.models import (RunContext, TargetConfig, Fingerprint, BucketExpectation)

SUPA = "https://abcdefghijklmnopqrst.supabase.co"

def _cfg(**kw):
    return TargetConfig(name="t", base_url="https://staging.example", environment="staging",
                        ownership="owned", supabase_url=SUPA, **kw)

def _ctx(*, cfg=None, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    return RunContext(target_cfg=cfg or _cfg(), fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=max_intrusion, run_dir=Path("."), ownership_verified=ownership_verified)

def _resp(status, payload):
    def _j():
        if payload is None: raise ValueError("no json")
        return payload
    return SimpleNamespace(status_code=status, json=_j)

def test_listable_not_expected_is_finding(monkeypatch):
    monkeypatch.setattr(st, "_post", lambda u,h,j: _resp(200, [{"name":"a.png"},{"name":"b.png"}]))
    cfg = _cfg(expect_buckets=[BucketExpectation(name="avatars", anon_list=False)])
    f, p = st.run_storage_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, ["avatars"], "t")
    assert [x.rule_id for x in f] == ["STORAGE_PUBLIC_LISTABLE"]
    assert f[0].severity == Severity.HIGH          # nomi non personali → HIGH
    assert "a.png" not in f[0].evidence and "b.png" not in f[0].evidence   # P8
    assert any(pc.check_id == "POSTURE_STORAGE_PRIVATE_avatars" and not pc.passed for pc in p)

def test_listable_personal_names_is_critical(monkeypatch):
    monkeypatch.setattr(st, "_post", lambda u,h,j: _resp(200, [{"name":"mario_codice_fiscale.pdf"}]))
    cfg = _cfg(expect_buckets=[BucketExpectation(name="docs", anon_list=False)])
    f, _ = st.run_storage_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, ["docs"], "t")
    assert f[0].severity == Severity.CRITICAL and f[0].gdpr_relevant is True

def test_expected_public_is_posture_pass(monkeypatch):
    monkeypatch.setattr(st, "_post", lambda u,h,j: _resp(200, [{"name":"x"}]))
    cfg = _cfg(expect_buckets=[BucketExpectation(name="public", anon_list=True)])
    f, p = st.run_storage_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, ["public"], "t")
    assert f == []
    assert any(pc.check_id == "POSTURE_STORAGE_PRIVATE_public" and pc.passed for pc in p)

def test_listable_undeclared_is_info(monkeypatch):     # R7
    monkeypatch.setattr(st, "_post", lambda u,h,j: _resp(200, [{"name":"x"}]))
    f, _ = st.run_storage_checks(_ctx(), SUPA, {"apikey":"k"}, ["unknown"], "t")
    assert f[0].rule_id == "STORAGE_LISTABLE_UNDECLARED" and f[0].severity == Severity.INFO

def test_not_listable_is_posture_pass(monkeypatch):
    monkeypatch.setattr(st, "_post", lambda u,h,j: _resp(401, None))
    f, p = st.run_storage_checks(_ctx(), SUPA, {"apikey":"k"}, ["avatars"], "t")
    assert f == [] and any(pc.check_id == "POSTURE_STORAGE_PRIVATE_avatars" and pc.passed for pc in p)

def test_gate_closed_zero_requests(monkeypatch):       # Review Focus #5 (gate-test)
    called = []
    monkeypatch.setattr(st, "_post", lambda u,h,j: called.append(u))
    f, p = st.run_storage_checks(_ctx(max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False),
                                 SUPA, {"apikey":"k"}, ["avatars"], "t")
    assert called == [] and f == [] and p == []

def test_bucket_name_cannot_escape_host(monkeypatch):  # Review Focus #3
    seen = {}
    monkeypatch.setattr(st, "_post", lambda u,h,j: seen.setdefault("u", u))
    st.run_storage_checks(_ctx(), SUPA, {"apikey":"k"}, ["evil/../x"], "t")
    assert seen["u"].startswith(f"{SUPA}/storage/v1/object/list/")
    assert "evil%2F..%2Fx" in seen["u"]


@pytest.mark.parametrize("resp", [None, _resp(500, None), _resp(400, {"error": "Bucket not found"}),
                                  _resp(429, None), _resp(200, None), _resp(200, {"x": 1})])
def test_not_determinable_is_info_never_pass(monkeypatch, resp):
    """R6/§4.7: rete giù, 4xx/5xx inattesi, body non interpretabile → INFO
    STORAGE_NOT_VERIFIABLE e NESSUN posture 'protetto' non guadagnato."""
    monkeypatch.setattr(st, "_post", lambda u, h, j: resp)
    f, p = st.run_storage_checks(_ctx(), SUPA, {"apikey": "k"}, ["avatars"], "t")
    assert [x.rule_id for x in f] == ["STORAGE_NOT_VERIFIABLE"]
    assert f[0].severity == Severity.INFO
    assert not any(pc.passed for pc in p)


def test_empty_list_is_protected(monkeypatch):
    """200 + [] → l'anon non vede oggetti → protetto (pass)."""
    monkeypatch.setattr(st, "_post", lambda u, h, j: _resp(200, []))
    f, p = st.run_storage_checks(_ctx(), SUPA, {"apikey": "k"}, ["avatars"], "t")
    assert f == [] and any(pc.passed for pc in p)


@pytest.mark.parametrize("name", ["syntax.png", "filename.pdf", "scorecard.png", "wildcard.svg",
                                  "logo.png"])
def test_non_personal_substrings_stay_high(monkeypatch, name):
    monkeypatch.setattr(st, "_post", lambda u, h, j: _resp(200, [{"name": name}]))
    cfg = _cfg(expect_buckets=[BucketExpectation(name="docs", anon_list=False)])
    f, _ = st.run_storage_checks(_ctx(cfg=cfg), SUPA, {"apikey": "k"}, ["docs"], "t")
    assert f[0].severity == Severity.HIGH and f[0].gdpr_relevant is False


@pytest.mark.parametrize("name", ["user_email.csv", "fattura-2024.pdf", "invoices/x.pdf",
                                  "carta_identita.jpg", "CF_mario.pdf"])
def test_personal_tokens_are_critical(monkeypatch, name):
    monkeypatch.setattr(st, "_post", lambda u, h, j: _resp(200, [{"name": name}]))
    cfg = _cfg(expect_buckets=[BucketExpectation(name="docs", anon_list=False)])
    f, _ = st.run_storage_checks(_ctx(cfg=cfg), SUPA, {"apikey": "k"}, ["docs"], "t")
    assert f[0].severity == Severity.CRITICAL and f[0].gdpr_relevant is True
