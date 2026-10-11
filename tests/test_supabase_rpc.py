import pytest
from pathlib import Path
from types import SimpleNamespace
import bastione.modules.supabase.rpc as rpc
from bastione.enums import IntrusionLevel, Severity, Confidence
from bastione.models import RunContext, TargetConfig, Fingerprint, RpcExpectation

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

def test_denylisted_name_not_invoked(monkeypatch):     # Review Focus #2a
    called = []
    monkeypatch.setattr(rpc, "_get", lambda u,h: called.append(u))
    f, _ = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey":"k"}, ["send_email"], "t")
    assert called == []
    assert f and f[0].rule_id == "RPC_NOT_VERIFIABLE" and f[0].severity == Severity.INFO

def test_data_exposed_personal_critical(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u,h: _resp(200, [{"id":1,"email":"m@x.it","nome":"Mario"}]))
    f, p = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey":"k"}, ["leak_users"], "t")
    hit = [x for x in f if x.rule_id == "RPC_DATA_EXPOSED"]
    assert hit and hit[0].severity == Severity.CRITICAL and hit[0].gdpr_relevant
    assert "m@x.it" not in hit[0].evidence and "Mario" not in hit[0].evidence     # P8
    assert "email" in hit[0].evidence                                            # colonne ok

def test_invocable_undeclared_medium_tentative(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u,h: _resp(200, [{"id":1,"qty":3}]))
    f, _ = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey":"k"}, ["get_counts"], "t")
    hit = [x for x in f if x.rule_id == "RPC_ANON_INVOCABLE"]
    assert hit and hit[0].severity == Severity.MEDIUM and hit[0].confidence == Confidence.TENTATIVE

def test_declared_public_is_posture_pass(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u,h: _resp(200, [{"id":1,"prezzo":10}]))
    cfg = _cfg(expect_rpcs=[RpcExpectation(name="listino", anon_execute=True)])
    f, p = rpc.run_rpc_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, ["listino"], "t")
    assert not [x for x in f if x.rule_id.startswith("RPC_")]
    assert any(pc.check_id == "POSTURE_RPC_GATED_listino" and pc.passed for pc in p)

def test_write_capable_tentative_no_post(monkeypatch):   # Review Focus #2b
    posts = []
    def getter(u,h): return _resp(405, None)
    monkeypatch.setattr(rpc, "_get", getter)
    f, _ = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey":"k"}, ["do_write"], "t")
    hit = [x for x in f if x.rule_id == "RPC_ANON_WRITE_CAPABLE"]
    assert hit and hit[0].severity == Severity.HIGH and hit[0].confidence == Confidence.TENTATIVE

def test_gated_401_posture_pass(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u,h: _resp(401, None))
    f, p = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey":"k"}, ["secret_fn"], "t")
    assert not f and any(pc.check_id == "POSTURE_RPC_GATED_secret_fn" and pc.passed for pc in p)

def test_gate_closed_zero_requests(monkeypatch):
    called = []
    monkeypatch.setattr(rpc, "_get", lambda u,h: called.append(u))
    f, p = rpc.run_rpc_checks(_ctx(max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False),
                              SUPA, {"apikey":"k"}, ["get_counts"], "t")
    assert called == [] and f == [] and p == []



@pytest.mark.parametrize("status", [400, 404, 409, 429, 500, 503])
def test_inconclusive_status_is_not_verifiable_never_pass(monkeypatch, status):
    """R6: solo 401/403 provano che l'anon non esegue la funzione. Un 404 (argomenti
    mancanti / funzione non trovata) o un 5xx NON sono un pass."""
    monkeypatch.setattr(rpc, "_get", lambda u, h: _resp(status, {"message": "x"}))
    f, p = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey": "k"}, ["get_listino"], "t")
    assert [x.rule_id for x in f] == ["RPC_NOT_VERIFIABLE"]
    assert not any(pc.passed for pc in p)


def test_no_response_is_not_verifiable(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u, h: None)
    f, p = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey": "k"}, ["get_listino"], "t")
    assert [x.rule_id for x in f] == ["RPC_NOT_VERIFIABLE"] and p == []


def test_error_body_25006_is_write_capable(monkeypatch):
    monkeypatch.setattr(rpc, "_get", lambda u, h: _resp(
        500, {"code": "25006", "message": "cannot execute UPDATE in a read-only transaction"}))
    f, _ = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey": "k"}, ["get_x"], "t")
    assert [x.rule_id for x in f] == ["RPC_ANON_WRITE_CAPABLE"]
    assert f[0].confidence == Confidence.TENTATIVE


def test_200_with_read_only_text_is_not_write_capable(monkeypatch):
    """Il blocco read-only è solo un errore: un 200 i cui dati citano 'read only' non
    è write-capable e non maschera RPC_DATA_EXPOSED."""
    monkeypatch.setattr(rpc, "_get", lambda u, h: _resp(
        200, {"message": "read only mode", "email": "a@b.c"}))
    f, _ = rpc.run_rpc_checks(_ctx(), SUPA, {"apikey": "k"}, ["get_profile"], "t")
    assert [x.rule_id for x in f] == ["RPC_DATA_EXPOSED"]
    assert "a@b.c" not in f[0].evidence          # P8: mai i valori


def test_minimal_read_and_sample_args_in_query(monkeypatch):
    seen = []
    monkeypatch.setattr(rpc, "_get", lambda u, h: seen.append(u) or _resp(401, None))
    cfg = _cfg(expect_rpcs=[RpcExpectation(name="search_x", sample_args={"q": "a b"})])
    rpc.run_rpc_checks(_ctx(cfg=cfg), SUPA, {"apikey": "k"}, ["search_x", "get_y"], "t")
    assert seen[0] == f"{SUPA}/rest/v1/rpc/search_x?q=a+b&limit=1"
    assert seen[1] == f"{SUPA}/rest/v1/rpc/get_y?limit=1"


def test_get_invalid_url_degrades_to_none():
    """Il confine I/O non solleva mai (InvalidURL non è un httpx.HTTPError)."""
    pytest.importorskip("httpx")
    assert rpc._get("::::", {"apikey": "k"}) is None
