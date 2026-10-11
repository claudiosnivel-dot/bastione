"""Test della probe GraphQL di Supabase (`modules/supabase/graphql.py`, M5 Task 7) — PROBE.

I primi tre test sono quelli del piano (introspezione esposta -> LOW, disabilitata ->
posture pass, gate chiuso -> zero richieste). Gli altri pinnano le invarianti che il
piano implica: gate-first (self-gate + backstop `authorize`), owned-only (stessa
authority di `base`, redirect non seguiti), P8 (niente chiavi / body / nomi di schema
negli output e nei log), resilienza e onesta (R6: una verifica non eseguita e un INFO
esplicito, MAI una posture "passata").

OFFLINE: l'unico confine I/O (`_post`) e monkeypatchato; nessun target live.
"""
import hashlib
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import bastione.modules.supabase.graphql as gq
from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied
from bastione.models import RunContext, TargetConfig, Fingerprint

SUPA = "https://abcdefghijklmnopqrst.supabase.co"

def _ctx(*, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    cfg = TargetConfig(name="t", base_url="https://staging.example", environment="staging",
                       ownership="owned", supabase_url=SUPA)
    return RunContext(target_cfg=cfg, fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=max_intrusion, run_dir=Path("."), ownership_verified=ownership_verified)

def _resp(status, payload):
    return SimpleNamespace(status_code=status, json=lambda: payload)

def test_introspection_enabled_is_low(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u,h,j: _resp(200, {"data": {"__schema": {"queryType": {"name": "Query"}}}}))
    f, p = gq.run_graphql_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_INTROSPECTION"] and f[0].severity == Severity.LOW

def test_introspection_disabled_posture_pass(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u,h,j: _resp(200, {"errors": [{"message": "introspection disabled"}]}))
    f, p = gq.run_graphql_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert f == [] and any(pc.check_id == "POSTURE_GRAPHQL_INTROSPECTION" and pc.passed for pc in p)

def test_gate_closed_zero_requests(monkeypatch):
    called = []
    monkeypatch.setattr(gq, "_post", lambda u,h,j: called.append(u))
    f, p = gq.run_graphql_checks(_ctx(max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False),
                                 SUPA, {"apikey":"k"}, "t")
    assert called == [] and f == [] and p == []


# ─── helper e fixture delle verifiche aggiuntive ─────────────────────────────

_EXPOSED = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
_SENTINEL_KEY = "sb_publishable_SENTINEL_KEY_DO_NOT_LEAK"


def _bad_json_resp(status):
    def _boom():
        raise ValueError("no json")
    return SimpleNamespace(status_code=status, json=_boom)


def _run(ctx=None, base=SUPA, headers=None):
    return gq.run_graphql_checks(ctx or _ctx(), base, headers or {"apikey": "k"}, "t")


@pytest.fixture()
def httpx_mod():
    return pytest.importorskip("httpx")


# ─── contratto del finding / della posture ───────────────────────────────────

def test_exposed_finding_and_posture_contract(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(200, _EXPOSED))
    f, p = _run()
    assert len(f) == 1
    fd = f[0]
    assert (fd.module, fd.rule_id) == ("supabase", "SUPABASE_GRAPHQL_INTROSPECTION")
    assert fd.confidence == Confidence.FIRM and fd.intrusion_used == IntrusionLevel.PROBE
    assert fd.location.endpoint == "/graphql/v1" and fd.location.url == SUPA
    assert fd.remediation_ref == "SUPABASE_GRAPHQL_INTROSPECTION"
    # finding_id LOCKED (§16): sha256("module:rule_id:location.canonical()")[:16]
    raw = f"supabase:SUPABASE_GRAPHQL_INTROSPECTION:{fd.location.canonical()}"
    assert fd.finding_id == hashlib.sha256(raw.encode()).hexdigest()[:16]
    # mutua esclusione (§17): esposta -> finding + posture FALLITA (peso LOW), mai entrambe
    assert len(p) == 1 and p[0].check_id == "POSTURE_GRAPHQL_INTROSPECTION"
    assert p[0].passed is False and p[0].severity_if_failed == Severity.LOW


def test_finding_id_is_stable_across_runs(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(200, _EXPOSED))
    assert _run()[0][0].finding_id == _run()[0][0].finding_id


def test_introspection_request_shape(monkeypatch):
    calls = []

    def fake(u, h, j):
        calls.append((u, h, j))
        return _resp(200, _EXPOSED)

    monkeypatch.setattr(gq, "_post", fake)
    headers = {"apikey": "k", "Authorization": "Bearer k"}
    _run(headers=headers)
    assert len(calls) == 1                                   # una sola richiesta
    url, sent_headers, body = calls[0]
    assert url == f"{SUPA}/graphql/v1"                       # owned-only: stessa authority di base
    assert sent_headers == headers
    assert body == {"query": "{__schema{queryType{name}}}"}  # introspezione minima
    assert "mutation" not in body["query"].lower()           # una query, mai una mutation


def test_trailing_slash_base_does_not_double_the_slash(monkeypatch):
    seen = []
    monkeypatch.setattr(gq, "_post", lambda u, h, j: seen.append(u) or _resp(200, _EXPOSED))
    _run(base=SUPA + "/")
    assert seen == [f"{SUPA}/graphql/v1"]


# ─── gate-first (§4.0.7) ─────────────────────────────────────────────────────

@pytest.mark.parametrize("level,verified", [
    (IntrusionLevel.READ_ONLY, True),
    (IntrusionLevel.PROBE, False),
    (IntrusionLevel.READ_ONLY, False),
])
def test_self_gate_blocks_every_closed_combination(monkeypatch, level, verified):
    called = []
    monkeypatch.setattr(gq, "_post", lambda u, h, j: called.append(u))
    f, p = _run(_ctx(max_intrusion=level, ownership_verified=verified))
    assert called == [] and f == [] and p == []


def test_mutating_ceiling_with_ownership_still_probes(monkeypatch):
    called = []
    monkeypatch.setattr(gq, "_post", lambda u, h, j: called.append(u) or _resp(200, _EXPOSED))
    f, _ = _run(_ctx(max_intrusion=IntrusionLevel.MUTATING))
    assert len(called) == 1 and [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_INTROSPECTION"]


def test_authorize_backstop_is_consulted_with_probe(monkeypatch):
    seen = []
    monkeypatch.setattr(gq, "authorize", lambda action, ctx: seen.append(action))
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(200, _EXPOSED))
    _run()
    assert seen == [IntrusionLevel.PROBE]


def test_authorize_backstop_denied_means_zero_requests(monkeypatch):
    called = []
    monkeypatch.setattr(gq, "_post", lambda u, h, j: called.append(u))

    def deny(action, ctx):
        raise IntrusionDenied("negato dal backstop")

    monkeypatch.setattr(gq, "authorize", deny)
    f, p = _run()
    assert called == [] and f == [] and p == []


# ─── oracolo: solo un oggetto `__schema` reale e "esposto" ────────────────────

@pytest.mark.parametrize("payload", [
    {"data": {"__schema": None}},                       # null non e uno schema enumerabile
    {"data": None, "errors": [{"message": "x"}]},
    {"data": {}},
    {"data": []},
    [],
    "oops",
    None,
])
def test_200_without_a_schema_object_is_not_exposed(monkeypatch, payload):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(200, payload))
    f, p = _run()
    assert f == [] and [pc.passed for pc in p] == [True]


def test_200_non_json_body_is_not_exposed(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _bad_json_resp(200))
    f, p = _run()
    assert f == [] and [pc.passed for pc in p] == [True]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405])
def test_definitive_refusal_is_posture_pass(monkeypatch, status):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(status, {"message": "nope"}))
    f, p = _run()
    assert f == [] and [pc.passed for pc in p] == [True]


# ─── onesta (R6): verifica non eseguita != verifica passata ──────────────────

def test_no_response_is_honest_info_not_a_posture_pass(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: None)
    f, p = _run()
    assert [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_NOT_VERIFIABLE"]
    assert f[0].severity == Severity.INFO and f[0].confidence == Confidence.TENTATIVE
    assert f[0].intrusion_used == IntrusionLevel.PROBE
    assert p == []          # una verifica non eseguita non deve gonfiare il posture score


@pytest.mark.parametrize("status", [302, 307, 408, 429, 500, 502, 503])
def test_inconclusive_status_is_not_verifiable(monkeypatch, status):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(status, {"errors": []}))
    f, p = _run()
    assert [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_NOT_VERIFIABLE"] and p == []
    assert str(status) in f[0].evidence


def test_not_verifiable_finding_id_is_locked_formula(monkeypatch):
    monkeypatch.setattr(gq, "_post", lambda u, h, j: None)
    fd = _run()[0][0]
    raw = f"supabase:SUPABASE_GRAPHQL_NOT_VERIFIABLE:{fd.location.canonical()}"
    assert fd.finding_id == hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── P8: nessun segreto / body / nome di schema nei campi e nei log ───────────

def test_p8_nothing_from_headers_or_response_leaks(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    payload = {"data": {"__schema": {"queryType": {"name": "SENTINEL_TYPE"},
                                     "types": [{"name": "sentinel_secret_table"}]}}}
    monkeypatch.setattr(gq, "_post", lambda u, h, j: _resp(200, payload))
    headers = {"apikey": _SENTINEL_KEY, "Authorization": f"Bearer {_SENTINEL_KEY}"}
    f, p = _run(headers=headers)
    blob = repr(f) + repr(p) + caplog.text
    for secret in (_SENTINEL_KEY, "SENTINEL_TYPE", "sentinel_secret_table"):
        assert secret not in blob


def test_p8_transport_error_message_is_not_logged(monkeypatch, caplog, httpx_mod):
    caplog.set_level(logging.DEBUG)

    def boom(*a, **k):      # h11 ripete il valore dell'header illegale nel messaggio
        raise httpx_mod.LocalProtocolError(f"Illegal header value b'{_SENTINEL_KEY}'")

    monkeypatch.setattr(httpx_mod, "post", boom)
    assert gq._post(f"{SUPA}/graphql/v1", {"apikey": _SENTINEL_KEY}, {"query": "q"}) is None
    assert "LocalProtocolError" in caplog.text      # il log c'e (non vacuo): solo il TIPO dell'errore
    assert _SENTINEL_KEY not in caplog.text


# ─── resilienza: il confine I/O non solleva mai ──────────────────────────────

@pytest.mark.parametrize("make_exc", [
    lambda h: h.ConnectError("x"),
    lambda h: h.ReadTimeout("x"),
    lambda h: h.InvalidURL("x"),     # NON e un HTTPError: deve comunque degradare
    lambda h: ValueError("x"),       # es. valore d'header non codificabile
])
def test_post_boundary_degrades_to_none_and_probe_does_not_crash(monkeypatch, httpx_mod, make_exc):
    def boom(*a, **k):
        raise make_exc(httpx_mod)

    monkeypatch.setattr(httpx_mod, "post", boom)
    assert gq._post(f"{SUPA}/graphql/v1", {"apikey": "k"}, {"query": "q"}) is None
    f, p = _run()
    assert [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_NOT_VERIFIABLE"] and p == []


def test_post_boundary_never_follows_redirects(monkeypatch, httpx_mod):
    seen = {}

    def fake(url, **kw):
        seen.update(kw)
        seen["url"] = url
        return _resp(200, {})

    monkeypatch.setattr(httpx_mod, "post", fake)
    gq._post(f"{SUPA}/graphql/v1", {"apikey": "k"}, {"query": "q"})
    assert seen["follow_redirects"] is False          # owned-only: nessun salto su un altro host
    assert seen["timeout"] == gq._HTTP_TIMEOUT
    assert seen["json"] == {"query": "q"} and seen["url"] == f"{SUPA}/graphql/v1"


def test_httpx_missing_degrades_to_not_verifiable(monkeypatch):
    monkeypatch.setitem(sys.modules, "httpx", None)   # `import httpx` -> ImportError
    assert gq._post(f"{SUPA}/graphql/v1", {"apikey": "k"}, {"query": "q"}) is None
    f, p = _run()
    assert [x.rule_id for x in f] == ["SUPABASE_GRAPHQL_NOT_VERIFIABLE"] and p == []
