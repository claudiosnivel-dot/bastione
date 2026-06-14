"""Test del modulo Supabase probe — la gemma (§11.1) — OFFLINE, read-only.

Strategia (come in test_gate.py / test_recon.py):
- Il confine HTTP del modulo è la funzione modulo-livello `_get(url, headers)`:
  è l'**unica** cosa monkeypatchata, così i test girano offline e nessun host
  reale viene mai puntato (M0 read-only).
- Si verifica la *gemma*: surface map dallo schema OpenAPI di PostgREST + RLS read
  test con l'anon key (pubblica per design, §8/§11).

Invarianti LOCKED coperti qui:
- `should_run` vero **solo** con `is_supabase` E `anon_key` presente (§9).
- 200 con righe e colonna di dato personale → Finding `RLS_DISABLED`
  `CRITICAL` + `gdpr_relevant=True`; con sole colonne non personali → `HIGH`.
- 200 vuoto / 401 / 403 → PostureCheck `POSTURE_RLS_<tabella>` passed.
- L'evidence NON contiene mai i valori delle righe (P8): solo conteggio + nomi
  colonna.
- Lo stub §11.2 (scritture canary) solleva `NotImplementedError("M2")`.
- Le RPC (`/rpc/*`) NON sono invocate in M0 (solo conteggio).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import (
    Finding,
    Fingerprint,
    PostureCheck,
    RunContext,
    TargetConfig,
)
from bastione.modules import supabase as supabase_pkg  # noqa: F401  (assicura l'import del package)
from bastione.modules.supabase import module as supa


SUPA_URL = "https://abcdefghijklmnopqrst.supabase.co"
ANON = "eyJhbGciOiJI.anonpayload.sig"  # placeholder: il modulo non decodifica la chiave


# ─── helper di costruzione (config / contesto / fingerprint) ────────────────

def make_cfg(*, name="gestionale", supabase_url=None):
    return TargetConfig(
        name=name,
        base_url="https://staging.example",
        environment="staging",
        ownership="owned",
        supabase_url=supabase_url,
    )


def make_fp(*, is_supabase=True, supabase_url=SUPA_URL, anon_key=ANON,
            discovered_tables=None):
    return Fingerprint(
        target="gestionale",
        resolved_urls=["https://staging.example/"],
        is_supabase=is_supabase,
        supabase_url=supabase_url,
        anon_key=anon_key,
        discovered_tables=discovered_tables or [],
    )


def make_ctx(*, fp=None, cfg=None, tmp_path: Path | None = None):
    return RunContext(
        target_cfg=cfg or make_cfg(),
        fingerprint=fp or make_fp(),
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=tmp_path or Path("."),
        ownership_verified=False,
    )


def fake_resp(*, status_code=200, payload=None, text=None):
    """Risposta httpx-like minimale: `.status_code` + `.json()` (+ `.text`)."""
    def _json():
        if payload is None:
            raise ValueError("no json")
        return payload
    return SimpleNamespace(
        status_code=status_code,
        json=_json,
        text=text if text is not None else json.dumps(payload),
    )


# ─── schema OpenAPI sintetico di PostgREST (la sorgente della surface map) ──

def openapi_schema(tables: dict[str, list[str]], rpcs: list[str] | None = None) -> dict:
    """Costruisce uno schema OpenAPI PostgREST-like.

    `tables`: nome tabella → lista nomi colonna. `rpcs`: nomi funzioni esposte
    sotto `/rpc/<nome>` (devono essere conteggiate ma MAI invocate in M0).
    """
    definitions = {
        tbl: {"properties": {col: {"type": "string"} for col in cols}}
        for tbl, cols in tables.items()
    }
    paths: dict[str, dict] = {"/": {}}
    for tbl in tables:
        paths[f"/{tbl}"] = {"get": {}}
    for rpc in rpcs or []:
        paths[f"/rpc/{rpc}"] = {"post": {}}
    return {"swagger": "2.0", "definitions": definitions, "paths": paths}


# ─── router di _get monkeypatchato: instrada per URL ─────────────────────────

def install_router(monkeypatch, *, schema, rows):
    """Monkeypatcha `_get` con un router offline.

    `schema`: dict OpenAPI ritornato per `<url>/rest/v1/`.
    `rows`: nome tabella → (status_code, payload) ritornato per la GET RLS.
    Registra ogni URL contattato in `calls` (per asserire che le RPC NON sono
    mai invocate in M0).
    """
    calls: list[str] = []

    def router(url, headers):
        calls.append(url)
        # surface map: la root dell'API REST
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        # RLS read test: /rest/v1/<tabella>?limit=1
        for tbl, (status, payload) in rows.items():
            if f"/rest/v1/{tbl}?" in url or url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return None

    monkeypatch.setattr(supa, "_get", router)
    return calls


# ─── should_run (§9) ────────────────────────────────────────────────────────

def test_should_run_true_with_supabase_and_anon():
    assert supa.SupabaseModule().should_run(make_fp(), make_cfg()) is True


def test_should_run_false_without_supabase():
    fp = make_fp(is_supabase=False, supabase_url=None)
    assert supa.SupabaseModule().should_run(fp, make_cfg()) is False


def test_should_run_false_without_anon_key():
    fp = make_fp(anon_key=None)
    assert supa.SupabaseModule().should_run(fp, make_cfg()) is False


# ─── identità del modulo (§9/§11) ──────────────────────────────────────────

def test_module_identity_is_readonly():
    mod = supa.SupabaseModule()
    assert mod.name == "supabase"
    assert mod.max_intrusion is IntrusionLevel.READ_ONLY


# ─── surface map: enumerazione tabelle dallo schema OpenAPI ─────────────────

def test_surface_map_enumerates_tables_and_counts_rpc(monkeypatch):
    schema = openapi_schema(
        {"clienti": ["id", "nome"], "listino": ["id", "prezzo"]},
        rpcs=["get_stats", "do_stuff"],
    )
    # tutte le tabelle protette: nessun Finding, solo PostureCheck
    rows = {"clienti": (401, None), "listino": (403, None)}
    calls = install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    # due tabelle enumerate → due PostureCheck (entrambe protette)
    ids = {pc.check_id for pc in res.posture_checks}
    assert "POSTURE_RLS_clienti" in ids
    assert "POSTURE_RLS_listino" in ids
    # le RPC NON devono MAI essere invocate in M0 (solo conteggio)
    assert not any("/rpc/" in u for u in calls)


# ─── RLS read test: 200 + righe + colonna personale → CRITICAL + gdpr ───────

def test_rls_disabled_personal_data_is_critical_and_gdpr(monkeypatch):
    schema = openapi_schema({"clienti": ["id", "nome", "email"]})
    rows = {"clienti": (200, [{"id": 1, "nome": "Mario", "email": "m@x.it"}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.gdpr_relevant is True
    assert f.confidence is Confidence.FIRM
    assert f.module == "supabase"
    assert f.target == "gestionale"
    assert f.location.endpoint == "/rest/v1/clienti"
    assert f.location.url == SUPA_URL
    assert f.remediation_ref == "RLS_DISABLED"
    assert f.owasp == ["A01:2021"]


# ─── RLS read test: 200 + righe + sole colonne non personali → HIGH ─────────

def test_rls_disabled_non_personal_is_high_not_gdpr(monkeypatch):
    schema = openapi_schema({"listino": ["id", "codice", "prezzo"]})
    rows = {"listino": (200, [{"id": 1, "codice": "A", "prezzo": 9}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].gdpr_relevant is False


# ─── evidence redatta (P8): mai i valori delle righe ────────────────────────

def test_evidence_redacts_row_values(monkeypatch):
    schema = openapi_schema({"clienti": ["id", "nome", "email"]})
    secret_email = "segretissimo@personale.it"
    rows = {"clienti": (200, [{"id": 1, "nome": "Mario", "email": secret_email}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    f = next(f for f in res.findings if f.rule_id == "RLS_DISABLED")
    # i VALORI di riga non devono comparire nell'evidence…
    assert secret_email not in f.evidence
    assert "Mario" not in f.evidence
    # …mentre i NOMI colonna e il conteggio sì (è la prova legittima)
    assert "email" in f.evidence
    assert "1" in f.evidence


# ─── PostureCheck: 200 vuoto / 401 / 403 → passed ───────────────────────────

@pytest.mark.parametrize(
    "status,payload",
    [(200, []), (401, None), (403, None)],
    ids=["empty-200", "401", "403"],
)
def test_protected_table_yields_passing_posture(monkeypatch, status, payload):
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (status, payload)}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    # nessun Finding RLS_DISABLED
    assert not [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    pc = pcs[0]
    assert pc.passed is True
    assert pc.severity_if_failed is Severity.HIGH
    assert pc.target == "gestionale"


# ─── sorgente supabase_url: fallback su TargetConfig ────────────────────────

def test_supabase_url_falls_back_to_target_cfg(monkeypatch):
    # fingerprint senza url ma is_supabase comunque vero: l'url viene dalla config
    fp = make_fp(supabase_url=None)
    cfg = make_cfg(supabase_url=SUPA_URL)
    schema = openapi_schema({"t": ["id"]})
    rows = {"t": (401, None)}
    calls = install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp, cfg=cfg))

    assert any(u.startswith(SUPA_URL) for u in calls)
    assert any(pc.check_id == "POSTURE_RLS_t" for pc in res.posture_checks)


# ─── segnale onesto: surface non enumerabile → UN finding INFO/TENTATIVE ─────
#
# Su un target reale la root REST può rispondere 401 all'anon (schema non
# introspezionabile). NON si tace (sarebbe fuorviante): si emette UN finding
# onesto SUPABASE_SCHEMA_NOT_ENUMERABLE che rende ESPLICITO che la verifica RLS
# NON è stata fatta (verifica INCOMPLETA, §11.1).

def test_surface_map_401_emits_honest_not_enumerable_finding(monkeypatch):
    def router(url, headers):
        # la root REST risponde 401 all'anon: schema non introspezionabile
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=401, payload=None)
        return None
    monkeypatch.setattr(supa, "_get", router)

    res = supa.SupabaseModule().run(make_ctx())

    # esattamente UN finding onesto, nessun posture check (RLS non verificata)
    assert len(res.findings) == 1
    assert res.posture_checks == []
    f = res.findings[0]
    assert f.rule_id == "SUPABASE_SCHEMA_NOT_ENUMERABLE"
    assert f.module == "supabase"
    assert f.severity is Severity.INFO
    assert f.confidence is Confidence.TENTATIVE
    assert f.target == "gestionale"
    assert f.location.endpoint == "/rest/v1/"
    assert f.location.url == SUPA_URL
    assert f.remediation_ref == "RLS_DISABLED"
    assert f.owasp == ["A01:2021"]
    assert f.intrusion_used is IntrusionLevel.READ_ONLY
    # l'evidence (NON segreta) riporta il MOTIVO esplicito del fallimento
    assert "status=401" in f.evidence
    # nessuna chiave/segreto nell'evidence (P8)
    assert ANON not in f.evidence


def test_surface_map_unreachable_emits_honest_finding_with_network_detail(monkeypatch):
    # _get → None (httpx assente o errore di rete): stesso segnale onesto
    monkeypatch.setattr(supa, "_get", lambda url, headers: None)

    res = supa.SupabaseModule().run(make_ctx())

    assert len(res.findings) == 1
    assert res.posture_checks == []
    f = res.findings[0]
    assert f.rule_id == "SUPABASE_SCHEMA_NOT_ENUMERABLE"
    assert f.severity is Severity.INFO
    assert f.confidence is Confidence.TENTATIVE
    # il detail di rete deve comparire nell'evidence
    assert "rete" in f.evidence.lower()


def test_surface_map_non_json_emits_honest_finding(monkeypatch):
    def router(url, headers):
        # 200 ma corpo non-JSON: .json() solleva → schema non disponibile
        return fake_resp(status_code=200, payload=None, text="<html>not json</html>")
    monkeypatch.setattr(supa, "_get", router)

    res = supa.SupabaseModule().run(make_ctx())

    assert len(res.findings) == 1
    assert res.posture_checks == []
    f = res.findings[0]
    assert f.rule_id == "SUPABASE_SCHEMA_NOT_ENUMERABLE"
    assert "non-JSON" in f.evidence


# ─── FALLBACK via bundle: surface 401 + discovered_tables → RLS test per nome ─
#
# Su un target hardened la root REST risponde 401 (OpenAPI non introspezionabile).
# Un attaccante ricava i nomi tabella dal bundle (.from('clienti')) e testa l'RLS
# per nome. `fingerprint.discovered_tables` porta quei nomi: il modulo fa il
# fallback e testa l'RLS tabella per tabella, riusando _rls_read_test.

def install_fallback_router(monkeypatch, *, surface_status=401, rows):
    """Router offline: la root REST risponde `surface_status` (≠200, schema NON
    enumerabile), le GET RLS per tabella seguono `rows` (nome → (status, payload))."""
    calls: list[str] = []

    def router(url, headers):
        calls.append(url)
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=surface_status, payload=None)
        for tbl, (status, payload) in rows.items():
            if f"/rest/v1/{tbl}?" in url or url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return None

    monkeypatch.setattr(supa, "_get", router)
    return calls


def test_fallback_via_bundle_rls_disabled_is_high(monkeypatch):
    # surface 401 + discovered_tables=['clienti'] con righe → RLS_DISABLED HIGH.
    # Severità LOCKED HIGH anche con colonne personali nel NOME: le colonne NON
    # sono note (tabella scoperta dal bundle, non da OpenAPI) → columns=[].
    fp = make_fp(discovered_tables=["clienti"])
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    f = findings[0]
    # severità HIGH LOCKED (no euristica GDPR senza colonne)
    assert f.severity is Severity.HIGH
    assert f.gdpr_relevant is False
    assert f.location.endpoint == "/rest/v1/clienti"
    # la nota deve dire esplicitamente che le colonne non sono note / dal bundle
    assert "colonne non" in f.description.lower() or "non note" in f.description.lower()
    assert "bundle" in f.description.lower()
    # evidence redatta: nessun valore di riga
    assert "x@y.it" not in f.evidence


def test_fallback_via_bundle_protected_table_yields_posture(monkeypatch):
    # tabella protetta (401) in fallback → POSTURE_RLS_<tab> passed
    fp = make_fp(discovered_tables=["clienti"])
    rows = {"clienti": (401, None)}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    assert not [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    assert pcs[0].passed is True


def test_fallback_via_bundle_emits_partial_coverage_honest_finding(monkeypatch):
    # in fallback si emette UN finding onesto INFO/TENTATIVE che documenta la
    # copertura PARZIALE (enumerazione via bundle, OpenAPI non disponibile).
    fp = make_fp(discovered_tables=["clienti", "ordini"])
    rows = {"clienti": (401, None), "ordini": (401, None)}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    partial = [f for f in res.findings if f.rule_id == "SUPABASE_SCHEMA_VIA_BUNDLE"]
    assert len(partial) == 1
    f = partial[0]
    assert f.severity is Severity.INFO
    assert f.confidence is Confidence.TENTATIVE
    assert f.intrusion_used is IntrusionLevel.READ_ONLY
    # onesto sulla parzialità: enumerazione via bundle, OpenAPI non disponibile
    assert "bundle" in f.description.lower()
    assert "parzial" in f.description.lower() or "potrebbero esistere" in f.description.lower()
    # nessun segreto nell'evidence (P8)
    assert ANON not in f.evidence
    # NON deve comparire il segnale "non enumerabile" (le tabelle ci sono dal bundle)
    assert "SUPABASE_SCHEMA_NOT_ENUMERABLE" not in {x.rule_id for x in res.findings}


def test_fallback_no_tables_keeps_not_enumerable(monkeypatch):
    # REGRESSIONE: surface 401 + discovered_tables=[] → resta
    # SUPABASE_SCHEMA_NOT_ENUMERABLE (comportamento attuale invariato).
    fp = make_fp(discovered_tables=[])
    monkeypatch.setattr(supa, "_get", lambda url, headers: (
        fake_resp(status_code=401, payload=None)
        if url.rstrip("/").endswith("/rest/v1") else None))

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    assert len(res.findings) == 1
    assert res.posture_checks == []
    assert res.findings[0].rule_id == "SUPABASE_SCHEMA_NOT_ENUMERABLE"


def test_happy_path_ignores_discovered_tables(monkeypatch):
    # REGRESSIONE path felice: surface 200 enumera da OpenAPI e IGNORA del tutto
    # discovered_tables (decisione LOCKED: bundle solo come fallback sul 401).
    fp = make_fp(discovered_tables=["tabella_dal_bundle"])
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (401, None)}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    pc_ids = {pc.check_id for pc in res.posture_checks}
    # solo la tabella da OpenAPI è stata testata, non quella dal bundle
    assert "POSTURE_RLS_clienti" in pc_ids
    assert "POSTURE_RLS_tabella_dal_bundle" not in pc_ids
    # nessun finding via-bundle sul path felice
    assert "SUPABASE_SCHEMA_VIA_BUNDLE" not in {f.rule_id for f in res.findings}


# ─── REGRESSIONE: il path felice NON deve mostrare il segnale onesto ─────────

def test_happy_path_does_not_emit_honest_signal(monkeypatch):
    # 200 + tabella con RLS aperta → ancora il finding RLS_DISABLED come prima;
    # il segnale onesto SUPABASE_SCHEMA_NOT_ENUMERABLE NON deve comparire.
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    rule_ids = {f.rule_id for f in res.findings}
    assert "RLS_DISABLED" in rule_ids
    assert "SUPABASE_SCHEMA_NOT_ENUMERABLE" not in rule_ids


# ─── il finding_id del segnale onesto coincide con baseline.diff.finding_id ──

def test_not_enumerable_finding_id_matches_baseline_diff(monkeypatch):
    from bastione.baseline.diff import finding_id as baseline_finding_id

    monkeypatch.setattr(supa, "_get", lambda url, headers: None)
    res = supa.SupabaseModule().run(make_ctx())
    f = res.findings[0]
    assert f.finding_id == baseline_finding_id(f)
    assert len(f.finding_id) == 16


# ─── resilienza: una tabella che fa errore non blocca le altre ──────────────

def test_one_table_error_does_not_crash_others(monkeypatch):
    schema = openapi_schema({"buona": ["id"], "rotta": ["id"]})

    def router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/rotta" in url:
            raise RuntimeError("boom")  # simula un errore inatteso sulla GET
        if "/rest/v1/buona" in url:
            return fake_resp(status_code=401, payload=None)
        return None

    monkeypatch.setattr(supa, "_get", router)

    res = supa.SupabaseModule().run(make_ctx())

    # la tabella sana produce comunque il suo PostureCheck
    assert any(pc.check_id == "POSTURE_RLS_buona" for pc in res.posture_checks)


# ─── header anon su ogni richiesta (apikey + Authorization Bearer) ──────────

def test_anon_headers_sent_on_every_request(monkeypatch):
    schema = openapi_schema({"clienti": ["id"]})
    seen_headers: list[dict] = []

    def router(url, headers):
        seen_headers.append(headers)
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        return fake_resp(status_code=401, payload=None)

    monkeypatch.setattr(supa, "_get", router)

    supa.SupabaseModule().run(make_ctx())

    assert seen_headers, "almeno una richiesta deve essere stata fatta"
    for h in seen_headers:
        assert h.get("apikey") == ANON
        assert h.get("Authorization") == f"Bearer {ANON}"


# ─── _get degrada a None se httpx manca (confine I/O) ───────────────────────

def test_get_returns_none_without_httpx(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert supa._get(f"{SUPA_URL}/rest/v1/", {"apikey": ANON}) is None


# ─── stub §11.2: le scritture canary sollevano NotImplementedError("M2") ────

def test_canary_write_stub_raises_not_implemented():
    mod = supa.SupabaseModule()
    with pytest.raises(NotImplementedError, match="M2"):
        mod._canary_write_test(make_ctx())


# ─── §17 FIX: tabella esposta → PostureCheck FALLITO (oltre al Finding) ─────
#
# Bug emerso da una run live: con RLS disabilitata si emetteva il Finding
# RLS_DISABLED ma NESSUN PostureCheck fallito → lo score (che si calcola dai
# PostureCheck, non dai finding) restava 100/100 pur con HIGH/CRITICAL aperti.
# Fix: il ramo "tabella leggibile dall'anon" emette ANCHE un PostureCheck
# POSTURE_RLS_<tab> passed=False, con severity_if_failed = severità del finding.


def test_rls_disabled_personal_emits_failed_posture_critical(monkeypatch):
    # scenario TDD 1: tabella esposta (200+righe, OpenAPI, colonne personali) →
    # 1 Finding RLS_DISABLED CRITICAL + 1 PostureCheck passed=False CRITICAL.
    schema = openapi_schema({"clienti": ["id", "nome", "email"]})
    rows = {"clienti": (200, [{"id": 1, "nome": "Mario", "email": "m@x.it"}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL

    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    pc = pcs[0]
    assert pc.passed is False
    # severity_if_failed DEVE coincidere con la severità del finding (peso 8)
    assert pc.severity_if_failed is Severity.CRITICAL
    assert pc.target == "gestionale"
    assert pc.remediation_ref == "RLS_DISABLED"
    # drift resta al default False (lo valorizza la fase POSTURE/baseline, §16)
    assert pc.drift is False
    # mutua esclusione: NESSUN posture passed=True per la stessa tabella
    assert not any(p.passed for p in res.posture_checks)


def test_rls_disabled_via_bundle_emits_failed_posture_high(monkeypatch):
    # scenario TDD 2: tabella esposta via_bundle (columns=[]) → finding HIGH +
    # posture passed=False HIGH (no euristica GDPR senza colonne).
    fp = make_fp(discovered_tables=["clienti"])
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH

    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    assert pcs[0].passed is False
    assert pcs[0].severity_if_failed is Severity.HIGH  # peso 5
    assert pcs[0].drift is False


def test_protected_table_emits_only_passing_posture(monkeypatch):
    # scenario TDD 3 (INVARIANTE): tabella protetta → posture passed=True,
    # nessun finding, nessun posture failed (mutua esclusione).
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (401, None)}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    assert not [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    assert pcs[0].passed is True


def test_exposed_rls_lowers_posture_score_below_100(monkeypatch):
    # scenario TDD 4 (integrazione): una run con ≥1 RLS esposta → posture_score
    # < 100 (prima del fix era 100, il bug di §17). Usa la formula reale.
    from bastione.posture.checks import posture_score

    schema = openapi_schema(
        {"clienti": ["id", "email"], "listino": ["id", "prezzo"]})
    # clienti esposta (RLS off), listino protetta
    rows = {
        "clienti": (200, [{"id": 1, "email": "x@y.it"}]),
        "listino": (401, None),
    }
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx())

    # c'è almeno un posture fallito (clienti) e uno passato (listino)
    assert any(not pc.passed for pc in res.posture_checks)
    assert any(pc.passed for pc in res.posture_checks)
    score = posture_score(res.posture_checks)
    assert score < 100.0


# ─── finding_id stabile (§16) deterministico per tabella ────────────────────

def test_finding_id_is_stable_across_runs(monkeypatch):
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    f1 = next(f for f in supa.SupabaseModule().run(make_ctx()).findings)
    f2 = next(f for f in supa.SupabaseModule().run(make_ctx()).findings)
    assert f1.finding_id == f2.finding_id
    assert len(f1.finding_id) == 16
