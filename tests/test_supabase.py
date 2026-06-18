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
    TableExpectation,
    TargetConfig,
)
from bastione.modules import supabase as supabase_pkg  # noqa: F401  (assicura l'import del package)
from bastione.modules.supabase import module as supa


SUPA_URL = "https://abcdefghijklmnopqrst.supabase.co"
ANON = "eyJhbGciOiJI.anonpayload.sig"  # placeholder: il modulo non decodifica la chiave


# ─── helper di costruzione (config / contesto / fingerprint) ────────────────

def make_cfg(*, name="gestionale", supabase_url=None, expectations=None):
    return TargetConfig(
        name=name,
        base_url="https://staging.example",
        environment="staging",
        ownership="owned",
        supabase_url=supabase_url,
        expectations=expectations or [],
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


def make_ctx(*, fp=None, cfg=None, tmp_path: Path | None = None,
             max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False):
    return RunContext(
        target_cfg=cfg or make_cfg(),
        fingerprint=fp or make_fp(),
        max_intrusion=max_intrusion,
        run_dir=tmp_path or Path("."),
        ownership_verified=ownership_verified,
    )


def fake_resp(*, status_code=200, payload=None, text=None, headers=None):
    """Risposta httpx-like minimale: `.status_code` + `.json()` (+ `.text`,
    `.headers`). `headers` (opzionale) simula es. il `Content-Range` di PostgREST
    con `Prefer: count=exact` sul DELETE di cleanup (§11.2)."""
    def _json():
        if payload is None:
            raise ValueError("no json")
        return payload
    return SimpleNamespace(
        status_code=status_code,
        json=_json,
        text=text if text is not None else json.dumps(payload),
        headers=headers or {},
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

def test_module_identity_max_intrusion_is_mutating():
    # M2 step 2: max_intrusion bumpato a MUTATING — la PIÙ ALTA intrusione che il
    # modulo PUÒ chiedere (§9), per il canary write (§11.2). NON cambia il
    # comportamento read-only: il canary si self-gata su ctx.max_intrusion (vedi
    # test_canary_skipped_when_max_intrusion_below_mutating).
    mod = supa.SupabaseModule()
    assert mod.name == "supabase"
    assert mod.max_intrusion is IntrusionLevel.MUTATING


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


# ════════════════════════════════════════════════════════════════════════════
# §11.2 CANARY WRITE (M2 step 2) — il PRIMO "scrivere" di Bastione (MUTATING 🔴)
# ════════════════════════════════════════════════════════════════════════════
#
# La sicurezza viene PRIMA della copertura. Tutto OFFLINE: _get/_post/_delete sono
# le UNICHE cose monkeypatchate; NESSUN target live viene mai puntato. I test degli
# INVARIANTI di sicurezza (LOCKED) vengono per primi.


# ── router con _post/_delete: instrada GET (surface+read) e cattura POST/DELETE ─

def install_canary_router(
    monkeypatch, *, schema, rows, post=None, delete=None,
):
    """Router OFFLINE che cabla i TRE confini di I/O del modulo.

    `schema`: dict OpenAPI per `<url>/rest/v1/`.
    `rows`  : nome tabella → (status, payload) per la GET RLS read.
    `post`  : nome tabella → (status, payload) per il POST canary (default 401).
    `delete`: nome tabella → esito del DELETE di cleanup. Valore o `status` (int) o
              `(status, payload)`. Il modulo invia il DELETE con
              `Prefer: return=representation` e conferma il cleanup SOLO se il body
              prova ≥1 riga rimossa: per uno `status` 2xx nudo il router restituisce
              quindi una rappresentazione di DEFAULT non vuota (`[{"id": 0}]`, =1
              riga cancellata → cleanup confermato). Per simulare il caso d'attacco
              'DELETE 2xx ma 0 righe' (RLS che filtra) passare `(204, [])`.
              Default (tabella assente): 200 + rappresentazione non vuota.

    Registra ogni chiamata in `calls` con (verbo, url[, body]). Le funzioni
    `_post`/`_delete` sono monkeypatchate: nessun host reale è mai puntato.
    """
    post = post or {}
    delete = delete or {}
    calls: list[tuple] = []

    def _delete_outcome(spec):
        """Normalizza una voce `delete` in (status, payload). Un int nudo → status
        con rappresentazione di default non vuota (prova di 1 riga rimossa)."""
        if isinstance(spec, tuple):
            return spec
        return (spec, [{"id": 0}])

    def get_router(url, headers):
        calls.append(("GET", url))
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        for tbl, (status, payload) in rows.items():
            if f"/rest/v1/{tbl}?" in url or url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return None

    def post_router(url, headers, json):
        calls.append(("POST", url, json))
        for tbl, (status, payload) in post.items():
            if url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return fake_resp(status_code=401, payload=None)  # default: INSERT protetto

    def delete_router(url, headers):
        calls.append(("DELETE", url))
        for tbl, spec in delete.items():
            if f"/rest/v1/{tbl}" in url:
                status, payload = _delete_outcome(spec)
                return fake_resp(status_code=status, payload=payload)
        # default: cleanup ok → 200 con rappresentazione non vuota (1 riga rimossa).
        return fake_resp(status_code=200, payload=[{"id": 0}])

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(supa, "_post", post_router)
    monkeypatch.setattr(supa, "_delete", delete_router)
    return calls


def mutating_ctx(*, fp=None, cfg=None):
    """RunContext MUTATING con ownership verificata su staging: il caso in cui il
    canary È autorizzato a partire (il gate runtime passa)."""
    return make_ctx(fp=fp, cfg=cfg,
                    max_intrusion=IntrusionLevel.MUTATING, ownership_verified=True)


# ── router VIA_BUNDLE per il canary: surface 401 (OpenAPI chiusa) + POST/DELETE ─

def install_via_bundle_canary_router(
    monkeypatch, *, rows, post=None, delete=None, surface_status=401,
):
    """Router OFFLINE per il path FALLBACK via_bundle (M2: canary su superficie
    SINTETICA `read_open`). La root REST risponde `surface_status` (≠200 → OpenAPI
    NON enumerabile → fallback via bundle, colonne IGNOTE → superficie sintetica
    con colonne=[]). Gli altri tre confini di I/O sono gli stessi di
    `install_canary_router`:

    `rows`  : nome tabella → (status, payload) per la GET RLS read (popola read_open
              quando 200+righe).
    `post`  : nome tabella → (status, payload) per il POST canary (default 401).
    `delete`: nome tabella → esito del DELETE di cleanup (int status o (status,
              payload)). Default: 200 + rappresentazione non vuota (1 riga rimossa)."""
    post = post or {}
    delete = delete or {}
    calls: list[tuple] = []

    def _delete_outcome(spec):
        if isinstance(spec, tuple):
            return spec
        return (spec, [{"id": 0}])

    def get_router(url, headers):
        calls.append(("GET", url))
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=surface_status, payload=None)
        for tbl, (status, payload) in rows.items():
            if f"/rest/v1/{tbl}?" in url or url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return None

    def post_router(url, headers, json):
        calls.append(("POST", url, json))
        for tbl, (status, payload) in post.items():
            if url.rstrip("/").endswith(f"/rest/v1/{tbl}"):
                return fake_resp(status_code=status, payload=payload)
        return fake_resp(status_code=401, payload=None)  # default: INSERT protetto

    def delete_router(url, headers):
        calls.append(("DELETE", url))
        for tbl, spec in delete.items():
            if f"/rest/v1/{tbl}" in url:
                status, payload = _delete_outcome(spec)
                return fake_resp(status_code=status, payload=payload)
        return fake_resp(status_code=200, payload=[{"id": 0}])

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(supa, "_post", post_router)
    monkeypatch.setattr(supa, "_delete", delete_router)
    return calls


# ── INVARIANTE 1: GATE — il canary è il self-gate su ctx.max_intrusion ──────

def test_canary_skipped_when_max_intrusion_below_mutating(monkeypatch):
    """NON-REGRESSIONE (INVARIANTE 1): con max_intrusion < MUTATING il canary è
    INTERAMENTE saltato → comportamento read-only IDENTICO a oggi. Nessun POST,
    nessun DELETE, nessun finding/posture di scrittura."""
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    posts: list = []
    monkeypatch.setattr(supa, "_post",
                        lambda url, headers, json: posts.append(url))
    monkeypatch.setattr(supa, "_delete",
                        lambda url, headers: posts.append(url))
    install_router(monkeypatch, schema=schema, rows=rows)

    # max_intrusion=READ_ONLY (default make_ctx)
    res = supa.SupabaseModule().run(make_ctx())

    # NESSUNA scrittura: _post/_delete mai chiamati
    assert posts == []
    # comportamento read-only invariato: il solito RLS_DISABLED, nessun write
    assert any(f.rule_id == "RLS_DISABLED" for f in res.findings)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    assert not any(f.rule_id.startswith("CANARY") for f in res.findings)
    assert not any(pc.check_id.startswith("POSTURE_RLS_WRITE_")
                   for pc in res.posture_checks)


def test_canary_first_action_is_authorize_mutating(monkeypatch):
    """INVARIANTE 1 (backstop): il canary chiama gate.authorize(MUTATING, ctx)
    come PRIMA azione. Verificato spiando authorize: deve essere invocato con
    MUTATING PRIMA di qualsiasi _post."""
    seen: list = []
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"clienti": (401, None)})

    import bastione.modules.supabase.module as mod_mod
    real_authorize = mod_mod.authorize

    def spy_authorize(action, ctx):
        seen.append(action)
        return real_authorize(action, ctx)

    monkeypatch.setattr(mod_mod, "authorize", spy_authorize)

    supa.SupabaseModule().run(mutating_ctx())

    # authorize è stato chiamato con MUTATING
    assert IntrusionLevel.MUTATING in seen
    # ed è stato chiamato PRIMA del primo POST (gate prima di scrivere)
    first_post = next((i for i, c in enumerate(calls) if c[0] == "POST"), None)
    assert seen, "authorize non è stato chiamato"
    assert first_post is not None


def test_canary_aborts_if_ownership_not_verified(monkeypatch):
    """INVARIANTE 1: ownership_verified=False → authorize solleva IntrusionDenied
    → il canary ABORTA (nessun POST). Il gate è l'autorità: non si scrive senza
    ownership verificata."""
    from bastione.gate import IntrusionDenied

    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows, post={"clienti": (201, None)})

    ctx = make_ctx(max_intrusion=IntrusionLevel.MUTATING, ownership_verified=False)
    with pytest.raises(IntrusionDenied):
        supa.SupabaseModule().run(ctx)

    # MAI un POST se il gate aborta
    assert not any(c[0] == "POST" for c in calls)


def test_canary_aborts_if_not_staging(monkeypatch):
    """INVARIANTE 1: environment != staging → authorize solleva IntrusionDenied →
    il canary ABORTA (nessun POST). Staging-only è LOCKED nel gate."""
    from bastione.gate import IntrusionDenied

    # cfg di produzione: ma il gate authorize(MUTATING) impone staging.
    cfg = TargetConfig(
        name="gestionale", base_url="https://prod.example",
        environment="production", ownership="owned", supabase_url=None,
        expectations=[],
    )
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows, post={"clienti": (201, None)})

    ctx = make_ctx(cfg=cfg, max_intrusion=IntrusionLevel.MUTATING,
                   ownership_verified=True)
    with pytest.raises(IntrusionDenied):
        supa.SupabaseModule().run(ctx)
    assert not any(c[0] == "POST" for c in calls)


# ── INVARIANTE 3: SUPERFICIE LIMITATA — mai blind-write su tabelle a caso ────

def test_canary_only_targets_read_open_and_matrix_insert_tables(monkeypatch):
    """INVARIANTE 3: il canary bersaglia SOLO l'unione di (a) tabelle con attesa
    anon_insert nella matrice e (b) tabelle trovate RLS-LEGGIBILI in questa run.
    Una tabella PROTETTA in lettura e NON in matrice NON viene MAI scritta."""
    # clienti: read-open (200+righe) → bersaglio per (b).
    # protetta: read-protetta (401) e NON in matrice → NON deve essere scritta.
    schema = openapi_schema(
        {"clienti": ["id", "email"], "protetta": ["id", "dato"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}]),
            "protetta": (401, None)}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"clienti": (401, None)})

    supa.SupabaseModule().run(mutating_ctx())

    post_urls = [c[1] for c in calls if c[0] == "POST"]
    # clienti (read-open) viene scritta…
    assert any(u.rstrip("/").endswith("/rest/v1/clienti") for u in post_urls)
    # …ma 'protetta' (read-protetta, non in matrice) MAI
    assert not any(u.rstrip("/").endswith("/rest/v1/protetta") for u in post_urls)


def test_canary_targets_matrix_insert_table_even_if_read_protected(monkeypatch):
    """INVARIANTE 3 (lato a): una tabella con anon_insert=True nella matrice è
    bersaglio del canary ANCHE se è read-protetta (l'owner ha opt-in al write-test).
    """
    cfg = make_cfg(expectations=[
        TableExpectation(name="inbox", anon_insert=True),
    ])
    # inbox è read-PROTETTA (401), ma in matrice con anon_insert=True
    schema = openapi_schema({"inbox": ["id", "messaggio"]})
    rows = {"inbox": (401, None)}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"inbox": (401, None)})

    supa.SupabaseModule().run(mutating_ctx(cfg=cfg))

    post_urls = [c[1] for c in calls if c[0] == "POST"]
    assert any(u.rstrip("/").endswith("/rest/v1/inbox") for u in post_urls)


# ── VIA_BUNDLE: colonne IGNOTE → scrittura cleanup-safe sulla superficie read_open ─

def test_canary_via_bundle_writes_on_read_open_surface(monkeypatch):
    """M2: nel path via_bundle (OpenAPI chiusa, colonne IGNOTE) il canary NON viene
    più saltato in cieco — scrive sulla superficie GIÀ PROVATA LEGGIBILE dall'anon
    (`read_open`) con body VUOTO ({}, soli default) e cleanup per PK. Qui la tabella
    è read-aperta → ci DEVE essere un POST verso di essa (e nessun
    CANARY_SKIPPED_NO_SCHEMA: c'è una superficie su cui testare la scrittura)."""
    fp = make_fp(discovered_tables=["clienti"])
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}  # read-open
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"clienti": (201, [{"id": 5}])}, delete={"clienti": 200})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    posts = [c for c in calls if c[0] == "POST"]
    assert any(c[1].rstrip("/").endswith("/rest/v1/clienti") for c in posts)
    # body VUOTO: senza schema colonne si inserisce coi soli default
    assert any(c[2] == {} for c in posts)
    # NON più lo skip "no schema": la superficie read-aperta è testabile
    assert not any(f.rule_id == "CANARY_SKIPPED_NO_SCHEMA" for f in res.findings)


# ── ESITO: POST protetto (401/403) → posture write passed ───────────────────

@pytest.mark.parametrize("status", [401, 403], ids=["401", "403"])
def test_canary_post_protected_yields_write_posture_passed(monkeypatch, status):
    """POST 401/403 → INSERT protetto → PostureCheck POSTURE_RLS_WRITE_<t>
    passed=True. NESSUN cleanup (niente riga scritta)."""
    schema = openapi_schema({"clienti": ["id", "email"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows, post={"clienti": (status, None)})

    res = supa.SupabaseModule().run(mutating_ctx())

    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_clienti"]
    assert len(pcs) == 1
    assert pcs[0].passed is True
    # nessun finding di scrittura aperta
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # niente DELETE: non c'è nulla da pulire
    assert not any(c[0] == "DELETE" for c in calls)


# ── ESITO: POST 201 → RLS_WRITE_OPEN + cleanup DELETE verificato ────────────

def test_canary_post_accepted_emits_write_open_and_cleans_up(monkeypatch):
    """POST 201 → RLS_WRITE_OPEN (FIRM, MUTATING). Severità HIGH di base (colonne
    non personali, non in matrice). Poi CLEANUP: DELETE chiamato E verificato
    (2xx) → nessun CANARY_CLEANUP_FAILED."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    # POST accettato: torna la rappresentazione con la PK
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 42, "testo": "__bastione_canary_."}])},
        delete={"note": 200})

    res = supa.SupabaseModule().run(mutating_ctx())

    writes = [f for f in res.findings if f.rule_id == "RLS_WRITE_OPEN"]
    assert len(writes) == 1
    f = writes[0]
    assert f.severity is Severity.HIGH
    assert f.confidence is Confidence.FIRM
    assert f.intrusion_used is IntrusionLevel.MUTATING
    assert f.remediation_ref == "RLS_WRITE_OPEN"
    assert f.owasp == ["A01:2021"]
    assert f.location.endpoint == "/rest/v1/note"
    # cleanup eseguito e verificato → nessun CANARY_CLEANUP_FAILED
    assert any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)
    # posture write FALLITO per la tabella scritta (mutua esclusione)
    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_note"]
    assert len(pcs) == 1
    assert pcs[0].passed is False


def test_canary_post_accepted_marker_uses_run_dir_name(monkeypatch, tmp_path):
    """Il marker è univoco per run: '__bastione_canary_' + run_dir.name → finisce
    nel body del POST (così la riga canary è identificabile per il cleanup)."""
    run_dir = tmp_path / "20260614T120000Z"
    run_dir.mkdir()
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 7, "testo": "m"}])}, delete={"note": 200})

    ctx = make_ctx(tmp_path=run_dir, max_intrusion=IntrusionLevel.MUTATING,
                   ownership_verified=True)
    supa.SupabaseModule().run(ctx)

    post = next(c for c in calls if c[0] == "POST")
    body = post[2]
    marker = "__bastione_canary_20260614T120000Z"
    assert marker in str(body)


# ── INVARIANTE 2: CLEANUP GARANTITO — DELETE fallito → CANARY_CLEANUP_FAILED ─

def test_canary_cleanup_failed_when_delete_not_confirmed(monkeypatch):
    """INVARIANTE 2: POST 201 ma il DELETE NON è confermato (es. 500) →
    Finding CANARY_CLEANUP_FAILED CRITICAL/FIRM con tabella + marker + istruzioni
    di DELETE manuale. MAI una riga canary non rimossa senza un finding CRITICAL."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 99, "testo": "m"}])},
        delete={"note": 500})  # cleanup NON confermato

    res = supa.SupabaseModule().run(mutating_ctx())

    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    f = failed[0]
    assert f.severity is Severity.CRITICAL
    assert f.confidence is Confidence.FIRM
    # l'evidence include tabella + marker + istruzione DELETE manuale (il marker
    # NON è un segreto: serve a permettere la rimozione manuale)
    assert "note" in f.evidence
    assert "__bastione_canary_" in f.evidence
    assert "delete" in f.evidence.lower() or "delete" in f.description.lower()
    # il DELETE è stato comunque TENTATO
    assert any(c[0] == "DELETE" for c in calls)


def test_canary_cleanup_failed_when_delete_returns_none(monkeypatch):
    """INVARIANTE 2: anche un DELETE che ritorna None (rete giù) NON è confermato
    → CANARY_CLEANUP_FAILED CRITICAL (resilienza: nessun crash, ma si segnala)."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}

    def get_router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/note" in url:
            return fake_resp(status_code=200, payload=[{"id": 1, "testo": "x"}])
        return None

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(
        supa, "_post",
        lambda url, headers, json: fake_resp(status_code=201,
                                             payload=[{"id": 5, "testo": "m"}]))
    monkeypatch.setattr(supa, "_delete", lambda url, headers: None)

    res = supa.SupabaseModule().run(mutating_ctx())

    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    assert failed[0].severity is Severity.CRITICAL


# ── DIFETTO 1 (must-fix): DELETE 2xx ma 0 righe rimosse → CANARY_CLEANUP_FAILED ─

def test_canary_cleanup_failed_when_delete_2xx_but_zero_rows(monkeypatch):
    """INVARIANTE 2 (regressione difetto 1): lo scenario d'attacco CLASSICO del
    canary write — anon con policy INSERT permissiva MA senza policy DELETE.
    Flusso: POST 201 (riga canary scritta) → il DELETE gira sotto RLS, le righe
    sono filtrate (0 cancellate) e PostgREST risponde 204 (un 2xx) con
    rappresentazione VUOTA. Lo status 2xx NON deve bastare a 'confermare' il
    cleanup: una riga canary resterebbe ORFANA sul target. Deve invece emettere
    CANARY_CLEANUP_FAILED CRITICAL con tabella + marker + istruzioni manuali."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    # POST 201 (riga scritta) MA DELETE 204 con representation = [] → 0 righe rimosse.
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 7, "testo": "m"}])},
        delete={"note": (204, [])})  # 2xx ma NESSUNA riga cancellata

    res = supa.SupabaseModule().run(mutating_ctx())

    # il DELETE è stato tentato...
    assert any(c[0] == "DELETE" for c in calls)
    # ...ma NON confermato → CANARY_CLEANUP_FAILED CRITICAL con marker e istruzioni.
    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    f = failed[0]
    assert f.severity is Severity.CRITICAL
    assert f.confidence is Confidence.FIRM
    assert "note" in f.evidence
    assert "__bastione_canary_" in f.evidence
    assert "delete" in f.evidence.lower() or "delete" in f.description.lower()


def test_canary_delete_sends_return_representation_prefer(monkeypatch):
    """REGRESSIONE difetto 1: il DELETE di cleanup DEVE chiedere a PostgREST la
    prova della rimozione → header `Prefer: return=representation` (così il body è
    l'array delle righe cancellate). Senza, lo status 2xx sarebbe l'unica 'prova'
    (insufficiente)."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    seen_headers: list = []

    def get_router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/note" in url:
            return fake_resp(status_code=200, payload=[{"id": 1, "testo": "x"}])
        return None

    def delete_router(url, headers):
        seen_headers.append(headers)
        return fake_resp(status_code=200, payload=[{"id": 7}])

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(
        supa, "_post",
        lambda url, headers, json: fake_resp(status_code=201,
                                             payload=[{"id": 7, "testo": "m"}]))
    monkeypatch.setattr(supa, "_delete", delete_router)

    supa.SupabaseModule().run(mutating_ctx())

    assert seen_headers, "il DELETE di cleanup non è stato chiamato"
    prefer = seen_headers[0].get("Prefer", "")
    assert "return=representation" in prefer


def test_canary_cleanup_confirmed_via_content_range(monkeypatch):
    """REGRESSIONE difetto 1 (lato positivo): un DELETE 2xx CON `Content-Range`
    che attesta ≥1 riga (es. '0-0/1') CONFERMA il cleanup → nessun
    CANARY_CLEANUP_FAILED, anche se il body fosse vuoto."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}

    def get_router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/note" in url:
            return fake_resp(status_code=200, payload=[{"id": 1, "testo": "x"}])
        return None

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(
        supa, "_post",
        lambda url, headers, json: fake_resp(status_code=201,
                                             payload=[{"id": 7, "testo": "m"}]))
    # 204 senza body MA Content-Range "0-0/1" → 1 riga rimossa → confermato.
    monkeypatch.setattr(
        supa, "_delete",
        lambda url, headers: fake_resp(status_code=204, payload=None,
                                       headers={"Content-Range": "0-0/1"}))

    res = supa.SupabaseModule().run(mutating_ctx())

    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)


def test_canary_cleanup_failed_via_content_range_zero(monkeypatch):
    """REGRESSIONE difetto 1: un DELETE 2xx con `Content-Range` che attesta 0 righe
    ('*/0') NON conferma → CANARY_CLEANUP_FAILED, anche con status 2xx."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}

    def get_router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/note" in url:
            return fake_resp(status_code=200, payload=[{"id": 1, "testo": "x"}])
        return None

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(
        supa, "_post",
        lambda url, headers, json: fake_resp(status_code=201,
                                             payload=[{"id": 7, "testo": "m"}]))
    monkeypatch.setattr(
        supa, "_delete",
        lambda url, headers: fake_resp(status_code=204, payload=None,
                                       headers={"Content-Range": "*/0"}))

    res = supa.SupabaseModule().run(mutating_ctx())

    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    assert failed[0].severity is Severity.CRITICAL


# ── DIFETTO 2 (must-fix): eccezione tra POST 201 e cleanup → backstop segnala ──

def test_canary_cleanup_guaranteed_in_finally_on_exception(monkeypatch):
    """INVARIANTE 2 (regressione difetto 2): se un'eccezione viene sollevata DOPO
    il POST 201 (riga già scritta) ma PRIMA del cleanup — qui simulata facendo
    fallire la costruzione del PostureCheck/Finding — il cleanup NON deve essere
    saltato. Il try/finally garantisce comunque il DELETE; se anche quello non si
    completasse, il backstop emette CANARY_CLEANUP_FAILED. In nessun caso una riga
    canary resta orfana SENZA un finding CRITICAL che la segnali."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 7, "testo": "m"}])},
        delete={"note": 200})

    # Inietta un'eccezione tra il 201 e il cleanup: la costruzione del finding
    # RLS_WRITE_OPEN solleva. Il finally deve comunque eseguire il DELETE.
    def boom(*a, **k):
        raise RuntimeError("kaboom tra POST e cleanup")

    monkeypatch.setattr(supa.SupabaseModule, "_rls_write_open_finding",
                        staticmethod(boom))

    res = supa.SupabaseModule().run(mutating_ctx())

    # Nonostante l'eccezione, il DELETE di cleanup è stato eseguito (finally).
    assert any(c[0] == "DELETE" for c in calls)
    # E NON è rimasta una riga orfana non segnalata: il DELETE 200 con
    # rappresentazione non vuota conferma il cleanup → nessuna riga persa in
    # silenzio. Soprattutto: NESSUN crash della run (l'eccezione è contenuta dal
    # bare-except per-tabella, dopo che il finally ha già rimosso la riga).
    assert res is not None


def test_canary_backstop_emits_cleanup_failed_if_exception_skips_cleanup(monkeypatch):
    """REGRESSIONE difetto 2 (backstop): se un'eccezione sfugge perfino al finally
    (qui: il cleanup stesso solleva DOPO che il POST è andato a 201), il bare-except
    di `_canary_write_test` NON deve ingoiarla in silenzio: deve emettere
    CANARY_CLEANUP_FAILED per la riga rimasta sul target (con il marker)."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 7, "testo": "m"}])},
        delete={"note": 200})

    # Il cleanup solleva (es. _delete che esplode): l'eccezione risale oltre il
    # finally fino al bare-except di _canary_write_test → deve scattare il backstop.
    def boom_cleanup(*a, **k):
        raise RuntimeError("kaboom nel cleanup")

    monkeypatch.setattr(supa.SupabaseModule, "_canary_cleanup", boom_cleanup)

    res = supa.SupabaseModule().run(mutating_ctx())

    # il POST 201 è avvenuto (riga scritta)...
    assert any(c[0] == "POST" for c in calls)
    # ...e il backstop ha emesso CANARY_CLEANUP_FAILED con il marker (riga orfana
    # segnalata, MAI silenziata).
    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    f = failed[0]
    assert f.severity is Severity.CRITICAL
    assert "note" in f.evidence
    assert "__bastione_canary_" in f.evidence


# ── ESITO: POST 4xx schema/constraint → RLS_WRITE_OPEN TENTATIVE, no DELETE ──

@pytest.mark.parametrize("status", [400, 409, 422], ids=["400", "409", "422"])
def test_canary_post_4xx_schema_is_tentative_no_cleanup(monkeypatch, status):
    """POST 4xx schema/constraint (400/409/422): la richiesta ha SUPERATO il layer
    RLS ma è stata respinta dallo schema → RLS_WRITE_OPEN confidence TENTATIVE,
    nota 'nessuna riga scritta'. NIENTE da pulire → nessun DELETE."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows, post={"note": (status, None)})

    res = supa.SupabaseModule().run(mutating_ctx())

    writes = [f for f in res.findings if f.rule_id == "RLS_WRITE_OPEN"]
    assert len(writes) == 1
    assert writes[0].confidence is Confidence.TENTATIVE
    assert "nessuna riga" in writes[0].description.lower()
    # nessuna riga scritta → nessun cleanup
    assert not any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)


def test_canary_4xx_matrix_conformance_anon_insert_true_suppressed(monkeypatch):
    """ORACOLO §15 coerente sul ramo 4xx (regressione): se anon_insert=True la
    scrittura è ATTESA by design → CONFORME anche quando l'INSERT viene respinto
    dallo schema (4xx). Posture POSTURE_RLS_WRITE_<t> passed=True, NESSUN
    RLS_WRITE_OPEN. La posture non deve dipendere dall'esito 201-vs-4xx."""
    cfg = make_cfg(expectations=[
        TableExpectation(name="note", anon_insert=True),
    ])
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows, post={"note": (400, None)})

    res = supa.SupabaseModule().run(mutating_ctx(cfg=cfg))

    # conforme: nessun RLS_WRITE_OPEN, posture write passed=True che cita §15
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    pw = [p for p in res.posture_checks if p.check_id == "POSTURE_RLS_WRITE_note"]
    assert len(pw) == 1 and pw[0].passed is True
    assert "§15" in pw[0].detail
    # nessuna riga scritta (4xx) → nessun DELETE
    assert not any(c[0] == "DELETE" for c in calls)


# ── ESITO: POST None/altro → INFO inconcludente (resilienza), nessuna scrittura ─

def test_canary_post_none_is_inconclusive_no_write(monkeypatch):
    """POST None (rete giù) → INFO inconcludente, nessuna scrittura, nessun
    cleanup, nessun crash (resilienza P8)."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}

    def get_router(url, headers):
        if url.rstrip("/").endswith("/rest/v1"):
            return fake_resp(status_code=200, payload=schema)
        if "/rest/v1/note" in url:
            return fake_resp(status_code=200, payload=[{"id": 1, "testo": "x"}])
        return None

    monkeypatch.setattr(supa, "_get", get_router)
    monkeypatch.setattr(supa, "_post", lambda url, headers, json: None)
    deletes: list = []
    monkeypatch.setattr(supa, "_delete",
                        lambda url, headers: deletes.append(url))

    res = supa.SupabaseModule().run(mutating_ctx())

    # nessun RLS_WRITE_OPEN (esito inconcludente), nessun cleanup
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    assert deletes == []


# ── ORACOLO per le SCRITTURE (§15): anon_insert ─────────────────────────────

def test_canary_matrix_violation_anon_insert_false_is_critical(monkeypatch):
    """ORACOLO §15: anon_insert=False (scrittura NON attesa) ma il POST è accettato
    (201) → VIOLAZIONE → CRITICAL + nota 'viola la matrice (§15)'. Cleanup eseguito."""
    cfg = make_cfg(expectations=[
        TableExpectation(name="ordini", anon_insert=False),
    ])
    schema = openapi_schema({"ordini": ["id", "codice"]})
    rows = {"ordini": (200, [{"id": 1, "codice": "A"}])}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"ordini": (201, [{"id": 1, "codice": "A"}])}, delete={"ordini": 200})

    res = supa.SupabaseModule().run(mutating_ctx(cfg=cfg))

    writes = [f for f in res.findings if f.rule_id == "RLS_WRITE_OPEN"]
    assert len(writes) == 1
    f = writes[0]
    assert f.severity is Severity.CRITICAL
    assert "matrice" in f.description.lower()
    assert "§15" in f.description
    # cleanup comunque eseguito
    assert any(c[0] == "DELETE" for c in calls)


def test_canary_matrix_conformance_anon_insert_true_suppresses_but_cleans(monkeypatch):
    """ORACOLO §15: anon_insert=True (scrittura ATTESA by design) → CONFORME:
    RLS_WRITE_OPEN SOPPRESSO, PostureCheck POSTURE_RLS_WRITE_<t> passed=True che
    cita §15. MA il cleanup va eseguito comunque (la riga canary va rimossa)."""
    cfg = make_cfg(expectations=[
        TableExpectation(name="contatti", anon_insert=True),
    ])
    schema = openapi_schema({"contatti": ["id", "messaggio"]})
    # contatti read-protetta (401): bersaglio del canary per la matrice (lato a)
    rows = {"contatti": (401, None)}
    calls = install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"contatti": (201, [{"id": 3, "messaggio": "m"}])},
        delete={"contatti": 200})

    res = supa.SupabaseModule().run(mutating_ctx(cfg=cfg))

    # RLS_WRITE_OPEN SOPPRESSO (conforme)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # PostureCheck write passed=True che cita §15
    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_contatti"]
    assert len(pcs) == 1
    assert pcs[0].passed is True
    assert "§15" in pcs[0].detail
    # ma la riga canary è stata comunque RIMOSSA (cleanup eseguito)
    assert any(c[0] == "DELETE" for c in calls)
    # nessun CANARY_CLEANUP_FAILED (cleanup ok)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)


def test_canary_personal_columns_accepted_is_critical(monkeypatch):
    """ORACOLO §15 (assente): senza attesa in matrice, severità di base HIGH MA
    CRITICAL se le colonne sono personali (le scritture su dati personali sono più
    gravi)."""
    schema = openapi_schema({"clienti": ["id", "email", "nome"]})
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it", "nome": "Mario"}])}
    install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"clienti": (201, [{"id": 1, "email": "x@y.it", "nome": "Mario"}])},
        delete={"clienti": 200})

    res = supa.SupabaseModule().run(mutating_ctx())

    writes = [f for f in res.findings if f.rule_id == "RLS_WRITE_OPEN"]
    assert len(writes) == 1
    assert writes[0].severity is Severity.CRITICAL


# ════════════════════════════════════════════════════════════════════════════
# CANARY VIA_BUNDLE (M2) — canary write ABILITATO sulla superficie SINTETICA
# read_open quando l'OpenAPI è chiusa (caso reale: il Supabase hosted moderno
# blocca GET /rest/v1/ all'anon). Colonne IGNOTE → body {} (soli default),
# cleanup per PK dalla rappresentazione. Tutto OFFLINE: _get/_post/_delete
# monkeypatchati. Le 5 INVARIANTI §11.2 restano LOCKED.
# ════════════════════════════════════════════════════════════════════════════


def test_canary_via_bundle_read_open_post_201_writes_and_cleans(monkeypatch):
    """VIA_BUNDLE + read_open={'canary'} + MUTATING + POST 201 (rappresentazione
    con PK) + DELETE conferma 1 riga → Finding RLS_WRITE_OPEN (written=True) su
    'canary', cleanup CONFERMATO (NESSUN CANARY_CLEANUP_FAILED). NON più
    CANARY_SKIPPED_NO_SCHEMA: la scrittura sulla superficie read-aperta è ora
    eseguita anche senza schema colonne (body {} = soli default)."""
    fp = make_fp(discovered_tables=["canary"])
    rows = {"canary": (200, [{"id": 1, "x": 1}])}  # read-open → entra in read_open
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"canary": (201, [{"id": 42}])},  # rappresentazione con PK
        delete={"canary": 200})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    # il POST è stato eseguito sulla tabella read-aperta, con body VUOTO ({})
    posts = [c for c in calls if c[0] == "POST"]
    assert any(c[1].rstrip("/").endswith("/rest/v1/canary") for c in posts)
    assert any(c[2] == {} for c in posts), "body del POST via_bundle deve essere {}"
    # RLS_WRITE_OPEN written=True (FIRM, MUTATING) su 'canary'
    writes = [f for f in res.findings if f.rule_id == "RLS_WRITE_OPEN"]
    assert len(writes) == 1
    f = writes[0]
    assert f.confidence is Confidence.FIRM
    assert f.intrusion_used is IntrusionLevel.MUTATING
    assert f.location.endpoint == "/rest/v1/canary"
    # cleanup CONFERMATO (DELETE chiamato + 1 riga rimossa) → nessun fallimento
    assert any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)
    # NON c'è più lo skip "no schema" su questa superficie
    assert not any(f.rule_id == "CANARY_SKIPPED_NO_SCHEMA" for f in res.findings)


def test_canary_via_bundle_201_no_pk_col_none_is_cleanup_failed(monkeypatch):
    """PUNTO DI SICUREZZA CRITICO: VIA_BUNDLE → col=None (colonne ignote). POST 201
    ma la rappresentazione NON contiene una PK utilizzabile → non è costruibile né
    un DELETE per PK né un filtro `?col=eq.marker` mirato → la verifica DEVE
    risolvere in CANARY_CLEANUP_FAILED (CRITICAL), MAI un successo silenzioso, MAI
    una riga orfana. Qui il DELETE 'ultima spiaggia' (?marker=eq.…) non rimuove
    nulla (la colonna non esiste / 0 righe) → non confermato → CRITICAL."""
    fp = make_fp(discovered_tables=["canary"])
    rows = {"canary": (200, [{"id": 1, "x": 1}])}
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"canary": (201, [])},          # 201 SENZA PK nella rappresentazione
        delete={"canary": (204, [])})        # il DELETE non rimuove nulla (0 righe)

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    # il POST è avvenuto (riga canary scritta) e il DELETE è stato TENTATO…
    assert any(c[0] == "POST" for c in calls)
    assert any(c[0] == "DELETE" for c in calls)
    # …ma il cleanup NON è confermato → CANARY_CLEANUP_FAILED CRITICAL con marker.
    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    f = failed[0]
    assert f.severity is Severity.CRITICAL
    assert f.confidence is Confidence.FIRM
    assert "canary" in f.evidence
    assert "__bastione_canary_" in f.evidence
    # nessun successo silenzioso: la riga orfana è SEGNALATA, non taciuta.


def test_canary_via_bundle_delete_2xx_zero_rows_is_cleanup_failed(monkeypatch):
    """VIA_BUNDLE + POST 201 (con PK) ma DELETE 2xx con 0 righe rimosse (RLS che
    filtra il DELETE) → CANARY_CLEANUP_FAILED: lo status 2xx da solo NON conferma,
    la riga canary resterebbe orfana (invariante 2)."""
    fp = make_fp(discovered_tables=["canary"])
    rows = {"canary": (200, [{"id": 1, "x": 1}])}
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"canary": (201, [{"id": 7}])},  # PK presente → DELETE per id
        delete={"canary": (204, [])})         # 2xx ma 0 righe rimosse

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    assert any(c[0] == "DELETE" for c in calls)
    failed = [f for f in res.findings if f.rule_id == "CANARY_CLEANUP_FAILED"]
    assert len(failed) == 1
    assert failed[0].severity is Severity.CRITICAL
    assert "__bastione_canary_" in failed[0].evidence


def test_canary_via_bundle_post_protected_no_finding_no_cleanup(monkeypatch):
    """VIA_BUNDLE + POST 401/403 → INSERT protetto → posture write 'protected'
    passed=True, NESSUN finding di scrittura, NESSUN cleanup (niente riga scritta)."""
    fp = make_fp(discovered_tables=["canary"])
    rows = {"canary": (200, [{"id": 1, "x": 1}])}
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows, post={"canary": (403, None)})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_canary"]
    assert len(pcs) == 1
    assert pcs[0].passed is True
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # niente da pulire → nessun DELETE
    assert not any(c[0] == "DELETE" for c in calls)


def test_canary_via_bundle_empty_read_open_no_write_honest_signal(monkeypatch):
    """VIA_BUNDLE con read_open VUOTO (nessuna tabella anon-leggibile): NESSUNA
    scrittura (nessun POST), e UN segnale ONESTO nel nuovo significato — non
    'nessuno schema' ma 'nessuna tabella anon-leggibile su cui testare la
    scrittura'."""
    fp = make_fp(discovered_tables=["protetta"])
    rows = {"protetta": (401, None)}  # NON read-open → read_open resta vuoto
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows, post={"protetta": (201, [{"id": 1}])})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp))

    # NESSUNA scrittura: nessuna tabella read-aperta su cui agire
    assert not any(c[0] == "POST" for c in calls)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # segnale onesto nel NUOVO significato: niente "no schema", ma "nessuna tabella
    # anon-leggibile su cui testare la scrittura".
    skip = [f for f in res.findings if f.rule_id == "CANARY_SKIPPED_NO_SCHEMA"]
    assert len(skip) == 1
    msg = (skip[0].description + " " + skip[0].evidence).lower()
    assert "legg" in msg  # "leggibile"/"anon-leggibile": il NUOVO significato onesto


def test_canary_via_bundle_read_only_run_skips_canary_entirely(monkeypatch):
    """NON-REGRESSIONE (self-gate, INVARIANTE 1): VIA_BUNDLE ma run READ-ONLY (non
    MUTATING) → il canary è INTERAMENTE saltato: nessun POST, nessun DELETE, nessun
    finding/posture di scrittura, nessun CANARY_*."""
    fp = make_fp(discovered_tables=["canary"])
    rows = {"canary": (200, [{"id": 1, "x": 1}])}
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows, post={"canary": (201, [{"id": 1}])})

    # max_intrusion=READ_ONLY (default make_ctx) → self-gate chiude il canary
    res = supa.SupabaseModule().run(make_ctx(fp=fp))

    assert not any(c[0] == "POST" for c in calls)
    assert not any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    assert not any(f.rule_id.startswith("CANARY") for f in res.findings)
    assert not any(pc.check_id.startswith("POSTURE_RLS_WRITE_")
                   for pc in res.posture_checks)


def test_canary_via_bundle_matrix_anon_insert_true_suppressed(monkeypatch):
    """ORACOLO §15: VIA_BUNDLE + read_open={'t'} + cfg dichiara anon_insert=True per
    't' + POST 201 → finding RLS_WRITE_OPEN SOPPRESSO, posture write 'expected'
    (passed=True) conforme a §15. Il cleanup va comunque eseguito (riga rimossa)."""
    cfg = make_cfg(expectations=[TableExpectation(name="t", anon_insert=True)])
    fp = make_fp(discovered_tables=["t"])
    rows = {"t": (200, [{"id": 1, "x": 1}])}  # read-open
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"t": (201, [{"id": 9}])}, delete={"t": 200})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp, cfg=cfg))

    # finding di scrittura SOPPRESSO (scrittura ATTESA by design)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # posture write 'expected' passed=True che cita §15
    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_t"]
    assert len(pcs) == 1
    assert pcs[0].passed is True
    assert "§15" in pcs[0].detail
    # la riga canary è comunque stata rimossa → nessun cleanup fallito
    assert any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)


def test_canary_via_bundle_matrix_insert_read_protected_is_write_tested(monkeypatch):
    """REGRESSIONE (INVARIANTE 3, ramo a, gap LOW chiuso): nel path VIA_BUNDLE una
    tabella con anon_insert=True nella matrice §15 (opt-in ESPLICITO dell'owner al
    write-test) DEVE essere write-testata ANCHE se è read-PROTETTA — esattamente
    come nel path OpenAPI (test_canary_targets_matrix_insert_table_even_if_read_
    protected). Prima del fix la superficie sintetica era {t: [] for t in read_open}:
    le sue chiavi erano ESATTAMENTE read_open, quindi `_canary_targets` (che interseca
    `(read_open|matrix_insert) & schema`) eliminava ogni tabella matrice NON read-
    aperta → l'opt-in read-protetto spariva SENZA segnale onesto specifico (lo skip
    'no schema' scatta solo a read_open interamente vuoto). 'pub' read-aperta NON
    deve mascherare il gap: read_open è non-vuoto e il ramo (a) era disabilitato."""
    cfg = make_cfg(expectations=[
        TableExpectation(name="inbox", anon_insert=True),
    ])
    # inbox e pub scoperte dal bundle; inbox è read-PROTETTA (401), pub read-aperta.
    fp = make_fp(discovered_tables=["inbox", "pub"])
    rows = {"inbox": (401, None), "pub": (200, [{"id": 1}])}
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        # inbox: write APERTA (201) → opt-in conforme; pub: write protetta (401).
        post={"inbox": (201, [{"id": 5}]), "pub": (401, None)},
        delete={"inbox": 200})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp, cfg=cfg))

    # il POST su 'inbox' (matrice opt-in, read-protetta) È stato eseguito (ramo a)…
    post_urls = [c[1] for c in calls if c[0] == "POST"]
    assert any(u.rstrip("/").endswith("/rest/v1/inbox") for u in post_urls), \
        "la tabella matrice anon_insert=True read-protetta DEVE essere write-testata"
    # …con body VUOTO ({}, colonne ignote) come tutta la superficie via_bundle.
    inbox_posts = [c for c in calls
                   if c[0] == "POST" and c[1].rstrip("/").endswith("/rest/v1/inbox")]
    assert all(c[2] == {} for c in inbox_posts)
    # anon_insert=True → scrittura ATTESA by design → finding SOPPRESSO, posture
    # write 'expected' passed=True (oracolo §15), e la riga canary è stata rimossa.
    assert not any(f.rule_id == "RLS_WRITE_OPEN"
                   and f.location.endpoint == "/rest/v1/inbox"
                   for f in res.findings)
    pcs = [pc for pc in res.posture_checks
           if pc.check_id == "POSTURE_RLS_WRITE_inbox"]
    assert len(pcs) == 1 and pcs[0].passed is True
    assert any(c[0] == "DELETE" for c in calls)
    assert not any(f.rule_id == "CANARY_CLEANUP_FAILED" for f in res.findings)
    # NON c'è lo skip onesto: read_open era non-vuoto E il ramo (a) NON è più muto.
    assert not any(f.rule_id == "CANARY_SKIPPED_NO_SCHEMA" for f in res.findings)


def test_canary_via_bundle_matrix_insert_not_discovered_is_not_targeted(monkeypatch):
    """INVARIANTE 3 (mai blind-write): una tabella con anon_insert=True nella matrice
    ma NON presente tra le tabelle scoperte dal bundle (`discovered`) NON è
    bersagliata — non c'è alcuna superficie reale enumerata da sondare. Il ramo (a)
    è limitato a `matrix_insert & discovered`. Con read_open vuoto e nessuna tabella
    matrice scoperta, NON si scrive: skip ONESTO."""
    cfg = make_cfg(expectations=[
        TableExpectation(name="fantasma", anon_insert=True),  # NON in discovered
    ])
    fp = make_fp(discovered_tables=["protetta"])
    rows = {"protetta": (401, None)}  # read-protetta → read_open vuoto
    calls = install_via_bundle_canary_router(
        monkeypatch, rows=rows,
        post={"fantasma": (201, [{"id": 1}]), "protetta": (201, [{"id": 1}])})

    res = supa.SupabaseModule().run(mutating_ctx(fp=fp, cfg=cfg))

    # nessun POST: 'fantasma' non scoperta (no surface), 'protetta' non in matrice
    # e read-protetta → nessun bersaglio.
    assert not any(c[0] == "POST" for c in calls)
    assert not any(f.rule_id == "RLS_WRITE_OPEN" for f in res.findings)
    # con superficie write VUOTA (né ramo a né ramo b) il segnale onesto scatta.
    skip = [f for f in res.findings if f.rule_id == "CANARY_SKIPPED_NO_SCHEMA"]
    assert len(skip) == 1


# ── evidence redatta (P8): il POST non perde i valori delle righe ───────────

def test_canary_evidence_does_not_leak_anon_key(monkeypatch):
    """P8: nessuna chiave/segreto nelle evidence dei finding canary."""
    schema = openapi_schema({"note": ["id", "testo"]})
    rows = {"note": (200, [{"id": 1, "testo": "x"}])}
    install_canary_router(
        monkeypatch, schema=schema, rows=rows,
        post={"note": (201, [{"id": 1, "testo": "m"}])}, delete={"note": 500})

    res = supa.SupabaseModule().run(mutating_ctx())

    for f in res.findings:
        assert ANON not in f.evidence


# ── _post/_delete degradano a None senza httpx (confine I/O) ────────────────

def test_post_returns_none_without_httpx(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert supa._post(f"{SUPA_URL}/rest/v1/note", {"apikey": ANON}, {"a": 1}) is None
    assert supa._delete(f"{SUPA_URL}/rest/v1/note", {"apikey": ANON}) is None


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


# ─── §15 MODO ORACOLO: consumo della matrice di attese (M2 step 1) ───────────
#
# La matrice di attese (§15) chiude gli ambigui da sola: un risultato che VIOLA
# un'attesa sale di severità (→ CRITICAL, criterio LOCKED §11.1.2); un risultato
# CONFORME (tabella pubblica per scelta) viene DECLASSATO/SOPPRESSO (niente
# Finding RLS_DISABLED, solo un PostureCheck passed=True onesto).
# In questo step si consuma SOLO `anon_select` (sul RLS READ test); `anon_insert`
# sarà consumato dal canary §11.2 in M2 step 2.

# ── helper puro `_expectation_for(table, cfg)` ──────────────────────────────

def test_expectation_for_matches_by_name_case_sensitive():
    # match per nome tabella, case-sensitive come PostgREST
    cfg = make_cfg(expectations=[
        TableExpectation(name="clienti", anon_select=False),
        TableExpectation(name="listino_pubblico", anon_select=True),
    ])
    exp = supa._expectation_for("clienti", cfg)
    assert exp is not None and exp.name == "clienti" and exp.anon_select is False
    pub = supa._expectation_for("listino_pubblico", cfg)
    assert pub is not None and pub.anon_select is True
    # case-sensitive: "Clienti" ≠ "clienti" → None
    assert supa._expectation_for("Clienti", cfg) is None
    # tabella non in matrice → None
    assert supa._expectation_for("ordini", cfg) is None


def test_expectation_for_none_when_no_expectations():
    # nessuna matrice → sempre None (modo adversario, comportamento invariato)
    assert supa._expectation_for("clienti", make_cfg()) is None


# ── VIOLAZIONE: anon_select=False ESPOSTA → CRITICAL + nota matrice ──────────

def test_matrix_violation_anon_select_false_is_critical(monkeypatch):
    # il proprietario ha dichiarato anon_select=False ma l'anon LEGGE: VIOLAZIONE.
    # Severità → CRITICAL (criterio LOCKED §11.1.2), confidence resta FIRM, la
    # description NOTA esplicitamente che viola la matrice di attese (§15).
    cfg = make_cfg(expectations=[
        TableExpectation(name="ordini", anon_select=False),
    ])
    # colonne NON personali: senza la matrice sarebbe HIGH; la violazione → CRITICAL
    schema = openapi_schema({"ordini": ["id", "codice", "totale"]})
    rows = {"ordini": (200, [{"id": 1, "codice": "A", "totale": 9}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(cfg=cfg))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.confidence is Confidence.FIRM
    # gdpr_relevant NON forzato: la violazione di matrice non implica dati personali
    assert f.gdpr_relevant is False
    # la description cita la matrice di attese (§15)
    assert "matrice" in f.description.lower()
    assert "§15" in f.description
    # PostureCheck fallito allineato sulla stessa severità (peso 8)
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_ordini"]
    assert len(pcs) == 1
    assert pcs[0].passed is False
    assert pcs[0].severity_if_failed is Severity.CRITICAL


# ── CONFORMITÀ: anon_select=True ESPOSTA → finding SOPPRESSO, posture pass ───

def test_matrix_conformance_anon_select_true_suppresses_finding(monkeypatch):
    # tabella pubblica BY DESIGN (es. listino_pubblico): la lettura anon è ATTESA
    # → NON emettere il Finding RLS_DISABLED; emettere POSTURE_RLS_<t> passed=True
    # con detail che dichiara la conformità alla matrice (§15).
    cfg = make_cfg(expectations=[
        TableExpectation(name="listino_pubblico", anon_select=True),
    ])
    schema = openapi_schema({"listino_pubblico": ["id", "prezzo"]})
    rows = {"listino_pubblico": (200, [{"id": 1, "prezzo": 9}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(cfg=cfg))

    # NESSUN Finding RLS_DISABLED (soppresso/declassato)
    assert not [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    # PostureCheck POSTURE_RLS_<t> passed=True (lo score resta onesto)
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_listino_pubblico"]
    assert len(pcs) == 1
    pc = pcs[0]
    assert pc.passed is True
    # il detail dichiara che la lettura anon è ATTESA dalla matrice (§15)
    assert "§15" in pc.detail
    assert "attes" in pc.detail.lower() or "pubblica" in pc.detail.lower()
    # mutua esclusione: nessun posture fallito per la stessa tabella
    assert not any(not p.passed for p in res.posture_checks)


def test_matrix_conformance_does_not_lower_posture_score(monkeypatch):
    # una tabella pubblica per scelta (conforme) NON deve abbassare lo score:
    # lo score resta onesto (non è un fallimento).
    from bastione.posture.checks import posture_score

    cfg = make_cfg(expectations=[
        TableExpectation(name="listino_pubblico", anon_select=True),
    ])
    schema = openapi_schema({"listino_pubblico": ["id", "prezzo"]})
    rows = {"listino_pubblico": (200, [{"id": 1, "prezzo": 9}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(cfg=cfg))

    assert posture_score(res.posture_checks) == 100.0


# ── tabella NON in matrice ESPOSTA → comportamento ATTUALE invariato ─────────

def test_table_not_in_matrix_keeps_adversary_behaviour_high(monkeypatch):
    # con matrice ma SENZA voce per questa tabella → exp None → modo adversario:
    # colonne non personali → HIGH (comportamento invariato).
    cfg = make_cfg(expectations=[
        TableExpectation(name="altra_tabella", anon_select=False),
    ])
    schema = openapi_schema({"listino": ["id", "codice", "prezzo"]})
    rows = {"listino": (200, [{"id": 1, "codice": "A", "prezzo": 9}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(cfg=cfg))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].gdpr_relevant is False
    # nessun riferimento alla matrice nella description (exp None)
    assert "matrice di attese" not in findings[0].description.lower()


def test_table_not_in_matrix_personal_columns_stay_critical(monkeypatch):
    # con matrice ma SENZA voce per questa tabella → exp None → euristica colonne:
    # colonne personali → CRITICAL + gdpr (comportamento invariato).
    cfg = make_cfg(expectations=[
        TableExpectation(name="altra_tabella", anon_select=False),
    ])
    schema = openapi_schema({"clienti": ["id", "nome", "email"]})
    rows = {"clienti": (200, [{"id": 1, "nome": "Mario", "email": "m@x.it"}])}
    install_router(monkeypatch, schema=schema, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(cfg=cfg))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].gdpr_relevant is True


# ── VIA BUNDLE: la matrice si applica anche senza colonne (per nome) ─────────

def test_via_bundle_matrix_violation_is_critical(monkeypatch):
    # OpenAPI chiusa (401) → fallback via bundle (colonne ignote). La matrice dà
    # comunque ground-truth per nome: anon_select=False + esposta → CRITICAL,
    # NONOSTANTE columns=[] (qui l'oracolo dà più valore: niente euristica colonne).
    cfg = make_cfg(expectations=[
        TableExpectation(name="clienti", anon_select=False),
    ])
    fp = make_fp(discovered_tables=["clienti"])
    rows = {"clienti": (200, [{"id": 1, "email": "x@y.it"}])}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp, cfg=cfg))

    findings = [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    assert len(findings) == 1
    f = findings[0]
    # CRITICAL per violazione di matrice, anche senza colonne note
    assert f.severity is Severity.CRITICAL
    assert "matrice" in f.description.lower()
    assert "§15" in f.description
    # PostureCheck fallito allineato (peso 8)
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_clienti"]
    assert len(pcs) == 1
    assert pcs[0].passed is False
    assert pcs[0].severity_if_failed is Severity.CRITICAL


def test_via_bundle_matrix_conformance_suppresses_finding(monkeypatch):
    # OpenAPI chiusa (401) → fallback via bundle. Tabella pubblica per scelta
    # (anon_select=True) esposta → finding SOPPRESSO, POSTURE_RLS_<t> passed=True.
    cfg = make_cfg(expectations=[
        TableExpectation(name="listino_pubblico", anon_select=True),
    ])
    fp = make_fp(discovered_tables=["listino_pubblico"])
    rows = {"listino_pubblico": (200, [{"id": 1, "prezzo": 9}])}
    install_fallback_router(monkeypatch, surface_status=401, rows=rows)

    res = supa.SupabaseModule().run(make_ctx(fp=fp, cfg=cfg))

    # NESSUN Finding RLS_DISABLED (conforme alla matrice)
    assert not [f for f in res.findings if f.rule_id == "RLS_DISABLED"]
    pcs = [pc for pc in res.posture_checks if pc.check_id == "POSTURE_RLS_listino_pubblico"]
    assert len(pcs) == 1
    assert pcs[0].passed is True
    assert "§15" in pcs[0].detail
    # il finding onesto di copertura parziale resta (enumerazione via bundle)
    assert any(f.rule_id == "SUPABASE_SCHEMA_VIA_BUNDLE" for f in res.findings)
