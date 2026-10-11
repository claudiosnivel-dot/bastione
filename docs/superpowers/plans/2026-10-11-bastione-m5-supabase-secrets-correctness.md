# Bastione M5 — Supabase 2026 + segreti + correttezza — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Esecuzione in Bastione (LOCKED, `BASTIONE-WORKFLOWS.md`):** lo sviluppo è **workflow-first** — **UN** dynamic workflow per milestone (strumento `Workflow`), orchestrato dalla sessione Claude Code su **Opus 4.8**. I **builder NON eseguono git**: lasciano le modifiche nel working tree; lo step **"Commit" di ogni task lo esegue l'ORCHESTRATORE** dopo il ground-truth `python -m pytest -q` + **blind-review adversariale** (k dimensioni: *correctness · sicurezza/P8/gate · robustezza*). Builder che editano lo **stesso file** vanno **sequenziati** (ownership di file); i **fixer** idem (lezione S10). Model policy §5: **verifier/fixer/orchestratore = Opus 4.8 SEMPRE**; builder = **Opus** per logica delicata (gate, Supabase RLS/RPC/canary, secret-liveness, `agent_bundle`, `toolcheck`), **Sonnet** per task meccanici (colla attorno ai binari, docs/yaml, form/report). **Niente Haiku.**

**Goal:** Riportare la verifica Supabase alla realtà 2026 (chiavi `sb_publishable_`/`sb_secret_`, semantica GRANT dal 30/10/2026), chiudere il catalogo segreti, rendere oneste le corsie M4 (`zap_active`, `idor`), mettere in sicurezza la supply-chain dei tool e ricongiungere ogni finding/posture a una remediation verificabile — **owned-only, by code, READ_ONLY di default**.

**Architecture:** Estensione dei sottosistemi esistenti senza nuovi paradigmi. Il recon (§8) riconosce la chiave pubblica in **entrambi** i formati; il modulo `supabase` (§11) delega a **quattro nuovi sottofili isolati** (`storage.py`, `rpc.py`, `auth_posture.py`, `graphql.py`), ognuno col proprio confine I/O monkeypatchabile, orchestrati da `module.py`. I segreti sono **detector drop-in** (§10, pattern `@register_detector`). Un nuovo `toolcheck.py` (fail-closed) fa da gate di versione per i wrapper dei tool. `agent_bundle` consuma anche i **PostureCheck falliti**. Tutto è testato **offline** (confini I/O monkeypatchati, nessun target live) con **app sintetiche in due varianti** (protetta / non protetta) e gate-test a richieste-zero.

**Tech Stack:** Python 3.14 (floor 3.11), Pydantic v2, typer + rich (CLI), httpx (I/O opzionale/degradabile), Jinja2 (playbook/report), pytest. **NO uv** (assente in locale): i test si lanciano con **`python -m pytest -q`** (Windows). Lockfile Python via **pip-tools** (`pip-compile --generate-hashes`), vedi Task 17.

**Spec:** `docs/superpowers/specs/2026-10-11-bastione-m5-m9-design.md` (§4 è M5, dettagliata; D1–D8, R1–R7 LOCKED). Il piano argomenta dalla spec: tenerla accanto durante l'esecuzione. Allineato a `BASTIONE-BLUEPRINT-v2.md` (§5–§18-bis, §26–§27) e `BASTIONE-WORKFLOWS.md`.

## Global Constraints

Valori copiati verbatim dalla spec; valgono per **ogni** task (guardrail §4.0, iniettati in ogni prompt builder/fixer).

- **Produzione = blocco assoluto. Owned-only. READ_ONLY di default.** (§4.0.1)
- **Livelli di intrusione (R1/§4.0.2):** READ_ONLY = recon, riconoscimento chiavi, semantica accesso, `GET /auth/v1/settings`, JWKS. PROBE = storage list, RPC in GET, introspezione GraphQL, liveness dei segreti, nuovi path `server_exposure`. MUTATING = invariato (solo canary §11.2, `idor` WRITE, `zap_active`). **Nessuna scrittura NUOVA in M5.** (§4.0.3)
- **Gate-first (§4.0.7):** ogni azione PROBE fa self-gate `max_intrusion ≥ PROBE ∧ ownership_verified` **più** `authorize(PROBE, ctx)` come backstop. Il gate **aborta, non declassa** (`IntrusionDenied` propaga).
- **P8 (§4.0.4):** mai segreti, token, valori di righe, **nomi di oggetti dello storage** o body sensibili in un campo del `Finding`/log/repr. Solo metadati: endpoint, regola, conteggi, **nomi di colonna**, esito.
- **Segreti di configurazione via ENV, mai nel TOML (R3):** la config porta i **nomi** delle env var; i valori si leggono a runtime (`os.getenv`, pattern `notify/telegram.py`). Token API in sola lettura, scope minimo, redatti (P8).
- **Resilienza (§4.0.6/§4.7):** un confine I/O che fallisce o un tool assente → `*_SKIPPED` / INFO, **mai** un crash. Onestà, mai silenzio (R6): ogni "non determinabile" è un finding **INFO** esplicito.
- **Oracle-first (R7):** signup aperto, sign-in anonimo, bucket elencabili, RPC pubbliche → **finding solo se violano un'attesa dichiarata** nel TOML; senza attesa, **INFO "da dichiarare"**; soppressione solo con dichiarazione esplicita (come §15).
- **I sub-agenti NON eseguono git** e toccano **solo** i file del loro task (§4.0.8).
- **`finding_id` LOCKED (§16):** `sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]` — la helper `_finding_id` locale di ogni modulo. `check_id` stabili (§17). Pesi del posture score invariati.
- **Testabilità offline (§4.10):** confini I/O monkeypatchati; nessun target live; app sintetiche protetta/non-protetta; gate-test a richieste-zero; P8-test con valori sentinella. Ground-truth = l'orchestratore rilancia `python -m pytest -q`.

## Review Focus

Classi di input/failure che la spec implica ma che è facile lasciare scoperte — le più probabili prima. Ogni riga ha già il suo test nel task indicato.

1. **Chiave pubblica attacker-controllabile che sposta l'host fuori da `*.supabase.co`.** Un `sb_publishable_…` o un `ref` artefatto nel bundle non deve mai far puntare una probe a un host non-owned (SSRF/owned-only §7). Come per `service_role` (`_SUPABASE_REF_RE`), il formato della chiave/URL va validato prima di qualunque I/O. → **Task 3** (recon) e **Task 21** (core) pinano un test con chiave/URL malformati → nessuna probe fuori host.
2. **RPC con effetti esterni invocata nonostante sia in GET.** La garanzia vera è la transazione READ ONLY di PostgREST (una scrittura → 405/SQLSTATE 25006), ma la denylist di nomi è la cintura: un nome in denylist **non** va mai invocato. → **Task 5** pina (a) nomi denylist → zero richieste a quell'endpoint, (b) una funzione write-capable → `RPC_ANON_WRITE_CAPABLE` TENTATIVE senza escalation.
3. **Storage list su bucket il cui nome viene dal bundle.** Il POST `object/list/{bucket}` deve restare sull'host `supabase_url` owned; un nome bucket con `/`, `?`, `..` non deve uscire dal path. → **Task 4** pina un nome bucket degenere → endpoint contenuto, host invariato.
4. **`toolcheck` con `--version` illeggibile o assente.** Un tool con policy la cui versione non si legge deve **fail-closed** (`ok=False` → SKIPPED, nessuna esecuzione). → **Task 2** pina versione garbage/None → `ok=False`; **Task 15** pina che nuclei non gira se la versione è vietata.
5. **Il cambio di severità nuclei non deve riattivare template intrusivi/mutanti.** Alzare il cap di detection (includere high/critical) deve lasciare intatto l'`-exclude-tags intrusive,dos,fuzz,attack,sqli,xss,ssrf,rce,lfi`. → **Task 15** pina l'argv: tag intrusivi ancora esclusi, severità alzata.

## File Structure

| File | Tipo | Responsabilità | Task |
|---|---|---|---|
| `bastione/models.py` | mod | `Fingerprint.supabase_key_kind`, `discovered_buckets`, `discovered_rpcs`; nuovi `BucketExpectation`, `RpcExpectation`, `AuthExpectation`; `TargetConfig.supabase_buckets/supabase_rpcs/expect_auth/expect_buckets/expect_rpcs` | 1 |
| `bastione/config.py` | mod | `_flatten`: `[supabase].buckets/rpcs`, `[expectations.auth]`, `[[expectations.bucket]]`, `[[expectations.rpc]]` | 1 |
| `targets/_example.toml` | mod | esempi dei nuovi blocchi (commentati) | 1 |
| `bastione/modules/secrets/module.py` | mod | 1 riga: `severity=raw.severity_override or detector.severity` | 1 |
| `bastione/toolcheck.py` | **new** | `TOOL_POLICY`, `check_tool`, `_read_version` (confine I/O) → `ToolStatus` fail-closed (R4) | 2 |
| `bastione/recon/fingerprint.py` | mod | riconosce `sb_publishable_` oltre a `eyJ` (anon); `supabase_key_kind`; popola `discovered_buckets`/`discovered_rpcs` dal bundle | 3 |
| `bastione/modules/supabase/storage.py` | **new** | probe PROBE: list bucket (POST), `STORAGE_PUBLIC_LISTABLE`, oracolo R7 | 4 |
| `bastione/modules/supabase/rpc.py` | **new** | probe PROBE: RPC in GET, denylist, `RPC_*`, oracolo R7 | 5 |
| `bastione/modules/supabase/auth_posture.py` | **new** | READ_ONLY: `GET /auth/v1/settings` vs attese; `SIGNUP_*`, `ANON_SIGNIN_ENABLED` | 6 |
| `bastione/modules/supabase/graphql.py` | **new** | probe PROBE: introspezione GraphQL; `SUPABASE_GRAPHQL_INTROSPECTION` | 7 |
| `bastione/modules/secrets/detectors/supabase_secret.py`, `stripe.py` | **new** | `SECRET_SUPABASE_SECRET_KEY`, `SECRET_STRIPE` (+ liveness) | 8 |
| `bastione/modules/secrets/detectors/cloud_repo.py` | **new** | `SECRET_AWS_AKIA`, `SECRET_GITHUB`, `SECRET_NPM`, `SECRET_UPSTASH` | 9 |
| `bastione/modules/secrets/detectors/ai_keys.py` | **new** | `SECRET_OPENAI`, `SECRET_ANTHROPIC`, `SECRET_GOOGLE_API_KEY` (+ liveness) | 10 |
| `bastione/modules/secrets/detectors/misc.py` | **new** | `SECRET_TELEGRAM_BOT`, `SECRET_PRIVATE_KEY`, `SECRET_HIGH_ENTROPY` | 11 |
| `bastione/modules/secrets/detectors/__init__.py` | mod | import dei nuovi detector (passo unico finale) | 23 |
| `bastione/modules/zap_active/module.py` | mod | fix (a) sessione applicata, (b) seeding endpoint, (c) attesa fine scan, (d) teardown `finally` | 12 |
| `bastione/modules/idor/module.py` | mod | rispetta le sessioni a cookie (thread `sess.cookies`) | 13 |
| `bastione/auth/session.py` | mod | `_http_request` propaga `cookies=` | 13 |
| `bastione/modules/trivy/module.py`, `semgrep/module.py`, `zap/module.py` | mod | gate `toolcheck` (versione min + denylist) | 14 |
| `bastione/modules/nuclei/module.py` | mod | gate `toolcheck` + copertura detection (CVE gravi), tag invasivi ancora esclusi | 15 |
| `bastione/cli.py` | mod | `doctor`: versione + stato via `toolcheck`; fix nome `zap`→`zap-baseline.py` | 16 |
| `.github/workflows/bastione.yml`, `requirements.lock`, `pyproject.toml` | mod/new | action pin per SHA, lockfile con hash, group | 17 |
| `bastione/remediation/agent_bundle.py` | mod | consuma PostureCheck falliti; allinea `MISSING_CSP`→`POSTURE_CSP`; FixBuilder M5; RLS SQL + GRANT (30/10) | 18 |
| `playbooks/*.md` | **new** | playbook per i rule_id M4+M5 mancanti | 19 |
| `bastione/report/markdown.py`, `report/html.py` | mod | sezione "Limiti di verifica (§26)" | 20 |
| `bastione/modules/supabase/module.py` | mod | riconoscimento key kind, semantica accesso (RLS vs GRANT → "protetto ma fragile"), legacy-keys INFO, **wiring** dei 4 sottomoduli | 21 |
| `bastione/modules/server_exposure/module.py` | mod | nuovi path, `DEV_SERVER_EXPOSED`, `API_SPEC_EXPOSED`, body esposti → detector L2 | 22 |
| `bastione/orchestrator.py` | mod | `build_fix_plan` riceve i PostureCheck; `README.md` | 24 |
| `README.md` | mod | nota M5 (corsie 2026) | 24 |
| `tests/test_*.py` | new/mod | un test file per lane (vedi ogni task) | tutte |

## Ordine d'esecuzione (onde — §4.1, mappate sul DAG `dipende_da`)

- **Onda 1:** Task 1 (contratti) · Task 2 (toolcheck). *Disgiunti → paralleli.*
- **Onda 2 (tutti dipendono da 1 e/o 2, file disgiunti → paralleli):** Task 3 (recon) · 4 · 5 · 6 · 7 (sottomoduli supabase) · 8 · 9 · 10 · 11 (detector) · 12 (zap_active) · 13 (idor+session) · 14 · 15 (tool wrapper; **nuclei è solo Task 15**, trivy/semgrep/zap solo Task 14 → disgiunti) · 16 (cli doctor) · 17 (CI) · 18 (agent_bundle) · 19 (playbook) · 20 (report).
- **Onda 3 (integrazione):** Task 23 (`detectors/__init__.py`) · Task 21 (supabase core+wiring, dipende da 3,4,5,6,7) · Task 22 (server_exposure, dipende da 23 per i detector).
- **Onda 4:** Task 24 (orchestrator wiring, dipende da 18 + 21).

**Blind-review per corsia** (correctness · sicurezza/P8/gate · robustezza; **di più** per le probe PROBE e per `agent_bundle`). **Fixer sequenziati per ownership di file.** Ground-truth: `python -m pytest -q` sull'albero stabile a workflow concluso.

## Decisioni chiuse nel piano (erano §11 "aperte, non bloccanti")

- **Lockfile Python → pip-tools** (`pip-compile --generate-hashes` → `requirements.lock`): uv è assente in locale e la CI usa `pip`. (Task 17)
- **Timeout di default `zap_active` = 30 min** (`_ZAP_SCAN_DEADLINE = 1800`), configurabile via `BASTIONE_ZAP_SCAN_TIMEOUT`. (Task 12)
- **Denylist RPC a effetti esterni** = sottostringhe di nome in `_RPC_SIDE_EFFECT_DENY` (Task 5): `send,email,mail,sms,notify,pay,charge,refund,invoice,webhook,reset,delete,drop,truncate,insert,update,upsert,grant,revoke,exec,http,request,call,invoke,sync,import,export,provision,cron,schedule,enqueue,publish,broadcast`.
- **`SIGNUP_NO_EMAIL_CONFIRM`** = finding **sempre** (MEDIUM) quando l'autoconfirm è attivo (debolezza indipendente); `SIGNUP_OPEN` e `ANON_SIGNIN_ENABLED` restano **oracle-first** (R7). (Task 6)
- **M6-related** (WPScan vs Wordfence; TXT apex vs per-sottodominio) restano aperte: sono di M6/M8, fuori scope M5.

---

## ONDA 1 — Contratti

### Task 1: W0 — contratti (`models.py`, `config.py`, `_example.toml`)

**Builder: Opus** (contratti condivisi — un errore qui si propaga a tutte le corsie).

**Files:**
- Modify: `bastione/models.py` (classe `Fingerprint` ~righe 91-109; classe `TargetConfig` ~righe 242-254; nuovi modelli dopo `TableExpectation` ~riga 198)
- Modify: `bastione/config.py` (`_flatten` ~righe 50-103)
- Modify: `targets/_example.toml`
- Test: `tests/test_config.py` (estendi), `tests/test_models.py` (estendi)

**Interfaces (prodotte — le altre corsie vi si appoggiano):**
- `Fingerprint.supabase_key_kind: Literal["legacy_jwt","publishable"] | None = None`
- `Fingerprint.discovered_buckets: list[str] = []`, `Fingerprint.discovered_rpcs: list[str] = []`
- `BucketExpectation(name: str, anon_list: bool = False)`
- `RpcExpectation(name: str, anon_execute: bool = False, sample_args: dict = {})`
- `AuthExpectation(signup_open: bool | None = None, anonymous_signin: bool | None = None)`
- `TargetConfig.supabase_buckets: list[str] = []`, `.supabase_rpcs: list[str] = []`, `.expect_auth: AuthExpectation | None = None`, `.expect_buckets: list[BucketExpectation] = []`, `.expect_rpcs: list[RpcExpectation] = []`

- [ ] **Step 1 — Test (RED): modelli e flattening.** Aggiungi a `tests/test_config.py`:

```python
import tomllib
from bastione.config import _flatten
from bastione.models import (
    TargetConfig, BucketExpectation, RpcExpectation, AuthExpectation, Fingerprint,
)

_M5_TOML = """
name = "t"
base_url = "https://staging.example.com"
environment = "staging"
ownership = "owned"

[supabase]
url = "https://abcdef.supabase.co"
buckets = ["avatars"]
rpcs = ["get_listino"]

[expectations.auth]
signup_open = false
anonymous_signin = false

[[expectations.table]]
name = "clienti"
anon_select = false

[[expectations.bucket]]
name = "avatars"
anon_list = false

[[expectations.rpc]]
name = "get_listino"
anon_execute = true
sample_args = { categoria = "freni" }
"""

def test_flatten_parses_m5_supabase_and_expectations():
    cfg = TargetConfig(**_flatten(tomllib.loads(_M5_TOML)))
    assert cfg.supabase_buckets == ["avatars"]
    assert cfg.supabase_rpcs == ["get_listino"]
    assert cfg.expect_auth == AuthExpectation(signup_open=False, anonymous_signin=False)
    assert [b.name for b in cfg.expect_buckets] == ["avatars"]
    assert cfg.expect_buckets[0].anon_list is False
    assert cfg.expect_rpcs[0].anon_execute is True
    assert cfg.expect_rpcs[0].sample_args == {"categoria": "freni"}
    # retro-compat: le table expectations esistenti restano
    assert [t.name for t in cfg.expectations] == ["clienti"]

def test_m5_fields_optional_and_default_empty():
    cfg = TargetConfig(name="t", base_url="https://s.example", environment="staging", ownership="owned")
    assert cfg.supabase_buckets == [] and cfg.supabase_rpcs == []
    assert cfg.expect_auth is None and cfg.expect_buckets == [] and cfg.expect_rpcs == []

def test_fingerprint_key_kind_and_discovery_defaults():
    fp = Fingerprint(target="t", resolved_urls=[])
    assert fp.supabase_key_kind is None
    assert fp.discovered_buckets == [] and fp.discovered_rpcs == []
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_config.py -q` → FAIL (`ImportError`/`AttributeError`: i nuovi nomi non esistono).

- [ ] **Step 3 — Impl: `models.py`.** (a) Nel modello `Fingerprint` aggiungi dopo `anon_key` (riga 98) i tre campi — `anon_key` resta e ora contiene la chiave pubblica di **entrambi** i tipi (§4.2):

```python
    # §4.2 M5: tipo della chiave pubblica estratta (legacy JWT `eyJ…` vs nuova
    # `sb_publishable_…`). None se nessuna chiave trovata. `anon_key` resta e porta
    # la chiave pubblica di ENTRAMBI i tipi (retrocompatibilità).
    supabase_key_kind: Literal["legacy_jwt", "publishable"] | None = None
    # Nomi bucket/RPC ricavati dal bundle JS same-host (§4.2/§8). Fallback quando lo
    # storage non elenca all'anon e l'OpenAPI è chiusa. Default [] → backward-compatible.
    discovered_buckets: list[str] = []
    discovered_rpcs: list[str] = []
```

(b) Dopo `TableExpectation` (riga 198) aggiungi i tre modelli (`Literal` è già importato):

```python
class BucketExpectation(BaseModel):    # [[expectations.bucket]] del TOML (§15/§4.2)
    name: str
    anon_list: bool = False            # l'anon può elencare gli oggetti del bucket?

class RpcExpectation(BaseModel):       # [[expectations.rpc]] del TOML (§15/§4.2)
    name: str
    anon_execute: bool = False         # l'anon può eseguire la funzione?
    sample_args: dict = {}             # argomenti opzionali per invocarla (query string)

class AuthExpectation(BaseModel):      # [expectations.auth] del TOML (§15/§4.2)
    signup_open: bool | None = None       # il signup pubblico è voluto? None = non dichiarato
    anonymous_signin: bool | None = None  # il sign-in anonimo è voluto? None = non dichiarato
```

(c) In `TargetConfig` aggiungi dopo `expectations` (riga 251):

```python
    supabase_buckets: list[str] = []            # [supabase].buckets (nomi noti)
    supabase_rpcs: list[str] = []               # [supabase].rpcs (nomi noti)
    expect_auth: AuthExpectation | None = None  # [expectations.auth]
    expect_buckets: list[BucketExpectation] = []  # [[expectations.bucket]]
    expect_rpcs: list[RpcExpectation] = []        # [[expectations.rpc]]
```

(d) In `RawSecret` (riga 171-175) aggiungi un override di severità opzionale — serve ai detector (Stripe) che emettono severità diverse per lo STESSO `detector_id` a seconda del match (live=CRITICAL, test=HIGH, webhook=HIGH, D4):

```python
    # §4.4 M5: override di severità per-match. Il modulo secrets usa questo se
    # presente, altrimenti `detector.severity`. Permette a un detector (Stripe) di
    # distinguere live/test/webhook mantenendo UN solo detector_id. None = usa il
    # default del detector.
    severity_override: "Severity | None" = None
```

(`Severity` è già importato in `models.py` via `from bastione.enums import (...)`.)

- [ ] **Step 4 — Impl: `config.py`.** In `_flatten`, sostituisci il blocco `tables = (data.get("expectations") or {}).get("table")` (righe 73-75) con:

```python
    expectations = data.get("expectations") or {}
    if expectations.get("table") is not None:
        kwargs["expectations"] = expectations["table"]
    if "auth" in expectations:
        kwargs["expect_auth"] = expectations["auth"]
    if "bucket" in expectations:
        kwargs["expect_buckets"] = expectations["bucket"]
    if "rpc" in expectations:
        kwargs["expect_rpcs"] = expectations["rpc"]
```

e nel blocco `supabase = data.get("supabase") or {}` (righe 63-65) aggiungi, dopo il check su `url`:

```python
    if "buckets" in supabase:
        kwargs["supabase_buckets"] = supabase["buckets"]
    if "rpcs" in supabase:
        kwargs["supabase_rpcs"] = supabase["rpcs"]
```

- [ ] **Step 5 — Impl: `_example.toml`.** Aggiorna il blocco `[supabase]` e il blocco `[expectations]` con gli esempi dei nuovi campi (tutti opzionali):

```toml
[supabase]
url = "https://abcdef.supabase.co"
buckets = ["avatars"]                   # nomi noti (lo storage non li elenca all'anon)
rpcs = ["get_listino"]                  # nomi noti oltre a quelli del bundle

[expectations.auth]
signup_open = false                     # il signup pubblico è voluto?
anonymous_signin = false                # il sign-in anonimo è voluto?

[[expectations.bucket]]
name = "avatars"
anon_list = false                       # l'anon può elencare gli oggetti?

[[expectations.rpc]]
name = "get_listino"
anon_execute = true                     # l'anon può eseguirla?
sample_args = { categoria = "freni" }   # opzionale: argomenti (query string)
```

> NB TOML: i nuovi blocchi stanno **sotto** `[expectations]` come le `[[expectations.table]]` esistenti; `[expectations.auth]` è una sotto-tabella, `[[expectations.bucket]]`/`[[expectations.rpc]]` sono array-of-tables. Valido in qualunque ordine purché le chiavi non si sovrappongano.

- [ ] **Step 6 — Impl + test: wiring `severity_override` nel modulo secrets.** In `bastione/modules/secrets/module.py`, nel `run()`, **sostituisci** `severity=detector.severity,` (riga ~206) con `severity=raw.severity_override or detector.severity,`. È l'UNICA riga toccata in `module.py` (il resto di L2 è tutto in `detectors/*.py`). Aggiungi a `tests/test_secrets.py`:

```python
def test_raw_secret_severity_override_wins(monkeypatch):
    """Un RawSecret con severity_override pilota la severità del Finding (D4)."""
    import bastione.modules.secrets.module as mod_module
    from bastione.modules.secrets.detectors.base import Detector, DETECTORS
    from bastione.models import RawSecret, Location
    from bastione.enums import Severity
    class _Fake(Detector):
        detector_id = "SECRET_FAKE_OVR"; title = "x"; severity = Severity.CRITICAL
        def scan(self, asset):
            return [RawSecret(detector_id=self.detector_id, value="k"*20,
                              location=Location(file=asset.source), severity_override=Severity.HIGH)]
    DETECTORS.append(_Fake())          # l'autouse _reset_detectors ripristina
    base = "https://staging.example.com/"
    monkeypatch.setattr(mod_module, "_fetch", lambda url: fake_resp(url=base, text="x"))
    res = mod_module.SecretsModule().run(_make_ctx(resolved_urls=[base]))
    ovr = [f for f in res.findings if f.rule_id == "SECRET_FAKE_OVR"]
    assert ovr and ovr[0].severity == Severity.HIGH
```

- [ ] **Step 7 — Run (GREEN):** `python -m pytest tests/test_config.py tests/test_models.py tests/test_secrets.py -q` → PASS. Poi l'intera suite `python -m pytest -q` (nessuna regressione: i campi sono tutti opzionali con default).

- [ ] **Step 8 — Commit** *(orchestratore, non builder):* `git add bastione/models.py bastione/config.py bastione/modules/secrets/module.py targets/_example.toml tests/test_config.py tests/test_models.py tests/test_secrets.py && git commit -m "feat(m5): contratti W0 — key_kind/bucket/rpc discovery, attese auth/bucket/rpc, RawSecret.severity_override"`

---

### Task 2: W0 — `toolcheck.py` (gate di versione fail-closed, R4)

**Builder: Opus** (gate di sicurezza supply-chain).

**Files:**
- Create: `bastione/toolcheck.py`
- Test: `tests/test_toolcheck.py`

**Interfaces (prodotte — le usano Task 14, 15, 16):**
- `TOOL_POLICY: dict[str, dict]`
- `ToolStatus(NamedTuple)`: `ok: bool`, `version: str | None`, `reason: str`
- `check_tool(name: str) -> ToolStatus`
- `_read_version(name: str) -> str | None` — confine I/O **monkeypatchato nei test**

- [ ] **Step 1 — Test (RED):** `tests/test_toolcheck.py`:

```python
import bastione.toolcheck as tc

def test_no_policy_tool_is_allowed():
    s = tc.check_tool("whatweb")           # nessuna policy → ammesso
    assert s.ok is True

def test_version_ok(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.72.0")
    s = tc.check_tool("trivy")
    assert s.ok is True and s.version == "0.72.0"

def test_version_below_min_fails(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.71.9")
    s = tc.check_tool("trivy")
    assert s.ok is False and "minimo" in s.reason

def test_version_denied_fails(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.69.4")
    s = tc.check_tool("trivy")
    assert s.ok is False and "VIETATA" in s.reason.upper() or "vietat" in s.reason

def test_version_unreadable_fail_closed(monkeypatch):   # Review Focus #4
    monkeypatch.setattr(tc, "_read_version", lambda name: None)
    s = tc.check_tool("nuclei")
    assert s.ok is False and s.version is None

def test_version_garbage_fail_closed(monkeypatch):      # Review Focus #4
    monkeypatch.setattr(tc, "_read_version", lambda name: "nuclei banana split")
    s = tc.check_tool("nuclei")
    assert s.ok is False

def test_nuclei_min_and_extract_from_noise(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Nuclei Engine Version: v3.10.0")
    assert tc.check_tool("nuclei").ok is True
    monkeypatch.setattr(tc, "_read_version", lambda name: "v3.9.9")
    assert tc.check_tool("nuclei").ok is False
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_toolcheck.py -q` → FAIL (`ModuleNotFoundError: bastione.toolcheck`).

- [ ] **Step 3 — Impl:** `bastione/toolcheck.py`:

```python
"""Gate di versione fail-closed per i tool esterni (R4, §4.2/§4.7).

`check_tool(name)` applica una policy (versione minima + denylist) leggendo la
versione reale del tool. Una versione vietata, sotto il minimo o NON LEGGIBILE
→ `ok=False` (fail-closed): il chiamante NON esegue il tool e emette `*_SKIPPED`
INFO col motivo (§26). Un tool senza policy → `ok=True` (ammesso).

`_read_version` è l'UNICO confine I/O: monkeypatchato nei test (nessun subprocess
reale), come i `_run_*` dei wrapper.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import NamedTuple

log = logging.getLogger("bastione.toolcheck")

# Policy iniziale (§4.2, LOCKED): CVE note nei tool.
TOOL_POLICY: dict[str, dict] = {
    "trivy": {"min": "0.72.0", "deny": ["0.69.4", "0.69.5", "0.69.6"]},
    "nuclei": {"min": "3.10.0", "deny": []},
}

_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_VERSION_TIMEOUT = 10


class ToolStatus(NamedTuple):
    ok: bool
    version: str | None
    reason: str


def _read_version(name: str) -> str | None:
    """Esegue `<name> --version` e ritorna l'output grezzo (stdout+stderr), o None
    se il binario è assente o l'esecuzione fallisce. Confine I/O monkeypatchabile."""
    if shutil.which(name) is None:
        return None
    try:
        proc = subprocess.run([name, "--version"], capture_output=True, text=True,
                              timeout=_VERSION_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("toolcheck: lettura versione di %r fallita: %s", name, exc)
        return None
    return (proc.stdout or "") + (proc.stderr or "")


def _extract_version(raw: str) -> str | None:
    """Primo `N.N.N` nell'output (gestisce `v3.10.0`, `Version: 0.72.0`, ecc.)."""
    m = _SEMVER_RE.search(raw or "")
    return m.group(0) if m else None


def _parse_semver(v: str) -> tuple[int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return (a, b, c)


def check_tool(name: str) -> ToolStatus:
    """Applica `TOOL_POLICY[name]` leggendo la versione reale (R4). Fail-closed."""
    policy = TOOL_POLICY.get(name)
    if policy is None:
        return ToolStatus(True, None, "nessuna policy: tool ammesso")
    raw = _read_version(name)
    if raw is None:
        return ToolStatus(False, None,
                          "versione non leggibile (fail-closed R4): tool non eseguito")
    ver = _extract_version(raw)
    if ver is None:
        return ToolStatus(False, None,
                          f"versione non interpretabile dall'output (fail-closed R4)")
    if ver in policy.get("deny", []):
        return ToolStatus(False, ver,
                          f"versione {ver} VIETATA (CVE nota, R4): tool non eseguito")
    minimum = policy.get("min")
    if minimum and _parse_semver(ver) < _parse_semver(minimum):
        return ToolStatus(False, ver,
                          f"versione {ver} sotto il minimo {minimum} (R4): tool non eseguito")
    return ToolStatus(True, ver, f"versione {ver} ammessa")
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_toolcheck.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/toolcheck.py tests/test_toolcheck.py && git commit -m "feat(m5): toolcheck fail-closed — policy versione min+denylist per trivy/nuclei (R4)"`

---

## ONDA 2 — Corsie (file disgiunti, in parallelo)

### Task 3: L1a — recon riconosce le chiavi 2026 (`recon/fingerprint.py`)

**Builder: Opus** (gemma del recon, owned-only §7).

**Files:**
- Modify: `bastione/recon/fingerprint.py` (nuove funzioni pure vicino a `extract_anon_key` ~riga 132; orchestrazione in `fingerprint()` ~righe 288-334)
- Test: `tests/test_recon.py` (estendi)

**Interfaces (prodotte):**
- `extract_public_key(text: str) -> tuple[str | None, str | None]` → `(chiave, kind)`, kind ∈ {`"legacy_jwt"`,`"publishable"`} o `(None, None)`
- `extract_rpc_names(text: str) -> list[str]`, `extract_bucket_names(text: str) -> list[str]`
- `fingerprint()` popola `supabase_key_kind`, `discovered_buckets`, `discovered_rpcs`

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_recon.py` (riusa `make_jwt`, `fake_resp` già presenti):

```python
from bastione.recon.fingerprint import (
    extract_public_key, extract_rpc_names, extract_bucket_names)

def test_extract_public_key_legacy_jwt():
    anon = make_jwt("anon")
    assert extract_public_key(f'createClient(u,"{anon}")') == (anon, "legacy_jwt")

def test_extract_public_key_publishable():
    assert extract_public_key('createClient(u,"sb_publishable_AbC123xyz")') == (
        "sb_publishable_AbC123xyz", "publishable")

def test_extract_public_key_prefers_legacy_when_both():
    anon = make_jwt("anon")
    assert extract_public_key(f'{anon} ... sb_publishable_AbC1')[1] == "legacy_jwt"

def test_extract_public_key_ignores_service_role():   # Review Focus #1
    svc = make_jwt("service_role")
    assert extract_public_key(f'const S="{svc}";') == (None, None)

def test_extract_rpc_and_bucket_names():
    js = "supabase.rpc('get_listino',{x:1}); supabase.storage.from('avatars').list()"
    assert extract_rpc_names(js) == ["get_listino"]
    assert extract_bucket_names(js) == ["avatars"]

def test_fingerprint_publishable_and_discovery(monkeypatch, tmp_path):
    import bastione.recon.fingerprint as fp_mod
    page = "https://app.example/"
    html = '<script src="/assets/app.js"></script>'
    js = ('const u="https://abcdefghijklmnopqrst.supabase.co";'
          'const k="sb_publishable_AbC123";'
          "supabase.rpc('get_listino');supabase.storage.from('avatars').list();")
    def fake_fetch(url):
        if url.rstrip("/") == page.rstrip("/"):
            return fake_resp(url=page, headers={}, text=html)
        if url == "https://app.example/assets/app.js":
            return fake_resp(url="https://app.example/assets/app.js", headers={}, text=js)
        return None
    monkeypatch.setattr(fp_mod, "_fetch", fake_fetch)
    monkeypatch.setattr(fp_mod, "_run_whatweb", lambda t: [])
    monkeypatch.setattr(fp_mod, "_run_katana", lambda t: [])
    fp = fp_mod.fingerprint(page, tmp_path)
    assert fp.supabase_key_kind == "publishable"
    assert fp.anon_key == "sb_publishable_AbC123"
    assert fp.discovered_rpcs == ["get_listino"]
    assert fp.discovered_buckets == ["avatars"]
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_recon.py -q` → FAIL.

- [ ] **Step 3 — Impl: funzioni pure.** Dopo `extract_anon_key` (riga 140) aggiungi le regex vicino alle altre (riga 51) e le funzioni:

```python
# Chiave pubblica nel formato nuovo 2026 (§4.2): `sb_publishable_<token>`.
_PUBLISHABLE_RE = re.compile(r"sb_publishable_[A-Za-z0-9]+")
# `.rpc('fn')` / `.rpc("fn", {...})` — entry RPC del client Supabase (§3/§4.2).
_RPC_FROM_RE = re.compile(r"\.rpc\(\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1")
# `.storage.from('bucket')` — entry storage del client (nomi bucket, §4.2).
_STORAGE_FROM_RE = re.compile(r"\.storage\s*\.\s*from\(\s*(['\"])([A-Za-z0-9._-]+)\1")
```

```python
def extract_public_key(text: str) -> tuple[str | None, str | None]:
    """Chiave pubblica Supabase: JWT `role:anon` (legacy) OPPURE `sb_publishable_`
    (nuovo formato 2026, §4.2). Ritorna `(chiave, kind)` con kind in
    {"legacy_jwt","publishable"}, o `(None, None)`. Preferisce la legacy quando
    entrambe presenti (deterministico). La service_role NON è una chiave pubblica:
    `extract_anon_key` la ignora già (§8/§10)."""
    legacy = extract_anon_key(text)
    if legacy is not None:
        return legacy, "legacy_jwt"
    m = _PUBLISHABLE_RE.search(text)
    if m is not None:
        return m.group(0), "publishable"
    return None, None

def extract_rpc_names(text: str) -> list[str]:
    """Nomi RPC referenziati da `.rpc('...')` nel bundle (§4.2). Puro, dedup+ordina."""
    return sorted({m.group(2) for m in _RPC_FROM_RE.finditer(text)})

def extract_bucket_names(text: str) -> list[str]:
    """Nomi bucket da `.storage.from('...')` nel bundle (§4.2). Puro, dedup+ordina."""
    return sorted({m.group(2) for m in _STORAGE_FROM_RE.finditer(text)})
```

- [ ] **Step 4 — Impl: orchestrazione.** In `fingerprint()`: aggiungi `key_kind: str | None = None` e gli accumulatori `buckets_acc: set[str] = set()`, `rpcs_acc: set[str] = set()` vicino a `discovered` (riga 290). Nel loop sui bundle (righe 302-313) **sostituisci** `anon_key = anon_key or extract_anon_key(jresp.text)` con:

```python
        if anon_key is None:
            k, kk = extract_public_key(jresp.text)
            if k is not None:
                anon_key, key_kind = k, kk
        buckets_acc.update(extract_bucket_names(jresp.text))
        rpcs_acc.update(extract_rpc_names(jresp.text))
```

e nella costruzione di `Fingerprint(...)` (righe 318-334) aggiungi i tre campi:

```python
        supabase_key_kind=key_kind,
        discovered_buckets=sorted(buckets_acc),
        discovered_rpcs=sorted(rpcs_acc),
```

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_recon.py -q` → PASS; poi `python -m pytest -q`.

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/recon/fingerprint.py tests/test_recon.py && git commit -m "feat(m5): recon riconosce sb_publishable_ + key_kind; scopre bucket/rpc dal bundle"`

### Task 4: L1c — `supabase/storage.py` (list dello storage, PROBE)

**Builder: Opus** (PROBE, owned-only, P8). File nuovo, disgiunto → parallelo a 5/6/7.

**Files:**
- Create: `bastione/modules/supabase/storage.py`
- Test: `tests/test_supabase_storage.py`

**Interfaces:**
- Consumes: `RunContext`, `gate.authorize`, modelli `Finding`/`PostureCheck`/`Location`.
- Produces: `run_storage_checks(ctx: RunContext, base: str, headers: dict[str,str], buckets: list[str], target: str) -> tuple[list[Finding], list[PostureCheck]]` — chiamata da `module.py` (Task 21). Confine I/O `_post(url, headers, json)` monkeypatchato.

- [ ] **Step 1 — Test (RED):** `tests/test_supabase_storage.py`:

```python
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
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_supabase_storage.py -q` → FAIL (`ModuleNotFoundError`).

- [ ] **Step 3 — Impl:** `bastione/modules/supabase/storage.py`:

```python
"""Supabase storage probe (§4.3/§11.1.3) — PROBE.

Per i bucket NOTI (bundle + TOML) verifica che l'anon non ne possa ELENCARE gli
oggetti, salvo attesa dichiarata (R7). Il list è una POST a
`/storage/v1/object/list/{bucket}`: è una LETTURA (enumerazione) classificata PROBE
(R1), NON una scrittura (nessuno stato creato, §4.0.3).

Owned-only (§7): si contatta solo l'host di `base`. Il nome bucket è URL-quotato e
usato solo come ultimo segmento del path — non può spostare l'authority (Review #3).
P8: mai i NOMI degli oggetti nel Finding; l'euristica dati-personali li guarda solo
internamente per la severità.
"""
from __future__ import annotations

import hashlib
import logging
from urllib.parse import quote

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.storage")
_HTTP_TIMEOUT = 15.0
_PERSONAL_HINTS = ("email", "nome", "name", "cognome", "telefono", "phone", "cf",
                   "fiscal", "codice_fiscale", "indirizzo", "address", "iban",
                   "card", "carta", "passport", "passaporto", "birth", "nascita",
                   "ssn", "tax", "contratto", "contract", "fattura", "invoice")


def _post(url: str, headers: dict, json: dict):
    """POST object/list (LETTURA/PROBE). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: storage probe non disponibile (§11.1.3)")
        return None
    try:
        return httpx.post(url, headers=headers, json=json, timeout=_HTTP_TIMEOUT,
                          follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("storage POST %s fallita: %s", url, exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _looks_personal(names: list[str]) -> bool:
    low = " ".join(names).lower()
    return any(h in low for h in _PERSONAL_HINTS)


def _object_names(resp) -> list[str] | None:
    """Nomi oggetto per l'euristica interna (mai emessi, P8). 200+array → lista."""
    if resp is None or getattr(resp, "status_code", None) != 200:
        return None
    try:
        data = resp.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(data, list):
        return None
    return [str(o.get("name", "")) for o in data if isinstance(o, dict)]


def run_storage_checks(ctx: RunContext, base: str, headers: dict[str, str],
                       buckets: list[str], target: str):
    """Probe PROBE dei bucket noti. Self-gate + backstop (§4.0.7). Owned-only."""
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("storage probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    expect = {b.name: b for b in cfg.expect_buckets}
    supa_url = cfg.supabase_url or base
    for bucket in buckets:
        endpoint = f"/storage/v1/object/list/{bucket}"
        url = f"{base}/storage/v1/object/list/{quote(bucket, safe='')}"
        names = _object_names(_post(url, headers, {"prefix": "", "limit": 100}))
        loc = Location(endpoint=endpoint, url=supa_url)
        if names is not None and len(names) > 0:
            exp = expect.get(bucket)
            if exp is not None and exp.anon_list:
                posture.append(_posture(bucket, target, True, Severity.HIGH,
                                        "bucket pubblico-elencabile ATTESO (§15)"))
            elif exp is None:
                findings.append(_undeclared_finding(bucket, len(names), loc, target))
            else:   # exp.anon_list is False → violazione
                sev = Severity.CRITICAL if _looks_personal(names) else Severity.HIGH
                findings.append(_listable_finding(bucket, len(names), loc, target, sev))
                posture.append(_posture(bucket, target, False, sev,
                                        "anon può elencare gli oggetti (violazione §15)"))
        else:
            posture.append(_posture(bucket, target, True, Severity.HIGH,
                                    "anon non elenca gli oggetti → bucket protetto"))
    return findings, posture


def _listable_finding(bucket, count, loc, target, sev) -> Finding:
    personal = sev is Severity.CRITICAL
    return Finding(
        finding_id=_finding_id("supabase", "STORAGE_PUBLIC_LISTABLE", loc),
        module="supabase", rule_id="STORAGE_PUBLIC_LISTABLE",
        title=f"Bucket storage '{bucket}' elencabile dall'anon"
              + (" (possibili dati personali)" if personal else ""),
        severity=sev, confidence=Confidence.FIRM, target=target, location=loc,
        evidence=f"{count} oggetti elencabili dall'anon (nomi NON inclusi, P8)",
        description=(
            f"POST /storage/v1/object/list/{bucket} con la chiave pubblica restituisce "
            f"{count} oggetti: l'anon può ENUMERARE il contenuto del bucket. La matrice "
            "§15 dichiara anon_list=false per questo bucket (violazione). "
            + ("I nomi degli oggetti suggeriscono dati personali → CRITICAL + GDPR."
               if personal else "Nessun nome riconducibile a dati personali → HIGH.")
            + " (P8: i nomi non sono inclusi nel finding.)"),
        remediation_ref="STORAGE_PUBLIC_LISTABLE", owasp=["A01:2021"],
        gdpr_relevant=personal, intrusion_used=IntrusionLevel.PROBE)


def _undeclared_finding(bucket, count, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "STORAGE_LISTABLE_UNDECLARED", loc),
        module="supabase", rule_id="STORAGE_LISTABLE_UNDECLARED",
        title=f"Bucket storage '{bucket}' elencabile — attesa non dichiarata",
        severity=Severity.INFO, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"{count} oggetti elencabili dall'anon (nomi NON inclusi, P8)",
        description=(
            f"L'anon può elencare gli oggetti del bucket '{bucket}', ma il TOML non "
            "dichiara se è voluto (R7). Dichiara l'attesa con "
            f"`[[expectations.bucket]] name=\"{bucket}\" anon_list=true|false`: se "
            "false, al prossimo scan diventa STORAGE_PUBLIC_LISTABLE; se true, "
            "confermerà una scelta esplicita."),
        remediation_ref="STORAGE_PUBLIC_LISTABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _posture(bucket, target, passed, sev, detail) -> PostureCheck:
    return PostureCheck(
        check_id=f"POSTURE_STORAGE_PRIVATE_{bucket}",
        title=f"Storage bucket '{bucket}' non elencabile dall'anon",
        passed=passed, severity_if_failed=sev, target=target,
        detail=detail, remediation_ref="STORAGE_PUBLIC_LISTABLE")
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_supabase_storage.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/supabase/storage.py tests/test_supabase_storage.py && git commit -m "feat(m5): supabase storage probe (PROBE) — STORAGE_PUBLIC_LISTABLE oracle-first, P8"`

### Task 5: L1c — `supabase/rpc.py` (RPC in GET, PROBE)

**Builder: Opus** (la probe più delicata: invocazione RPC, denylist, severità per esito). File nuovo, parallelo.

**Files:**
- Create: `bastione/modules/supabase/rpc.py`
- Test: `tests/test_supabase_rpc.py`

**Interfaces:**
- Produces: `run_rpc_checks(ctx: RunContext, base: str, headers: dict[str,str], rpcs: list[str], target: str) -> tuple[list[Finding], list[PostureCheck]]`. Confine I/O `_get(url, headers)` monkeypatchato.
- `_RPC_SIDE_EFFECT_DENY: tuple[str, ...]` (denylist nomi a effetto esterno).

**Semantica (D5, LOCKED):** PostgREST esegue QUALUNQUE funzione chiamata in **GET** in transazione **READ ONLY** (una scrittura → 405 / SQLSTATE `25006`). L'invocazione avviene SOLO in GET; mai POST. Argomenti opzionali dal TOML (`expect_rpcs[].sample_args`) → query string. Esclusione prudenziale delle funzioni a effetti esterni (denylist) → `RPC_NOT_VERIFIABLE`, **mai invocate** (Review Focus #2a). P8: mai i valori di riga nel Finding — solo nomi colonna, conteggio, esito.

- [ ] **Step 1 — Test (RED):** `tests/test_supabase_rpc.py`:

```python
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
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_supabase_rpc.py -q` → FAIL.

- [ ] **Step 3 — Impl:** `bastione/modules/supabase/rpc.py`:

```python
"""Supabase RPC probe (§4.3/§11.1.4) — PROBE, GET-only (D5).

PostgREST esegue qualunque funzione chiamata in GET in transazione READ ONLY (una
scrittura → 405 / SQLSTATE 25006). Per le RPC note (bundle + TOML) verifichiamo che
quelle non dichiarate pubbliche non siano eseguibili dall'anon e non restituiscano
dati personali. Le funzioni a effetti esterni (denylist) NON sono mai invocate →
RPC_NOT_VERIFIABLE (§4.3). Mai una POST: la scrittura è fuori scope M5 (§4.0.3).

P8: mai i valori di riga nel Finding — solo nomi colonna, conteggio, esito. Owned-only
(§7): solo l'host di `base`; il nome RPC è URL-quotato come ultimo segmento del path.
"""
from __future__ import annotations

import hashlib
import logging
from urllib.parse import quote, urlencode

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.rpc")
_HTTP_TIMEOUT = 15.0

# Sottostringhe di nome che segnalano un effetto ESTERNO/di scrittura: la funzione
# NON va invocata, nemmeno in GET (la transazione read-only blocca la scrittura nel
# DB, ma non un side-effect verso l'esterno: email, pagamenti, webhook). §4.3/D5.
_RPC_SIDE_EFFECT_DENY: tuple[str, ...] = (
    "send", "email", "mail", "sms", "notify", "pay", "charge", "refund", "invoice",
    "webhook", "reset", "delete", "drop", "truncate", "insert", "update", "upsert",
    "grant", "revoke", "exec", "http", "request", "call", "invoke", "sync", "import",
    "export", "provision", "cron", "schedule", "enqueue", "publish", "broadcast",
)
_PERSONAL_HINTS = ("email", "nome", "name", "cognome", "telefono", "phone", "cf",
                   "fiscal", "codice_fiscale", "indirizzo", "address", "iban", "card",
                   "carta", "passport", "birth", "nascita", "ssn", "tax")


def _get(url: str, headers: dict):
    """GET read-only (invocazione RPC). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: rpc probe non disponibile (§11.1.4)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("rpc GET %s fallita: %s", url, exc)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _is_denylisted(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in _RPC_SIDE_EFFECT_DENY)


def _looks_personal(cols: list[str]) -> bool:
    low = " ".join(cols).lower()
    return any(h in low for h in _PERSONAL_HINTS)


def _is_write_blocked(resp) -> bool:
    """La funzione ha TENTATO una scrittura (bloccata dalla tx read-only, D5):
    HTTP 405, o corpo con SQLSTATE 25006 / 'read-only'."""
    if getattr(resp, "status_code", None) == 405:
        return True
    try:
        data = resp.json()
    except (ValueError, TypeError, AttributeError):
        return False
    if not isinstance(data, dict):
        return False
    blob = f"{data.get('code','')} {data.get('message','')}".lower()
    return "25006" in blob or "read-only" in blob or "read only" in blob


def _response_columns(resp) -> list[str] | None:
    """Nomi colonna della risposta 200 (per euristica interna, mai emessi). 200 non-write
    → lista di nomi ([] se scalare/vuoto); altrimenti None."""
    if getattr(resp, "status_code", None) != 200:
        return None
    try:
        data = resp.json()
    except (ValueError, TypeError, AttributeError):
        return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return list(data[0].keys())
    if isinstance(data, dict):
        return list(data.keys())
    return []


def run_rpc_checks(ctx: RunContext, base: str, headers: dict[str, str],
                   rpcs: list[str], target: str):
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("rpc probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    expect = {r.name: r for r in cfg.expect_rpcs}
    supa_url = cfg.supabase_url or base
    for name in rpcs:
        endpoint = f"/rest/v1/rpc/{name}"
        loc = Location(endpoint=endpoint, url=supa_url)
        if _is_denylisted(name):
            findings.append(_not_verifiable_finding(
                name, loc, target,
                "nome in denylist di funzioni a effetti esterni → esclusa prudenzialmente"))
            continue
        exp = expect.get(name)
        args = dict(exp.sample_args) if exp and exp.sample_args else {}
        url = f"{base}/rest/v1/rpc/{quote(name, safe='')}"
        if args:
            url += "?" + urlencode({k: str(v) for k, v in args.items()})
        resp = _get(url, headers)
        if resp is None:
            findings.append(_not_verifiable_finding(name, loc, target,
                                                    "nessuna risposta (rete/httpx)"))
            continue
        if _is_write_blocked(resp):
            findings.append(_write_capable_finding(name, loc, target))
            posture.append(_rpc_posture(name, target, False, Severity.HIGH,
                                        "anon può invocare una funzione write-capable (D5)"))
            continue
        cols = _response_columns(resp)
        if cols is None:
            # 401/403/404/altro → non invocabile dall'anon (gated)
            posture.append(_rpc_posture(name, target, True, Severity.MEDIUM,
                                        "anon non esegue la funzione → protetta"))
            continue
        # 200 → invocabile dall'anon
        if exp is not None and exp.anon_execute:
            posture.append(_rpc_posture(name, target, True, Severity.MEDIUM,
                                        "funzione pubblica ATTESA (§15)"))
        elif _looks_personal(cols):
            findings.append(_data_exposed_finding(name, cols, loc, target))
            posture.append(_rpc_posture(name, target, False, Severity.CRITICAL,
                                        "la funzione espone dati personali all'anon"))
        else:
            findings.append(_invocable_finding(name, loc, target, declared=exp is not None))
            posture.append(_rpc_posture(name, target, False, Severity.MEDIUM,
                                        "funzione invocabile dall'anon (non dichiarata pubblica)"))
    return findings, posture


def _not_verifiable_finding(name, loc, target, motivo) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_NOT_VERIFIABLE", loc),
        module="supabase", rule_id="RPC_NOT_VERIFIABLE",
        title=f"RPC '{name}' non verificabile", severity=Severity.INFO,
        confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"RPC {name}: {motivo}",
        description=(f"La funzione RPC '{name}' non è stata verificata: {motivo}. "
                     "Onestà difensiva (R6): la verifica NON è stata eseguita."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _data_exposed_finding(name, cols, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_DATA_EXPOSED", loc),
        module="supabase", rule_id="RPC_DATA_EXPOSED",
        title=f"RPC '{name}' espone dati personali all'anon",
        severity=Severity.CRITICAL, confidence=Confidence.FIRM, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → 200; colonne: {sorted(cols)} (valori NON inclusi, P8)",
        description=(f"La funzione '{name}', invocata in GET con la chiave pubblica, "
                     "restituisce righe con colonne riconducibili a dati personali. "
                     "L'anon legge dati che la RLS dovrebbe proteggere (§11.1.4). "
                     "(P8: solo i nomi colonna, mai i valori.)"),
        remediation_ref="RPC_DATA_EXPOSED", owasp=["A01:2021"],
        gdpr_relevant=True, intrusion_used=IntrusionLevel.PROBE)


def _write_capable_finding(name, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_ANON_WRITE_CAPABLE", loc),
        module="supabase", rule_id="RPC_ANON_WRITE_CAPABLE",
        title=f"RPC '{name}' write-capable invocabile dall'anon",
        severity=Severity.HIGH, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → la tx read-only ha bloccato una scrittura (405/25006)",
        description=(f"La funzione '{name}' è invocabile dall'anon e TENTA una scrittura "
                     "(bloccata dalla transazione READ ONLY di PostgREST in GET, D5). "
                     "In un contesto non-GET potrebbe scrivere: va limitata all'anon. "
                     "TENTATIVE — nessuna scrittura è stata eseguita (§4.0.3)."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _invocable_finding(name, loc, target, *, declared: bool) -> Finding:
    nudge = ("" if declared else
             f" Dichiara l'attesa con `[[expectations.rpc]] name=\"{name}\" "
             "anon_execute=true|false` per confermare o far emergere la violazione (R7).")
    return Finding(
        finding_id=_finding_id("supabase", "RPC_ANON_INVOCABLE", loc),
        module="supabase", rule_id="RPC_ANON_INVOCABLE",
        title=f"RPC '{name}' invocabile dall'anon",
        severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → 200 (nessuna colonna personale)",
        description=(f"La funzione '{name}' è eseguibile dall'anon ma non è dichiarata "
                     f"pubblica.{nudge} TENTATIVE: potrebbe essere voluta."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _rpc_posture(name, target, passed, sev, detail) -> PostureCheck:
    return PostureCheck(
        check_id=f"POSTURE_RPC_GATED_{name}",
        title=f"RPC '{name}' non eseguibile dall'anon (o pubblica per scelta)",
        passed=passed, severity_if_failed=sev, target=target,
        detail=detail, remediation_ref="RPC_ANON_INVOCABLE")
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_supabase_rpc.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/supabase/rpc.py tests/test_supabase_rpc.py && git commit -m "feat(m5): supabase rpc probe (PROBE, GET-only) — denylist, RPC_* oracle-first, P8"`

### Task 6: L1c — `supabase/auth_posture.py` (configurazione auth, READ_ONLY)

**Builder: Opus** (logica oracolo R7). File nuovo, parallelo.

**Files:**
- Create: `bastione/modules/supabase/auth_posture.py`
- Test: `tests/test_supabase_auth_posture.py`

**Interfaces:** `run_auth_posture_checks(ctx, base, headers, target) -> tuple[list[Finding], list[PostureCheck]]`. Confine I/O `_get(url, headers)`. READ_ONLY (nessun gate: è un endpoint pubblico documentato, R1) — ma `GET /auth/v1/settings` è l'unica chiamata.

**Decisioni (chiuse nel piano):** `SIGNUP_OPEN` e `ANON_SIGNIN_ENABLED` sono **oracle-first** (R7: finding solo se violano l'attesa; senza attesa → `AUTH_EXPECTATION_UNDECLARED` INFO). `SIGNUP_NO_EMAIL_CONFIRM` è MEDIUM **sempre** quando l'autoconfirm è attivo (debolezza indipendente). Settings non leggibili → `AUTH_SETTINGS_NOT_READABLE` INFO (R6). Lettura difensiva dei campi (`.get`), campo assente → quel controllo non emette nulla (log).

- [ ] **Step 1 — Test (RED):** `tests/test_supabase_auth_posture.py`:

```python
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
    monkeypatch.setattr(ap, "_get", lambda u,h: _settings(disable_signup=True, external_anonymous_users_enabled=True))
    cfg = _cfg(expect_auth=AuthExpectation(anonymous_signin=False))
    f, _ = ap.run_auth_posture_checks(_ctx(cfg=cfg), SUPA, {"apikey":"k"}, "t")
    assert any(x.rule_id == "ANON_SIGNIN_ENABLED" for x in f)

def test_settings_unreadable_is_info(monkeypatch):      # R6
    monkeypatch.setattr(ap, "_get", lambda u,h: None)
    f, _ = ap.run_auth_posture_checks(_ctx(), SUPA, {"apikey":"k"}, "t")
    assert f and f[0].rule_id == "AUTH_SETTINGS_NOT_READABLE" and f[0].severity == Severity.INFO
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_supabase_auth_posture.py -q` → FAIL.

- [ ] **Step 3 — Impl:** `bastione/modules/supabase/auth_posture.py`:

```python
"""Supabase auth posture (§4.3/§11.1.5) — READ_ONLY.

Confronta la configurazione PUBBLICA di GoTrue (`GET /auth/v1/settings`, endpoint
documentato → READ_ONLY, R1) con le attese dichiarate (R7). Sostituisce il
signup-probe POST di Fable (D3: niente creazione utenti). Onestà (R6): settings non
leggibili → AUTH_SETTINGS_NOT_READABLE INFO. Lettura difensiva dei campi.
"""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.auth_posture")
_HTTP_TIMEOUT = 15.0


def _get(url: str, headers: dict):
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: auth posture non disponibile (§11.1.5)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("auth settings GET %s fallita: %s", url, exc)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _finding(rule_id, title, sev, desc, loc, target, conf=Confidence.FIRM) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", rule_id, loc), module="supabase", rule_id=rule_id,
        title=title, severity=sev, confidence=conf, target=target, location=loc,
        evidence=f"GET /auth/v1/settings: {title}", description=desc,
        remediation_ref=rule_id, owasp=["A05:2021"], intrusion_used=IntrusionLevel.READ_ONLY)


def run_auth_posture_checks(ctx: RunContext, base: str, headers: dict[str, str], target: str):
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    cfg = ctx.target_cfg
    loc = Location(endpoint="/auth/v1/settings", url=cfg.supabase_url or base)
    resp = _get(f"{base}/auth/v1/settings", headers)
    if resp is None or getattr(resp, "status_code", None) != 200:
        findings.append(_finding(
            "AUTH_SETTINGS_NOT_READABLE", "Configurazione auth non leggibile", Severity.INFO,
            "GET /auth/v1/settings non ha risposto 200: la configurazione auth non è "
            "verificabile (R6). Verifica INCOMPLETA.", loc, target, conf=Confidence.TENTATIVE))
        return findings, posture
    try:
        s = resp.json()
    except (ValueError, TypeError):
        s = None
    if not isinstance(s, dict):
        findings.append(_finding(
            "AUTH_SETTINGS_NOT_READABLE", "Configurazione auth non interpretabile", Severity.INFO,
            "GET /auth/v1/settings ha risposto 200 ma non JSON-oggetto (R6).", loc, target,
            conf=Confidence.TENTATIVE))
        return findings, posture

    exp = cfg.expect_auth
    as_declared = True

    # 1) signup aperto (oracle-first R7)
    if "disable_signup" in s:
        signup_open = not bool(s.get("disable_signup"))
        if signup_open:
            want = exp.signup_open if exp else None
            if want is True:
                pass  # atteso
            elif want is False:
                as_declared = False
                findings.append(_finding(
                    "SIGNUP_OPEN", "Registrazione self-service aperta", Severity.MEDIUM,
                    "Il signup pubblico è attivo (`disable_signup=false`) ma la matrice "
                    "dichiara signup_open=false: violazione (§15).", loc, target))
            else:
                findings.append(_finding(
                    "AUTH_EXPECTATION_UNDECLARED", "Signup aperto — attesa non dichiarata",
                    Severity.INFO,
                    "Il signup pubblico è attivo ma il TOML non dichiara se è voluto. "
                    "Dichiara `[expectations.auth] signup_open=true|false` (R7).", loc, target,
                    conf=Confidence.TENTATIVE))

    # 2) conferma email (MEDIUM sempre quando autoconfirm attivo — decisione del piano)
    if bool(s.get("mailer_autoconfirm")):
        findings.append(_finding(
            "SIGNUP_NO_EMAIL_CONFIRM", "Conferma email non richiesta alla registrazione",
            Severity.MEDIUM,
            "`mailer_autoconfirm=true`: gli account sono attivi senza verifica email → "
            "abuso/spoofing dell'identità. Attiva la conferma email in Auth settings.",
            loc, target))

    # 3) sign-in anonimo (oracle-first R7)
    if "external_anonymous_users_enabled" in s:
        anon_on = bool(s.get("external_anonymous_users_enabled"))
        if anon_on:
            want = exp.anonymous_signin if exp else None
            if want is True:
                pass
            elif want is False:
                as_declared = False
                findings.append(_finding(
                    "ANON_SIGNIN_ENABLED", "Sign-in anonimo abilitato", Severity.MEDIUM,
                    "Il sign-in anonimo è attivo ma la matrice dichiara "
                    "anonymous_signin=false: violazione (§15).", loc, target))
            else:
                findings.append(_finding(
                    "AUTH_EXPECTATION_UNDECLARED", "Sign-in anonimo — attesa non dichiarata",
                    Severity.INFO,
                    "Il sign-in anonimo è attivo ma il TOML non dichiara se è voluto. "
                    "Dichiara `[expectations.auth] anonymous_signin=true|false` (R7).",
                    loc, target, conf=Confidence.TENTATIVE))

    posture.append(PostureCheck(
        check_id="POSTURE_AUTH_AS_DECLARED",
        title="Configurazione auth conforme alle attese dichiarate",
        passed=as_declared, severity_if_failed=Severity.MEDIUM, target=target,
        detail=("Signup/sign-in anonimo coerenti con [expectations.auth] (§15)."
                if as_declared else
                "La configurazione auth viola un'attesa dichiarata (vedi i finding)."),
        remediation_ref="SIGNUP_OPEN"))
    return findings, posture
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_supabase_auth_posture.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/supabase/auth_posture.py tests/test_supabase_auth_posture.py && git commit -m "feat(m5): supabase auth posture (READ_ONLY) — /auth/v1/settings vs attese (D3/R7)"`

---

### Task 7: L1c — `supabase/graphql.py` (introspezione GraphQL, PROBE)

**Builder: Sonnet** (check meccanico). File nuovo, parallelo.

**Files:**
- Create: `bastione/modules/supabase/graphql.py`
- Test: `tests/test_supabase_graphql.py`

**Interfaces:** `run_graphql_checks(ctx, base, headers, target) -> tuple[list[Finding], list[PostureCheck]]`. Confine I/O `_post(url, headers, json)`. PROBE (self-gate + backstop).

- [ ] **Step 1 — Test (RED):** `tests/test_supabase_graphql.py`:

```python
from pathlib import Path
from types import SimpleNamespace
import bastione.modules.supabase.graphql as gq
from bastione.enums import IntrusionLevel, Severity
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
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl:** `bastione/modules/supabase/graphql.py`:

```python
"""Supabase GraphQL introspection probe (§4.3/§11.1) — PROBE.

Conferma che l'introspezione GraphQL (`/graphql/v1`) non sia esposta all'anon: una
query di introspezione minima; se il server risponde con `data.__schema`, la
superficie è enumerabile → SUPABASE_GRAPHQL_INTROSPECTION (LOW). Solo lettura (una
query di introspezione non muta stato) ma classificata PROBE (logica applicativa).
"""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.graphql")
_HTTP_TIMEOUT = 15.0
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


def _post(url: str, headers: dict, json: dict):
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: graphql probe non disponibile (§11.1)")
        return None
    try:
        return httpx.post(url, headers=headers, json=json, timeout=_HTTP_TIMEOUT,
                          follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("graphql POST %s fallita: %s", url, exc)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _introspection_exposed(resp) -> bool:
    if resp is None or getattr(resp, "status_code", None) != 200:
        return False
    try:
        data = resp.json()
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("data"), dict) \
        and "__schema" in data["data"]


def run_graphql_checks(ctx: RunContext, base: str, headers: dict[str, str], target: str):
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("graphql probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    loc = Location(endpoint="/graphql/v1", url=cfg.supabase_url or base)
    exposed = _introspection_exposed(_post(f"{base}/graphql/v1", headers, _INTROSPECTION_QUERY))
    if exposed:
        findings.append(Finding(
            finding_id=_finding_id("supabase", "SUPABASE_GRAPHQL_INTROSPECTION", loc),
            module="supabase", rule_id="SUPABASE_GRAPHQL_INTROSPECTION",
            title="Introspezione GraphQL esposta all'anon", severity=Severity.LOW,
            confidence=Confidence.FIRM, target=target, location=loc,
            evidence="POST /graphql/v1 (introspection) → data.__schema presente",
            description="L'introspezione GraphQL è abilitata per l'anon: l'intera "
                        "superficie (tipi, campi, relazioni) è enumerabile, allargando "
                        "la ricognizione di un attaccante. Disabilitala in produzione.",
            remediation_ref="SUPABASE_GRAPHQL_INTROSPECTION", owasp=["A05:2021"],
            intrusion_used=IntrusionLevel.PROBE))
    posture.append(PostureCheck(
        check_id="POSTURE_GRAPHQL_INTROSPECTION",
        title="Introspezione GraphQL non esposta all'anon",
        passed=not exposed, severity_if_failed=Severity.LOW, target=target,
        detail=("Introspezione non raggiungibile dall'anon." if not exposed
                else "Introspezione GraphQL esposta (vedi finding)."),
        remediation_ref="SUPABASE_GRAPHQL_INTROSPECTION"))
    return findings, posture
```

- [ ] **Step 4 — Run (GREEN):** PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/supabase/graphql.py tests/test_supabase_graphql.py && git commit -m "feat(m5): supabase graphql introspection probe (PROBE)"`

### Task 8: L2 — detector `supabase_secret.py` + `stripe.py`

**Builder: Opus** (segreti critici + liveness verso provider). File nuovi, paralleli.

**Files:**
- Create: `bastione/modules/secrets/detectors/supabase_secret.py`, `bastione/modules/secrets/detectors/stripe.py`
- Test: `tests/test_detectors_supabase_stripe.py`

**Regole LOCKED (§4.4):** liveness solo con chiamate di **identità** presso il provider (PROBE, gate-first nel modulo esistente `_run_liveness`); evidence sempre redatta (P8, il modulo la redige); remediation = rotazione (L6). **Il detector è drop-in**: `@register_detector` + `scan()` (+ `validate_liveness` opzionale). Per Stripe la severità varia col match → `RawSecret.severity_override` (Task 1).

> **Nota di onestà (R6/§26), SECRET_SUPABASE_SECRET_KEY liveness:** la chiave `sb_secret_` è **opaca** (nessun project-ref derivabile dal token, a differenza del JWT `service_role`). La liveness richiederebbe il `supabase_url` (noto al modulo, non al detector) → in M5 `validate_liveness` ritorna `None` (verifica rimandata, dichiarata). La **detection** CRITICAL è completa.

- [ ] **Step 1 — Test (RED):** `tests/test_detectors_supabase_stripe.py`:

```python
from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity
import bastione.modules.secrets.detectors.supabase_secret as ss
import bastione.modules.secrets.detectors.stripe as st

def test_supabase_secret_key_critical():
    s = ss.SupabaseSecretKeyDetector().scan(TextAsset(source="app.js",
        content='const k="sb_secret_AbC123dEf456GhI789jKl";'))
    assert s and s[0].detector_id == "SECRET_SUPABASE_SECRET_KEY"
    assert ss.SupabaseSecretKeyDetector().severity == Severity.CRITICAL

def test_stripe_live_critical_test_high_webhook_high():   # D4
    d = st.StripeDetector()
    live = d.scan(TextAsset(source="x", content='sk_live_ABCdef0123456789XYZ'))
    test = d.scan(TextAsset(source="x", content='sk_test_ABCdef0123456789XYZ'))
    whk  = d.scan(TextAsset(source="x", content='whsec_ABCdef0123456789XYZ'))
    assert live[0].severity_override == Severity.CRITICAL
    assert test[0].severity_override == Severity.HIGH
    assert whk[0].severity_override == Severity.HIGH

def test_stripe_liveness_live_restricted_revoked(monkeypatch):
    d = st.StripeDetector()
    raw = RawSecret(detector_id="SECRET_STRIPE", value="sk_live_"+"A"*20, location=Location(file="x"))
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert d.validate_liveness(raw).mode == "live"
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=403))
    assert d.validate_liveness(raw).mode == "restricted"
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    r = d.validate_liveness(raw); assert r.alive is False and r.mode == "revoked"

def test_stripe_liveness_no_token_in_detail(monkeypatch):    # P8
    d = st.StripeDetector()
    tok = "sk_live_SENSITIVE000000000"
    raw = RawSecret(detector_id="SECRET_STRIPE", value=tok, location=Location(file="x"))
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert tok not in d.validate_liveness(raw).detail
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl `supabase_secret.py`:**

```python
"""Detector SECRET_SUPABASE_SECRET_KEY — chiave segreta Supabase nuovo formato (§4.4).

`sb_secret_…` bypassa la RLS esattamente come la legacy `service_role` → CRITICAL.
Liveness rimandata (token opaco, nessun ref): vedi nota R6 nel piano.
"""
from __future__ import annotations
import re
from bastione.enums import Severity
from bastione.models import Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

_RE = re.compile(r"sb_secret_[A-Za-z0-9]+")


@register_detector
class SupabaseSecretKeyDetector(Detector):
    detector_id = "SECRET_SUPABASE_SECRET_KEY"
    title = "Supabase secret key (nuovo formato) esposta"
    severity = Severity.CRITICAL
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return [RawSecret(detector_id=self.detector_id, value=m,
                          location=Location(file=asset.source))
                for m in _RE.findall(asset.content)]
```

- [ ] **Step 4 — Impl `stripe.py`:**

```python
"""Detector SECRET_STRIPE — chiavi segrete/ristrette Stripe + webhook secret (§4.4, D4).

Severità per match (RawSecret.severity_override): live/ristretta CRITICAL, test HIGH,
webhook HIGH. Liveness (identità, PROBE): GET api.stripe.com/v1/account → 200 live,
403 viva-ma-limitata (restricted), 401 revocata. P8: il detail non contiene il token.
"""
from __future__ import annotations
import logging
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.stripe")
_STRIPE_TIMEOUT = 15.0

# (regex, severità) — ordine: le forme più specifiche/gravi prima.
_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL),
    (re.compile(r"rk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL),
    (re.compile(r"sk_test_[A-Za-z0-9]{16,}"), Severity.HIGH),
    (re.compile(r"rk_test_[A-Za-z0-9]{16,}"), Severity.HIGH),
    (re.compile(r"whsec_[A-Za-z0-9]{16,}"), Severity.HIGH),
]


def _identity_get(url: str, headers: dict):
    """GET di identità (PROBE). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_STRIPE_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("stripe liveness fallita: %s", exc)
        return None


@register_detector
class StripeDetector(Detector):
    detector_id = "SECRET_STRIPE"
    title = "Chiave Stripe segreta/ristretta esposta"
    severity = Severity.CRITICAL          # default; il match imposta severity_override
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        out: list[RawSecret] = []
        for rx, sev in _PATTERNS:
            for m in rx.findall(asset.content):
                out.append(RawSecret(detector_id=self.detector_id, value=m,
                                     location=Location(file=asset.source),
                                     severity_override=sev))
        return out

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        # I webhook secret (whsec_) non sono chiavi API: niente identity call.
        if secret.value.startswith("whsec_"):
            return None
        resp = _identity_get("https://api.stripe.com/v1/account",
                             {"Authorization": f"Bearer {secret.value}"})
        if resp is None:
            return None
        status = getattr(resp, "status_code", None)
        if status == 200:
            return LivenessResult(alive=True, mode="live",
                                  detail="GET /v1/account → 200: chiave VIVA.")
        if status == 403:
            return LivenessResult(alive=True, mode="restricted",
                                  detail="GET /v1/account → 403: chiave VIVA ma a permessi limitati.")
        if status == 401:
            return LivenessResult(alive=False, mode="revoked",
                                  detail="GET /v1/account → 401: chiave revocata/non valida.")
        return None
```

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_detectors_supabase_stripe.py -q` → PASS.

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/modules/secrets/detectors/supabase_secret.py bastione/modules/secrets/detectors/stripe.py tests/test_detectors_supabase_stripe.py && git commit -m "feat(m5): detector sb_secret_ (CRITICAL) + Stripe (D4 severità per match, liveness provider)"`

> NB: `detectors/__init__.py` **non** si tocca qui — l'import dei nuovi detector è il passo unico finale (Task 23). Finché non è fatto, i detector non sono in `DETECTORS` a runtime (i test di questo task istanziano la classe direttamente).

### Task 9: L2 — detector `cloud_repo.py` (AWS, GitHub, npm, Upstash)

**Builder: Sonnet** (regex + liveness semplice). File nuovo, parallelo.

**Files:** Create `bastione/modules/secrets/detectors/cloud_repo.py`; Test `tests/test_detectors_cloud_repo.py`.

> **Onestà (R6/§26):** AWS = **flag only** (niente liveness: richiederebbe SigV4; §10.2). Upstash = detection ancorata all'URL REST `*.upstash.io` (il token REST esposto accanto); liveness rimandata (serve la coppia URL+token, non un singolo match). GitHub/npm: liveness di identità.

- [ ] **Step 1 — Test (RED):** `tests/test_detectors_cloud_repo.py`:

```python
from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity
import bastione.modules.secrets.detectors.cloud_repo as cr

def test_aws_akia_high_no_liveness():
    d = cr.AwsAkiaDetector()
    s = d.scan(TextAsset(source="x", content="AKIAIOSFODNN7EXAMPLE"))
    assert s and d.severity == Severity.HIGH
    assert d.validate_liveness(s[0]) is None            # flag only

def test_github_classic_and_pat():
    d = cr.GithubTokenDetector()
    assert d.scan(TextAsset(source="x", content="ghp_" + "a"*36))
    assert d.scan(TextAsset(source="x", content="github_pat_" + "A"*22 + "_" + "b"*40))

def test_github_liveness(monkeypatch):
    d = cr.GithubTokenDetector()
    raw = RawSecret(detector_id="SECRET_GITHUB", value="ghp_"+"a"*36, location=Location(file="x"))
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert d.validate_liveness(raw).alive is True
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    assert d.validate_liveness(raw).alive is False

def test_npm_and_upstash():
    assert cr.NpmTokenDetector().scan(TextAsset(source="x", content="npm_" + "a"*36))
    up = cr.UpstashDetector().scan(TextAsset(source="x", content='url:"https://eu1-cool-cat.upstash.io"'))
    assert up and cr.UpstashDetector().severity == Severity.HIGH
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl `cloud_repo.py`:**

```python
"""Detector cloud/repo (§4.4): AWS AKIA/ASIA, GitHub, npm, Upstash. HIGH.

GitHub/npm hanno liveness di identità (PROBE). AWS è flag-only (§10.2). Upstash è
ancorato all'URL REST (il token è esposto accanto); liveness rimandata (R6).
"""
from __future__ import annotations
import logging
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.cloud_repo")
_TIMEOUT = 15.0

_AWS_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
_GITHUB_RE = re.compile(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")
_NPM_RE = re.compile(r"npm_[A-Za-z0-9]{36}")
_UPSTASH_RE = re.compile(r"https://[a-z0-9-]+\.upstash\.io")


def _identity_get(url: str, headers: dict):
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("cloud_repo liveness fallita: %s", exc)
        return None


def _simple_scan(rx, detector_id, asset) -> list[RawSecret]:
    return [RawSecret(detector_id=detector_id, value=m, location=Location(file=asset.source))
            for m in rx.findall(asset.content)]


@register_detector
class AwsAkiaDetector(Detector):
    detector_id = "SECRET_AWS_AKIA"; title = "AWS access key esposta"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _simple_scan(_AWS_RE, self.detector_id, asset)


@register_detector
class GithubTokenDetector(Detector):
    detector_id = "SECRET_GITHUB"; title = "GitHub token esposto"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _simple_scan(_GITHUB_RE, self.detector_id, asset)
    def validate_liveness(self, secret):
        resp = _identity_get("https://api.github.com/user",
                             {"Authorization": f"Bearer {secret.value}",
                              "Accept": "application/vnd.github+json"})
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200: return LivenessResult(alive=True, mode="live", detail="GET /user → 200: token VIVO.")
        if s == 401: return LivenessResult(alive=False, mode="revoked", detail="GET /user → 401: token revocato.")
        return None


@register_detector
class NpmTokenDetector(Detector):
    detector_id = "SECRET_NPM"; title = "npm token esposto"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _simple_scan(_NPM_RE, self.detector_id, asset)
    def validate_liveness(self, secret):
        resp = _identity_get("https://registry.npmjs.org/-/whoami",
                             {"Authorization": f"Bearer {secret.value}"})
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200: return LivenessResult(alive=True, mode="live", detail="whoami → 200: token VIVO.")
        if s == 401: return LivenessResult(alive=False, mode="revoked", detail="whoami → 401: token revocato.")
        return None


@register_detector
class UpstashDetector(Detector):
    detector_id = "SECRET_UPSTASH"; title = "Upstash REST URL/token esposto"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _simple_scan(_UPSTASH_RE, self.detector_id, asset)
```

- [ ] **Step 4 — Run (GREEN):** PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/secrets/detectors/cloud_repo.py tests/test_detectors_cloud_repo.py && git commit -m "feat(m5): detector AWS/GitHub/npm/Upstash (HIGH); liveness identità GitHub+npm"`

---

### Task 10: L2 — detector `ai_keys.py` (OpenAI, Anthropic, Google)

**Builder: Opus** (liveness verso provider AI). File nuovo, parallelo.

**Files:** Create `bastione/modules/secrets/detectors/ai_keys.py`; Test `tests/test_detectors_ai_keys.py`.

> **Google (§4.4):** severità **LOW** (dopo mag-giu 2026 le chiavi standard non ristrette sono rifiutate da Gemini). La liveness conferma l'accesso alle API AI e **arricchisce la description** (meccanismo esistente `_run_liveness`). **La promozione LOW→HIGH su liveness richiederebbe un override di severità a tempo-di-liveness, non previsto dal pipeline M5** → rimandata, dichiarata (R6): il finding resta LOW con nota "accesso AI confermato" nella description. OpenAI/Anthropic: HIGH, liveness di identità.

- [ ] **Step 1 — Test (RED):** `tests/test_detectors_ai_keys.py`:

```python
from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity
import bastione.modules.secrets.detectors.ai_keys as ai

def test_openai_not_matching_anthropic():
    o = ai.OpenAiDetector()
    assert o.scan(TextAsset(source="x", content="sk-" + "A"*24))
    assert o.scan(TextAsset(source="x", content="sk-ant-" + "A"*24)) == []   # non è OpenAI
    assert o.severity == Severity.HIGH

def test_anthropic_match():
    a = ai.AnthropicDetector()
    assert a.scan(TextAsset(source="x", content="sk-ant-api03-" + "A"*24))

def test_google_low_and_liveness_detail(monkeypatch):
    g = ai.GoogleApiKeyDetector()
    s = g.scan(TextAsset(source="x", content="AIza" + "a"*35))
    assert s and g.severity == Severity.LOW
    raw = s[0]
    monkeypatch.setattr(ai, "_identity_get", lambda url, headers=None: SimpleNamespace(status_code=200))
    r = g.validate_liveness(raw)
    assert r.alive is True and "AI" in r.detail.upper()

def test_openai_liveness(monkeypatch):
    d = ai.OpenAiDetector()
    raw = RawSecret(detector_id="SECRET_OPENAI", value="sk-"+"A"*24, location=Location(file="x"))
    monkeypatch.setattr(ai, "_identity_get", lambda url, headers=None: SimpleNamespace(status_code=401))
    assert d.validate_liveness(raw).alive is False
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl `ai_keys.py`:**

```python
"""Detector chiavi AI (§4.4): OpenAI, Anthropic (HIGH), Google (LOW).

Liveness di identità (PROBE): OpenAI GET /v1/models (Bearer); Anthropic GET /v1/models
(x-api-key + anthropic-version); Google GET generativelanguage .../models?key= — se 200,
l'accesso alle API AI è confermato (arricchisce la description; promozione a HIGH rimandata, R6).
"""
from __future__ import annotations
import logging
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.ai_keys")
_TIMEOUT = 15.0

_OPENAI_RE = re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")
_ANTHROPIC_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")
_GOOGLE_RE = re.compile(r"AIza[0-9A-Za-z_-]{35}")


def _identity_get(url: str, headers: dict | None = None):
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, headers=headers or {}, timeout=_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("ai_keys liveness fallita: %s", exc)
        return None


def _scan(rx, det_id, asset):
    return [RawSecret(detector_id=det_id, value=m, location=Location(file=asset.source))
            for m in rx.findall(asset.content)]


@register_detector
class OpenAiDetector(Detector):
    detector_id = "SECRET_OPENAI"; title = "Chiave API OpenAI esposta"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _scan(_OPENAI_RE, self.detector_id, asset)
    def validate_liveness(self, secret):
        resp = _identity_get("https://api.openai.com/v1/models",
                             {"Authorization": f"Bearer {secret.value}"})
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200: return LivenessResult(alive=True, mode="live", detail="GET /v1/models → 200: chiave VIVA.")
        if s == 401: return LivenessResult(alive=False, mode="revoked", detail="GET /v1/models → 401: chiave revocata.")
        return None


@register_detector
class AnthropicDetector(Detector):
    detector_id = "SECRET_ANTHROPIC"; title = "Chiave API Anthropic esposta"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset): return _scan(_ANTHROPIC_RE, self.detector_id, asset)
    def validate_liveness(self, secret):
        resp = _identity_get("https://api.anthropic.com/v1/models",
                             {"x-api-key": secret.value, "anthropic-version": "2023-06-01"})
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200: return LivenessResult(alive=True, mode="live", detail="GET /v1/models → 200: chiave VIVA.")
        if s == 401: return LivenessResult(alive=False, mode="revoked", detail="GET /v1/models → 401: chiave revocata.")
        return None


@register_detector
class GoogleApiKeyDetector(Detector):
    detector_id = "SECRET_GOOGLE_API_KEY"; title = "Chiave API Google esposta"
    severity = Severity.LOW; gdpr_relevant = False
    def scan(self, asset): return _scan(_GOOGLE_RE, self.detector_id, asset)
    def validate_liveness(self, secret):
        # key in query string (mai nel detail, P8)
        resp = _identity_get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={secret.value}")
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200:
            return LivenessResult(alive=True, mode="live",
                                  detail="models?key → 200: accesso alle API AI CONFERMATO.")
        if s in (400, 403):
            return LivenessResult(alive=False, mode="restricted",
                                  detail="models?key → 4xx: chiave ristretta/non valida per le API AI.")
        return None
```

- [ ] **Step 4 — Run (GREEN):** PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/secrets/detectors/ai_keys.py tests/test_detectors_ai_keys.py && git commit -m "feat(m5): detector OpenAI/Anthropic (HIGH) + Google (LOW); liveness identità"`

### Task 11: L2 — detector `misc.py` (Telegram bot, private key, high-entropy)

**Builder: Sonnet.** File nuovo, parallelo.

**Files:** Create `bastione/modules/secrets/detectors/misc.py`; Test `tests/test_detectors_misc.py`.

- [ ] **Step 1 — Test (RED):** `tests/test_detectors_misc.py`:

```python
from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity, Confidence
import bastione.modules.secrets.detectors.misc as mc

def test_telegram_bot_token_high():
    d = mc.TelegramBotDetector()
    s = d.scan(TextAsset(source="x", content="123456789:AAE" + "a"*33))
    assert s and d.severity == Severity.HIGH

def test_telegram_liveness(monkeypatch):
    d = mc.TelegramBotDetector()
    raw = RawSecret(detector_id="SECRET_TELEGRAM_BOT", value="123:" + "a"*33, location=Location(file="x"))
    monkeypatch.setattr(mc, "_identity_get", lambda url: SimpleNamespace(status_code=200, json=lambda: {"ok": True}))
    assert d.validate_liveness(raw).alive is True

def test_private_key_block_critical():
    d = mc.PrivateKeyDetector()
    s = d.scan(TextAsset(source="x", content="-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END..."))
    assert s and d.severity == Severity.CRITICAL

def test_high_entropy_low_tentative():
    d = mc.HighEntropyDetector()
    # stringa ad alta entropia, non hex-hash, non in altre regex
    s = d.scan(TextAsset(source="x", content='token="aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0hJ"'))
    assert s and d.severity == Severity.LOW
    # i finding high-entropy sono SEMPRE tentative (il modulo usa confidence FIRM; qui
    # marchiamo l'incertezza nel RawSecret.entropy e nel titolo — vedi impl)
    assert s[0].entropy is not None

def test_high_entropy_skips_low_entropy_and_hex_hashes():
    d = mc.HighEntropyDetector()
    assert d.scan(TextAsset(source="x", content="aaaaaaaaaaaaaaaaaaaaaaaaaaaa")) == []
    assert d.scan(TextAsset(source="x", content="d41d8cd98f00b204e9800998ecf8427e")) == []  # md5-like
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl `misc.py`:**

```python
"""Detector misc (§4.4): Telegram bot (HIGH, liveness getMe), blocchi di chiave
privata (CRITICAL), stringhe ad alta entropia (LOW, sempre TENTATIVE).
"""
from __future__ import annotations
import logging
import math
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.misc")
_TIMEOUT = 15.0

_TELEGRAM_RE = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_ENTROPY_MIN = 4.0


def _identity_get(url: str):
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, timeout=_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("telegram liveness fallita: %s", exc)
        return None


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


@register_detector
class TelegramBotDetector(Detector):
    detector_id = "SECRET_TELEGRAM_BOT"; title = "Token bot Telegram esposto"
    severity = Severity.HIGH; gdpr_relevant = False
    def scan(self, asset):
        return [RawSecret(detector_id=self.detector_id, value=m, location=Location(file=asset.source))
                for m in _TELEGRAM_RE.findall(asset.content)]
    def validate_liveness(self, secret):
        resp = _identity_get(f"https://api.telegram.org/bot{secret.value}/getMe")
        if resp is None: return None
        s = getattr(resp, "status_code", None)
        if s == 200: return LivenessResult(alive=True, mode="live", detail="getMe → 200: bot VIVO.")
        if s in (401, 404): return LivenessResult(alive=False, mode="revoked", detail="getMe → 4xx: token revocato.")
        return None


@register_detector
class PrivateKeyDetector(Detector):
    detector_id = "SECRET_PRIVATE_KEY"; title = "Blocco di chiave privata esposto"
    severity = Severity.CRITICAL; gdpr_relevant = False
    def scan(self, asset):
        return [RawSecret(detector_id=self.detector_id, value=m, location=Location(file=asset.source))
                for m in _PRIVATE_KEY_RE.findall(asset.content)]


@register_detector
class HighEntropyDetector(Detector):
    detector_id = "SECRET_HIGH_ENTROPY"; title = "Stringa ad alta entropia (possibile segreto)"
    severity = Severity.LOW; gdpr_relevant = False
    def scan(self, asset):
        out = []
        for cand in _CANDIDATE_RE.findall(asset.content):
            if cand.isdigit():
                continue
            if _HEX_RE.match(cand) and len(cand) in (32, 40, 56, 64, 96, 128):
                continue  # probabile hash (md5/sha1/sha224/sha256/...), non un segreto
            ent = _shannon(cand)
            if ent >= _ENTROPY_MIN:
                out.append(RawSecret(detector_id=self.detector_id, value=cand,
                                     location=Location(file=asset.source), entropy=round(ent, 2)))
        return out
```

- [ ] **Step 4 — Run (GREEN):** PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/secrets/detectors/misc.py tests/test_detectors_misc.py && git commit -m "feat(m5): detector Telegram (liveness getMe) + private-key (CRITICAL) + high-entropy (LOW)"`

### Task 12: L4a — `zap_active` dice la verità (§4.6)

**Builder: Opus** (corsia MUTATING; i difetti rendono inaffidabile la validazione live di M4).

**Files:**
- Modify: `bastione/modules/zap_active/module.py` (`_run_zap_active` riga 101-153; `run()` riga 189-202; costanti riga 26)
- Test: `tests/test_zap_active.py` (estendi + aggiorna il `_FakeHttpx`)

**Difetti (dal codice attuale, L4):** (a) `session_headers` ricevuto ma MAI usato → la sessione non è applicata allo scan; (b) `endpoints` ricevuto ma MAI usato → lo scan non parte dagli endpoint `[auth]`; (c) nessun poll di `ascan/view/status` → gli alert si leggono prima della fine; (d) nessun `finally` → la policy vincolata (e ora le regole di sessione) non vengono rimosse.

**Fix (tutti dentro `_run_zap_active`, più 1 riga in `run()` per i cookie):**
- (a) applica la sessione con il **Replacer** di ZAP: una regola `REQ_HEADER` per ogni header della sessione (incluso un header `Cookie` se la sessione è a cookie — stesso difetto cookie di `idor`, risolto qui per zap).
- (b) **semina** gli endpoint dichiarati nel site tree con `core/action/accessUrl` prima dello scan (così sono in-scope).
- (c) **attendi** la fine: poll `ascan/view/status` fino a `100` o alla deadline `_ZAP_SCAN_DEADLINE` (default 30 min, env `BASTIONE_ZAP_SCAN_TIMEOUT`), poi leggi gli alert.
- (d) **teardown** in `finally`: `replacer/action/removeRule` per ogni regola + `ascan/action/removeScanPolicy`.

- [ ] **Step 1 — Test (RED):** aggiorna `_FakeHttpx` in `tests/test_zap_active.py` perché risponda ai nuovi endpoint, e aggiungi i test:

```python
class _FakeHttpx2:
    """Fake ZAP daemon per i fix M5. Registra (url, params) e risponde a tutti gli
    endpoint usati: disableScanners, replacer add/remove, accessUrl, scan, status, alerts,
    removeScanPolicy. `alerts_payload` e `status_seq` configurabili."""
    HTTPError = Exception
    def __init__(self, alerts=None, status_seq=("100",)):
        self.calls = []; self._alerts = alerts or []; self._status = list(status_seq)
    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params or {}))
        if url.endswith("/ascan/action/scan/"):
            return _J({"scan": "1"})
        if url.endswith("/ascan/view/status/"):
            return _J({"status": self._status.pop(0) if len(self._status) > 1 else self._status[0]})
        if url.endswith("/core/view/alerts/"):
            return _J({"alerts": self._alerts})
        return _J({})
class _J:
    def __init__(self, p): self._p = p
    def json(self): return self._p

def test_session_header_applied_before_scan(monkeypatch, tmp_path):
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080")
    monkeypatch.setenv("BASTIONE_ZAP_API_KEY", "k")
    fake = _FakeHttpx2(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {"Authorization": "Bearer x"},
                      ["/api/orders"], str(tmp_path / "o.json"))
    urls = [u for u, _ in fake.calls]
    i_rule = next(i for i, u in enumerate(urls) if u.endswith("/replacer/action/addRule/"))
    i_scan = next(i for i, u in enumerate(urls) if u.endswith("/ascan/action/scan/"))
    assert i_rule < i_scan                                   # (a) sessione prima dello scan
    _, rp = fake.calls[i_rule]
    assert rp.get("matchString") == "Authorization" and rp.get("matchType") == "REQ_HEADER"

def test_endpoints_seeded_before_scan(monkeypatch, tmp_path):
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    fake = _FakeHttpx2(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {}, ["/api/orders", "/api/notes"], str(tmp_path/"o.json"))
    seeded = [p.get("url") for u, p in fake.calls if u.endswith("/core/action/accessUrl/")]
    assert "https://staging.example/api/orders" in seeded and "https://staging.example/api/notes" in seeded

def test_waits_for_status_before_alerts(monkeypatch, tmp_path):     # (c)
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    monkeypatch.setattr(m.time, "sleep", lambda *_: None)
    fake = _FakeHttpx2(status_seq=("50", "100")); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {}, [], str(tmp_path/"o.json"))
    urls = [u for u, _ in fake.calls]
    i_status = next(i for i, u in enumerate(urls) if u.endswith("/ascan/view/status/"))
    i_alerts = next(i for i, u in enumerate(urls) if u.endswith("/core/view/alerts/"))
    assert i_status < i_alerts

def test_teardown_in_finally_even_on_error(monkeypatch, tmp_path):   # (d)
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    class _Boom(_FakeHttpx2):
        def get(self, url, params=None, timeout=None):
            if url.endswith("/core/view/alerts/"): raise RuntimeError("boom")
            return super().get(url, params, timeout)
    fake = _Boom(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {"Authorization": "x"}, [], str(tmp_path/"o.json"))
    urls = [u for u, _ in fake.calls]
    assert any(u.endswith("/replacer/action/removeRule/") for u in urls)
    assert any(u.endswith("/ascan/action/removeScanPolicy/") for u in urls)

def test_cookie_session_passed_to_boundary(monkeypatch):            # cookie non più scartati
    import bastione.modules.zap_active.module as m
    from bastione.models import AuthSession
    monkeypatch.setattr(m, "acquire_session", lambda acc, *, _http=None: AuthSession(
        account_label=acc.label, cookies={"sid": "abc"}, acquired_ok=True))
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/zap")
    seen = {}
    monkeypatch.setattr(m, "_run_zap_active", lambda base, sh, eps, out: seen.setdefault("sh", sh) or [])
    m.ZapActiveModule().run(_ctx())
    assert "Cookie" in seen["sh"] and "sid=abc" in seen["sh"]
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_zap_active.py -q` → FAIL.

- [ ] **Step 3 — Impl: costanti + helper + `_run_zap_active`.** In testa al modulo aggiungi `import os`, `import time`, `import json` (se assenti) e le costanti:

```python
# §4.6/§11 decisione piano: deadline di completamento dello scan (NON il timeout
# per-richiesta _ZAP_TIMEOUT). Default 30 min, configurabile via env.
_ZAP_SCAN_DEADLINE = int(os.getenv("BASTIONE_ZAP_SCAN_TIMEOUT", "1800"))
_ZAP_POLL_INTERVAL = 5
```

Aggiungi gli helper e **riscrivi** `_run_zap_active` (il corpo, non la firma — resta `(base_url, session_headers, endpoints, out_path)`):

```python
def _apply_session_headers(httpx, addr, params, headers) -> list[str]:
    """(a) Una regola Replacer REQ_HEADER per ogni header di sessione. Ritorna i
    nomi-regola per il teardown. Niente header → nessuna regola."""
    names = []
    for i, (k, v) in enumerate(headers.items()):
        name = f"bastione-auth-{i}"
        httpx.get(f"{addr}/JSON/replacer/action/addRule/", params={
            **params, "description": name, "enabled": "true", "matchType": "REQ_HEADER",
            "matchString": k, "matchRegex": "false", "replacement": v}, timeout=_ZAP_TIMEOUT)
        names.append(name)
    return names

def _seed_endpoints(httpx, addr, params, base_url, endpoints) -> None:
    """(b) Semina gli endpoint dichiarati nel site tree (accessUrl)."""
    for ep in endpoints:
        url = base_url + ep if ep.startswith("/") else ep
        httpx.get(f"{addr}/JSON/core/action/accessUrl/",
                  params={**params, "url": url, "followRedirects": "false"}, timeout=_ZAP_TIMEOUT)

def _wait_scan_complete(httpx, addr, params, scan_id) -> None:
    """(c) Poll ascan/view/status fino a 100 o deadline."""
    deadline = time.monotonic() + _ZAP_SCAN_DEADLINE
    while time.monotonic() < deadline:
        r = httpx.get(f"{addr}/JSON/ascan/view/status/",
                      params={**params, "scanId": scan_id}, timeout=_ZAP_TIMEOUT)
        if str((r.json() or {}).get("status", "")) == "100":
            return
        time.sleep(_ZAP_POLL_INTERVAL)
    log.warning("zap_active: deadline di scan raggiunta prima del 100%% (scanId=%s)", scan_id)

def _teardown(httpx, addr, params, rule_names) -> None:
    """(d) Rimuove le regole Replacer e la policy vincolata. Best-effort."""
    for name in rule_names:
        try:
            httpx.get(f"{addr}/JSON/replacer/action/removeRule/",
                      params={**params, "description": name}, timeout=_ZAP_TIMEOUT)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpx.get(f"{addr}/JSON/ascan/action/removeScanPolicy/",
                  params={**params, "scanPolicyName": _CONSTRAINED_POLICY}, timeout=_ZAP_TIMEOUT)
    except Exception:  # noqa: BLE001
        pass


def _run_zap_active(base_url: str, session_headers: dict, endpoints: list, out_path: str):
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: zap_active non disponibile (§14)")
        return None
    addr = os.getenv("BASTIONE_ZAP_ADDR")
    if not addr:
        log.warning("BASTIONE_ZAP_ADDR non impostato: zap_active non eseguito")
        return None
    params = {"apikey": os.getenv("BASTIONE_ZAP_API_KEY", "")}
    rule_names: list[str] = []
    try:
        # policy vincolata PRIMA di tutto (fail-closed §4.6): se non applicata, stop.
        if not _apply_excluded_policy(httpx, addr, params):
            log.warning("zap_active: policy vincolata non applicata → fail-closed, niente scan")
            return None
        rule_names = _apply_session_headers(httpx, addr, params, session_headers)   # (a)
        _seed_endpoints(httpx, addr, params, base_url, endpoints)                   # (b)
        scan_params = {**params, "url": base_url, "scanPolicyName": _CONSTRAINED_POLICY,
                       "recurse": "true", "inScopeOnly": "true"}
        resp = httpx.get(f"{addr}/JSON/ascan/action/scan/", params=scan_params, timeout=_ZAP_TIMEOUT)
        scan_id = str((resp.json() or {}).get("scan", ""))
        if scan_id:
            _wait_scan_complete(httpx, addr, params, scan_id)                       # (c)
        resp = httpx.get(f"{addr}/JSON/core/view/alerts/", params=params, timeout=_ZAP_TIMEOUT)
        alerts = (resp.json() or {}).get("alerts", [])
        try:
            Path(out_path).write_text(json.dumps(alerts), encoding="utf-8")
        except OSError:
            pass
        return alerts
    except Exception as exc:  # noqa: BLE001
        log.warning("zap_active: scan fallito, degrado a None (§4.7): %s", exc)
        return None
    finally:
        _teardown(httpx, addr, params, rule_names)                                  # (d)
```

- [ ] **Step 4 — Impl: `run()` passa anche i cookie.** In `run()` (riga ~199-202) sostituisci la costruzione degli header passati al boundary:

```python
        endpoints = [e.path_template for e in ctx.target_cfg.auth.api_endpoints]
        sess_headers = dict(sess.headers)
        if sess.cookies:   # la sessione a cookie NON va più scartata (come idor, Task 13)
            sess_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
        try:
            alerts = _run_zap_active(ctx.target_cfg.base_url.rstrip("/"),
                                     sess_headers, endpoints, str(out_path))
```

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_zap_active.py -q` → PASS (verifica che i test esistenti — ordine disableScanners<scan, fail-closed, SKIPPED — restino verdi).

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/modules/zap_active/module.py tests/test_zap_active.py && git commit -m "fix(m5): zap_active applica la sessione, semina gli endpoint, attende la fine, fa teardown (§4.6)"`

### Task 13: L4b — `idor` rispetta le sessioni a cookie (§4.6)

**Builder: Opus** (corsia MUTATING cross-tenant). File disgiunti da Task 12 → parallelo.

**Files:**
- Modify: `bastione/modules/idor/module.py` (`_http_request` riga 30; `_request`/`_request_json` righe 98-104)
- Modify: `bastione/auth/session.py` (`_http_request` riga 18)
- Test: `tests/test_idor.py` (aggiungi un test cookie)

**Difetto (L4):** `_request`/`_request_json` leggono SOLO `sess.headers`; `sess.cookies` non è mai usato e `_http_request` non ha un parametro `cookies` → una sessione a cookie (`acquire_session` ramo `session_cookie`, `session.py` righe 76-78) viene **silenziosamente scartata** e la corsia gira come anonima (falsi negativi).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_idor.py`:

```python
def test_cookie_session_is_respected(monkeypatch):
    """Una sessione a COOKIE deve essere applicata: con app leaky, l'IDOR si trova
    (prima del fix i cookie erano scartati → role=None → nessun finding)."""
    import bastione.modules.idor.module as m
    from bastione.models import AuthSession, ApiEndpoint
    from bastione.modules.idor.module import IdorModule
    def fake_acquire(account, *, _http=None):
        return AuthSession(account_label=account.label, cookies={"sid": account.label}, acquired_ok=True)
    monkeypatch.setattr(m, "acquire_session", fake_acquire)

    class _R:
        def __init__(self, status, payload): self.status_code = status; self._p = payload
        def json(self): return self._p
    def router(method, url, *, json=None, headers=None, cookies=None):
        role = (cookies or {}).get("sid")      # il ruolo arriva dal COOKIE, non dall'header
        if url.endswith("/api/orders"):
            return _R(200, [{"id": 1, "owner": "A"}])      # leaky: tutti vedono l'ordine di A
        if url.endswith("/api/orders/1"):
            return _R(200, {"id": 1, "owner": "A"})
        return _R(404, {})
    monkeypatch.setattr(m, "_http_request", router)

    auth = _auth(endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
                            ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    assert [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
```

- [ ] **Step 2 — Run (verify fail):** `python -m pytest tests/test_idor.py::test_cookie_session_is_respected -q` → FAIL (role resta None: i cookie non arrivano al router).

- [ ] **Step 3 — Impl: `idor/module.py`.** (a) `_http_request` (riga 30) — aggiungi `cookies`:

```python
def _http_request(method: str, url: str, *, json=None, headers=None, cookies=None):
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.request(method, url, json=json, headers=headers, cookies=cookies,
                             timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError:
        return None
```

(b) `_request`/`_request_json` (righe 98-104) — propaga i cookie:

```python
    def _request(self, method: str, url: str, sess):
        headers = dict(sess.headers) if sess else {}
        cookies = dict(sess.cookies) if sess else {}
        return _http_request(method, url, headers=headers, cookies=cookies)

    def _request_json(self, method, url, sess, body):
        headers = dict(sess.headers) if sess else {}
        cookies = dict(sess.cookies) if sess else {}
        return _http_request(method, url, json=body, headers=headers, cookies=cookies)
```

- [ ] **Step 4 — Impl: `auth/session.py`.** `_http_request` (riga 18) — aggiungi `cookies` e passalo a `httpx.request` (così il login_post può inviare cookie di sessione; default None = nessun cambiamento per i flussi esistenti):

```python
def _http_request(method: str, url: str, *, json=None, headers=None, cookies=None):
    ...
        return httpx.request(method, url, json=json, headers=headers, cookies=cookies,
                             timeout=_HTTP_TIMEOUT, follow_redirects=False)
```

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_idor.py tests/test_auth_session.py -q` → PASS (i test esistenti, che usano sessioni a header `X-Test-Role`, restano verdi: `cookies` è opzionale e il router header continua a funzionare).

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/modules/idor/module.py bastione/auth/session.py tests/test_idor.py && git commit -m "fix(m5): idor+session propagano i cookie di sessione (§4.6) — niente più falsi negativi"`

### Task 14: L5 — `toolcheck` nei wrapper trivy/semgrep/zap (R4)

**Builder: Sonnet** (colla attorno ai binari). File disgiunti da nuclei (Task 15) → parallelo.

**Files:**
- Modify: `bastione/modules/trivy/module.py` (dopo il `which` a riga ~194), `bastione/modules/semgrep/module.py` (dopo il `which` a riga ~178), `bastione/modules/zap/module.py` (dopo il `which` a riga ~208)
- Test: `tests/test_trivy.py` (estendi); smoke su semgrep/zap

**Pattern (identico nei tre):** subito DOPO il check `shutil.which(...) is None → _skipped(...)` (binario assente), inserisci il gate di versione. Riusa il `*_SKIPPED` esistente col nuovo motivo (§4.9). `check_tool` per un tool SENZA policy (semgrep, zap) ritorna `ok=True` senza leggere la versione → no-op a costo zero; trivy ha policy (min 0.72.0 + denylist) → blocca le versioni vietate PRIMA di eseguire il binario (Review Focus #4).

```python
from bastione.toolcheck import check_tool    # in cima al modulo
# ... dentro run(), dopo il which "present":
status = check_tool("trivy")                 # "semgrep" / "zap-baseline.py" negli altri
if not status.ok:
    return self._skipped(target, f"versione non ammessa (R4): {status.reason}")
```

> NB zap: il binario è `zap-baseline.py` (`_ZAP_BINARY`); passa quel nome a `check_tool` (nessuna policy → no-op, ma coerente e pronto per policy future).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_trivy.py`:

```python
def test_trivy_denied_version_skips_without_running(monkeypatch, tmp_path):
    import bastione.modules.trivy.module as tm
    import bastione.toolcheck as tc
    monkeypatch.setattr(tm.shutil, "which", lambda n: "/usr/bin/trivy")
    monkeypatch.setattr(tc, "_read_version", lambda n: "Version: 0.69.4")   # VIETATA
    ran = []
    monkeypatch.setattr(tm, "_run_trivy", lambda src, out: ran.append(1) or {})
    cfg = _cfg_with_source(str(tmp_path))         # helper esistente che imposta source_path
    res = tm.TrivyModule().run(_ctx(cfg=cfg))
    assert ran == []                               # il binario NON è stato eseguito (fail-closed)
    assert res.findings and res.findings[0].rule_id == "TRIVY_SKIPPED"
    assert "versione" in res.findings[0].evidence.lower()

def test_trivy_allowed_version_proceeds(monkeypatch, tmp_path):
    import bastione.modules.trivy.module as tm
    import bastione.toolcheck as tc
    monkeypatch.setattr(tm.shutil, "which", lambda n: "/usr/bin/trivy")
    monkeypatch.setattr(tc, "_read_version", lambda n: "Version: 0.72.0")
    monkeypatch.setattr(tm, "_run_trivy", lambda src, out: {"Results": []})
    cfg = _cfg_with_source(str(tmp_path))
    res = tm.TrivyModule().run(_ctx(cfg=cfg))
    assert not any(f.rule_id == "TRIVY_SKIPPED" for f in res.findings)
```

> Se `tests/test_trivy.py` non ha già un helper `_cfg_with_source`/`_ctx`, replica il fixture già presente nel file (il builder legge il file e riusa i suoi helper; il modulo trivy richiede `cfg.source_path` = dir esistente e `shutil.which` presente).

- [ ] **Step 2 — Run (verify fail):** FAIL (il gate non esiste ancora: la versione vietata viene eseguita).

- [ ] **Step 3 — Impl:** inserisci il gate `check_tool` nei tre wrapper come sopra (import in cima + 3 righe dopo il `which` in `run()`).

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_trivy.py tests/test_semgrep.py tests/test_zap.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/trivy/module.py bastione/modules/semgrep/module.py bastione/modules/zap/module.py tests/test_trivy.py && git commit -m "feat(m5): gate toolcheck nei wrapper trivy/semgrep/zap (R4 fail-closed)"`

---

### Task 15: L5 — nuclei: `toolcheck` + copertura CVE gravi (§4.7)

**Builder: Opus** (cambia la copertura di detection — rilevanza di sicurezza). File unico (nuclei) → sequenziato solo con sé stesso, parallelo al resto.

**Files:**
- Modify: `bastione/modules/nuclei/module.py` (gate dopo il `which` riga ~168; argv in `_run_nuclei` righe 88-109 → estrai in `_nuclei_argv`)
- Test: `tests/test_nuclei.py` (estendi)

**Due cambi:**
1. **Gate `toolcheck`** (nuclei HA policy: min 3.10.0): dopo il `which` present, `check_tool("nuclei")` → se non ok, `NUCLEI_SKIPPED` "versione non ammessa".
2. **Copertura detection** (§4.7): oggi l'argv cappa `-severity info,low,medium` (riga 94) → le CVE `high`/`critical` non girano. Alza a `info,low,medium,high,critical`. **Lascia intatto** `-exclude-tags intrusive,dos,fuzz,attack,sqli,xss,ssrf,rce,lfi` (Review Focus #5: le categorie invasive/di disservizio restano escluse) e **rimuovi** `-include-tags safe` (restringeva ai soli template "safe", tagliando i template di detection CVE; la sicurezza è garantita dall'`-exclude-tags`, non dal cap di severità).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_nuclei.py`:

```python
def test_nuclei_argv_covers_critical_but_excludes_intrusive():   # Review Focus #5
    import bastione.modules.nuclei.module as nm
    argv = nm._nuclei_argv(["https://staging.example"], "/tmp/out.jsonl")
    sev = argv[argv.index("-severity") + 1]
    assert "critical" in sev and "high" in sev
    tags = argv[argv.index("-exclude-tags") + 1]
    for t in ("intrusive", "dos", "attack", "sqli", "xss", "ssrf", "rce", "lfi"):
        assert t in tags
    assert "-include-tags" not in argv            # niente restrizione ai soli "safe"
    assert "-target" in argv and "https://staging.example" in argv

def test_nuclei_denied_version_skips(monkeypatch):
    import bastione.modules.nuclei.module as nm
    import bastione.toolcheck as tc
    monkeypatch.setattr(nm.shutil, "which", lambda n: "/usr/bin/nuclei")
    monkeypatch.setattr(tc, "_read_version", lambda n: "v3.9.0")   # < 3.10.0
    ran = []
    monkeypatch.setattr(nm, "_run_nuclei", lambda urls, out: ran.append(1) or [])
    from bastione.models import Fingerprint
    res = nm.NucleiModule().run(_ctx(fp=Fingerprint(target="t", resolved_urls=["https://s"])))
    assert ran == [] and res.findings[0].rule_id == "NUCLEI_SKIPPED"
```

> Riusa il fixture `_ctx` già in `tests/test_nuclei.py` (il modulo richiede `fp.resolved_urls` non vuoto, PROBE + ownership).

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl.** (a) Estrai l'argv in una funzione pura `_nuclei_argv(urls, out_path) -> list[str]` (prendi il corpo da `_run_nuclei` righe 88-109) con il nuovo `-severity` e senza `-include-tags`:

```python
def _nuclei_argv(urls: list[str], out_path: str) -> list[str]:
    argv = [
        "nuclei", "-jsonl", "-jsonl-export", out_path,
        # Guardrail anti-MUTATING (§14): le categorie invasive/di disservizio restano escluse.
        "-exclude-tags", "intrusive,dos,fuzz,attack,sqli,xss,ssrf,rce,lfi",
        # §4.7: la detection copre ANCHE high/critical (le CVE gravi), non più cappata.
        "-severity", "info,low,medium,high,critical",
        "-disable-update-check", "-silent", "-no-color",
    ]
    for url in urls:
        argv += ["-target", url]
    return argv
```

e in `_run_nuclei` sostituisci la costruzione inline con `argv = _nuclei_argv(urls, out_path)`.

(b) Nel `run()`, dopo `if shutil.which("nuclei") is None: return self._skipped(...)` aggiungi:

```python
        from bastione.toolcheck import check_tool
        status = check_tool("nuclei")
        if not status.ok:
            return self._skipped(target, f"versione non ammessa (R4): {status.reason}")
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_nuclei.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/nuclei/module.py tests/test_nuclei.py && git commit -m "feat(m5): nuclei — gate toolcheck + copertura CVE gravi (tag invasivi ancora esclusi, §4.7)"`

### Task 16: L5 — `doctor` mostra versione + stato (cli.py)

**Builder: Sonnet.** File unico (`cli.py`) → sequenziato solo con sé stesso.

**Files:** Modify `bastione/cli.py` (`doctor` righe 529-547; `_EXTERNAL_TOOLS` riga 92); Test `tests/test_cli.py` (estendi).

**Cambi:** (1) `doctor` aggiunge una colonna **versione** e, per i tool con policy (`trivy`,`nuclei`), mostra la versione reale e lo stato via `toolcheck.check_tool` (ok / motivo del blocco); (2) correggi il **mismatch di nome**: in `_EXTERNAL_TOOLS` sostituisci `"zap"` con `"zap-baseline.py"` (il binario reale usato dal modulo zap), così `doctor` e il modulo controllano lo stesso nome.

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_cli.py`:

```python
def test_doctor_shows_version_and_status_for_policied_tools(monkeypatch):
    import bastione.cli as cli, bastione.toolcheck as tc
    from typer.testing import CliRunner
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(tc, "_read_version",
                        lambda n: "Version: 0.72.0" if n == "trivy" else "v3.10.0")
    res = CliRunner().invoke(cli.app, ["doctor"])
    assert res.exit_code == 0
    assert "0.72" in res.stdout                      # versione trivy mostrata

def test_doctor_zap_name_fixed(monkeypatch):
    import bastione.cli as cli
    assert "zap-baseline.py" in cli._EXTERNAL_TOOLS and "zap" != cli._EXTERNAL_TOOLS[-1] or True
    # il binario reale è referenziato (niente più mismatch doctor↔modulo)
    assert "zap-baseline.py" in cli._EXTERNAL_TOOLS
```

- [ ] **Step 2 — Run (verify fail):** FAIL (nessuna colonna versione; `zap` vs `zap-baseline.py`).

- [ ] **Step 3 — Impl.** In `_EXTERNAL_TOOLS` (riga 92) sostituisci `"zap"` → `"zap-baseline.py"`. Riscrivi `doctor`:

```python
@app.command()
def doctor() -> None:
    """Verifica tool esterni e librerie opzionali: presenza, versione e policy (§24/R4)."""
    from bastione.toolcheck import check_tool, TOOL_POLICY
    table = Table(title="Bastione doctor — dipendenze opzionali (§24)",
                  show_header=True, header_style="bold")
    table.add_column("componente"); table.add_column("tipo")
    table.add_column("versione"); table.add_column("stato")
    for tool in _EXTERNAL_TOOLS:
        presente = shutil.which(tool) is not None
        version, stato = "—", _ok(presente)
        if presente and tool in TOOL_POLICY:
            st = check_tool(tool)
            version = st.version or "?"
            stato = "[green]ammesso[/]" if st.ok else f"[red]{st.reason}[/]"
        table.add_row(tool, "tool esterno", version, stato)
    table.add_row("httpx", "libreria python", "—", _ok(_lib_present("httpx")))
    console.print(table)
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_cli.py -q` → PASS.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/cli.py tests/test_cli.py && git commit -m "feat(m5): doctor mostra versione+policy via toolcheck; fix nome zap-baseline.py"`

---

### Task 17: L5 — supply-chain CI: action per SHA + lockfile con hash

**Builder: Sonnet** (yaml/config, nessun pytest — verifica con grep/comandi).

**Files:** Modify `.github/workflows/bastione.yml`; Create `requirements.lock`; Modify `pyproject.toml` (`[dependency-groups].dev` += `pip-tools`).

> Non è una corsia TDD-python: la ground-truth è (a) la suite resta verde, (b) il workflow non ha più tag mobili, (c) il lockfile ha gli hash.

- [ ] **Step 1 — Pin delle action per SHA.** Nel workflow, ogni `uses: <action>@vN` va al **commit SHA a 40 cifre** del rilascio taggato, con il tag in commento. Risolvi lo SHA (una volta, dall'host con rete) con:

```bash
for a in "actions/checkout:v4" "actions/setup-python:v5" "github/codeql-action:v3" "actions/upload-artifact:v4"; do
  repo="${a%%:*}"; tag="${a##*:}"
  sha=$(gh api "repos/${repo%/*}/${repo#*/}/git/refs/tags/$tag" --jq '.object.sha')
  # se il tag punta a un tag-object, dereferenzia: gh api repos/.../git/tags/$sha --jq .object.sha
  echo "$a -> $sha"
done
```

e sostituisci (SHA reali risolti dal comando; qui la FORMA attesa):

```yaml
      - uses: actions/checkout@<40-hex-sha>          # v4
      - uses: actions/setup-python@<40-hex-sha>      # v5
      - uses: github/codeql-action/upload-sarif@<40-hex-sha>   # v3
      - uses: actions/upload-artifact@<40-hex-sha>   # v4
```

- [ ] **Step 2 — Lockfile con hash (pip-tools).** Aggiungi `pip-tools` a `[dependency-groups].dev` in `pyproject.toml`:

```toml
[dependency-groups]
dev = [
    "pytest>=8",
    "pip-tools>=7",                  # pip-compile per il lockfile con hash (R4)
]
```

Genera il lockfile (deterministico dalle `dependencies` di `pyproject.toml`):

```bash
python -m piptools compile --generate-hashes --output-file requirements.lock pyproject.toml
```

Il file `requirements.lock` risultante (artefatto generato, committato) contiene ogni dipendenza **pinnata** con `--hash=sha256:...`.

- [ ] **Step 3 — CI usa il lockfile.** Nel workflow sostituisci lo step install (righe 69-72) con un install **con hash obbligatori**:

```yaml
      - name: Install Bastione (locked)
        run: |
          python -m pip install --upgrade pip
          pip install --require-hashes -r requirements.lock
          pip install -e . --no-deps
```

- [ ] **Step 4 — Verifica (al posto del pytest):**

```bash
grep -nE "uses: .*@[0-9a-f]{40}" .github/workflows/bastione.yml   # 4 match, nessun @vN
! grep -nE "uses: .*@v[0-9]" .github/workflows/bastione.yml       # nessun tag mobile residuo
grep -c -- "--hash=sha256:" requirements.lock                     # > 0
python -m pytest -q                                               # suite invariata
```

- [ ] **Step 5 — Azione umana (fuori dal workflow builder, §4.7):** aggiornare **trivy locale a ≥ 0.72.0** (CVE-2026-63328 nella 0.71.x). Finché non fatto, `doctor` e il wrapper trivy segnalano `TRIVY_SKIPPED` "versione non ammessa" — comportamento corretto (fail-closed). Da annotare nel riepilogo di fine sessione.

- [ ] **Step 6 — Commit** *(orchestratore):* `git add .github/workflows/bastione.yml requirements.lock pyproject.toml && git commit -m "feat(m5): supply-chain CI — action pinnate per SHA + lockfile pip-tools con hash (R4)"`

### Task 18: L6 — `agent_bundle` consuma i PostureCheck + rotazioni M5 + RLS/GRANT (§4.8)

**Builder: Opus** (`agent_bundle` è logica delicata, §5).

**Files:** Modify `bastione/remediation/agent_bundle.py` (`build_fix_plan` righe 505-553; `RlsDisabledFix.build` migration righe 208-247); Test `tests/test_agent_bundle.py` (estendi).

**Interfaces (prodotte — le usa Task 24):** `build_fix_plan(findings, cfg, *, now, run_dir, posture_checks: list[PostureCheck] | None = None) -> FixPlan`. Il nuovo parametro è **keyword-only con default None** → l'orchestratore non si rompe finché Task 24 non lo aggiorna.

**Tre cambi:**
1. **Consuma i PostureCheck falliti.** Ogni posture `passed=False` viene sintetizzato in un `Finding` (rule_id=check_id, severity=severity_if_failed) e passa per lo stesso loop di builder. Dedup: un fix già prodotto da un Finding reale non viene duplicato dalla posture.
2. **Allinea i rule_id.** `_RULE_ALIASES = {"POSTURE_CSP": "MISSING_CSP"}`: una posture `POSTURE_CSP` fallita trova il `MissingCspFix`. (`POSTURE_HSTS` è già la chiave del `HstsFix`.)
3. **Rotazioni M5 + RLS/GRANT.** FixBuilder di rotazione per i nuovi `SECRET_*` (§4.4); la migration RLS aggiunge il **GRANT esplicito** (pattern Supabase dal 30/10/2026: RLS + policy + GRANT nella stessa migrazione, §4.8).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_agent_bundle.py`:

```python
from datetime import datetime, timezone
from bastione.models import Finding, Location, PostureCheck, TargetConfig
from bastione.enums import Severity, Confidence, Status
from bastione.remediation.agent_bundle import build_fix_plan

def _cfg(): return TargetConfig(name="t", base_url="https://s.example", environment="staging", ownership="owned")
def _now(): return datetime(2026, 10, 11, tzinfo=timezone.utc)

def test_failed_posture_hsts_becomes_fix():
    pc = PostureCheck(check_id="POSTURE_HSTS", title="HSTS mancante", passed=False,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="assente")
    plan = build_fix_plan([], _cfg(), now=_now(), run_dir="r", posture_checks=[pc])
    assert any(fx.rule_id == "POSTURE_HSTS" for fx in plan.fixes)

def test_posture_csp_aliases_to_missing_csp():
    pc = PostureCheck(check_id="POSTURE_CSP", title="CSP mancante", passed=False,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="assente")
    plan = build_fix_plan([], _cfg(), now=_now(), run_dir="r", posture_checks=[pc])
    assert len(plan.fixes) == 1 and plan.fixes[0].fix_type.value == "config_change"

def test_passed_posture_ignored():
    pc = PostureCheck(check_id="POSTURE_HSTS", title="ok", passed=True,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="presente")
    assert build_fix_plan([], _cfg(), now=_now(), run_dir="r", posture_checks=[pc]).fixes == []

def test_rls_migration_includes_grant():
    f = Finding(finding_id="a"*16, module="supabase", rule_id="RLS_DISABLED", title="RLS",
                severity=Severity.CRITICAL, confidence=Confidence.FIRM, target="t",
                location=Location(endpoint="/rest/v1/clienti"), evidence="1 riga",
                description="", status=Status.NEW)
    plan = build_fix_plan([f], _cfg(), now=_now(), run_dir="r")
    sql = plan.fixes[0].instructions["migration_sql"]
    assert "GRANT" in sql and "clienti" in sql

def test_new_secret_rotation_builder():
    f = Finding(finding_id="b"*16, module="secrets", rule_id="SECRET_OPENAI", title="OpenAI",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target="t",
                location=Location(file="app.js"), evidence="sk-...", description="", status=Status.NEW)
    plan = build_fix_plan([f], _cfg(), now=_now(), run_dir="r")
    fx = plan.fixes[0]
    assert fx.fix_type.value == "secret_rotation" and fx.priority == 1
    assert fx.applicable_by.value == "agent+human"
```

- [ ] **Step 2 — Run (verify fail):** FAIL (posture non consumate; niente GRANT; nessun builder OpenAI).

- [ ] **Step 3 — Impl: rotazioni M5 (data-driven).** Dopo `StripeKeyRotationFix` (riga ~428) aggiungi la registrazione in blocco (riusa la base `_SecretRotationFix`):

```python
# Rotazioni dei segreti M5 (§4.4): remediation = rotazione (umano) + spostamento
# lato server. Registrazione data-driven per non ripetere la stessa classe.
_M5_ROTATIONS = [
    ("SECRET_SUPABASE_SECRET_KEY", "supabase", "secret key (sb_secret_)",
     "Supabase → Project Settings → API keys → rigenera la secret key e revoca quella attuale.",
     "Sposta la nuova chiave in env server-side; mai nel client. Usa la publishable nel frontend."),
    ("SECRET_OPENAI", "openai", "API key",
     "OpenAI → dashboard → API keys → revoca e rigenera la chiave esposta.",
     "Sposta la chiave in env server-side; il client non chiama OpenAI direttamente."),
    ("SECRET_ANTHROPIC", "anthropic", "API key",
     "Anthropic Console → API Keys → revoca e rigenera la chiave esposta.",
     "Sposta la chiave in env server-side; nessuna chiamata diretta dal client."),
    ("SECRET_GITHUB", "github", "token",
     "GitHub → Settings → Developer settings → revoca il token esposto e rigeneralo con scope minimo.",
     "Sposta il token nei secret CI/env server; mai nel repo o nel bundle."),
    ("SECRET_NPM", "npm", "token",
     "npm → Access Tokens → revoca il token esposto e creane uno nuovo (read-only se basta).",
     "Usa il token solo in CI via secret; rimuovilo da codice/.npmrc committati."),
    ("SECRET_UPSTASH", "upstash", "REST token",
     "Upstash → database → Details → rigenera il REST token.",
     "Sposta URL+token in env server-side; non esporli nel client."),
    ("SECRET_AWS_AKIA", "aws", "access key",
     "AWS IAM → disattiva/elimina la access key esposta e creane una nuova con permessi minimi.",
     "Usa ruoli/ambiente server; mai access key nel client o nel repo."),
    ("SECRET_TELEGRAM_BOT", "telegram", "bot token",
     "Telegram @BotFather → /revoke per il bot e genera un nuovo token.",
     "Custodisci il token in env server-side; il bot risponde da un backend."),
    ("SECRET_GOOGLE_API_KEY", "google", "API key",
     "Google Cloud Console → Credentials → revoca la chiave e creane una ristretta (referrer/API).",
     "Restringi la chiave e spostala server-side dove possibile."),
    ("SECRET_PRIVATE_KEY", "generic", "private key",
     "Revoca/ruota la chiave privata presso il suo emittente e rigenera la coppia.",
     "Conserva la chiave privata solo lato server (secret manager), mai nel repo/bundle."),
]
for _rid, _prov, _kn, _ha, _af in _M5_ROTATIONS:
    register_fix(type(f"_Rotation_{_rid}", (_SecretRotationFix,), {
        "rule_id": _rid, "provider": _prov, "key_name": _kn,
        "human_action": _ha, "agent_followup": _af,
        "warning": "La chiave trapelata è COMPROMESSA: rimuoverla dal codice NON basta, "
                   "va ruotata presso il provider (passo umano).",
    }))
```

- [ ] **Step 4 — Impl: RLS + GRANT.** In `RlsDisabledFix.build`, nel ramo tabella della `migration_sql`, dopo la riga `EXECUTE $q$CREATE POLICY sel_own ...$q$;` inserisci il GRANT esplicito (pattern post-30/10, §4.8):

```python
            f"    -- 30/10/2026: niente GRANT automatici sulle tabelle nuove → GRANT esplicito\n"
            f"    EXECUTE $q$GRANT SELECT ON public.{table} TO authenticated$q$;\n"
```

e nel ramo tabella della `rollback_sql`, dopo il `DROP POLICY IF EXISTS`:

```python
            f"    EXECUTE $q$REVOKE SELECT ON public.{table} FROM authenticated$q$;\n"
```

- [ ] **Step 5 — Impl: `build_fix_plan` consuma le posture.** Aggiungi vicino agli helper:

```python
from bastione.models import Location, PostureCheck   # (PostureCheck/Location nuovi import)
from bastione.enums import Confidence

_RULE_ALIASES = {"POSTURE_CSP": "MISSING_CSP"}   # §4.8

def _finding_from_posture(c: PostureCheck) -> Finding:
    """Sintetizza un Finding NEW da un PostureCheck FALLITO, così passa per lo stesso
    loop di FixBuilder (§4.8). severity = severity_if_failed; location vuota."""
    return Finding(
        finding_id=f"posture:{c.check_id}", module="posture", rule_id=c.check_id,
        title=c.title, severity=c.severity_if_failed, confidence=Confidence.FIRM,
        target=c.target, location=Location(), evidence=c.detail, description=c.detail,
        remediation_ref=c.remediation_ref, status=Status.NEW)

def _builder_for(rule_id: str):
    return FIX_BUILDERS.get(rule_id) or FIX_BUILDERS.get(_RULE_ALIASES.get(rule_id, ""))
```

e **riscrivi** il corpo di `build_fix_plan` per: (i) accettare `posture_checks`, (ii) usare `_builder_for`, (iii) de-duplicare:

```python
def build_fix_plan(findings, cfg, *, now, run_dir, posture_checks=None) -> FixPlan:
    fixes: list[FixEntry] = []
    seen: set[tuple] = set()

    def _add(f: Finding) -> None:
        if not _is_open(f):
            return
        builder = _builder_for(f.rule_id)
        if builder is None:
            return
        try:
            fe = builder.build(f, cfg)
        except Exception as exc:  # noqa: BLE001 — resilienza §4.7
            log.warning("FixBuilder %r ha sollevato sul finding %s: salto. (%s)",
                        f.rule_id, f.finding_id, exc)
            return
        key = (fe.rule_id, fe.context.get("resource"), fe.context.get("endpoint"),
               fe.context.get("file"))
        if key in seen:
            return      # dedup: un fix identico da Finding+posture non si duplica
        seen.add(key)
        fixes.append(fe)

    for f in findings:
        _add(f)
    for c in (posture_checks or []):
        if not c.passed:
            _add(_finding_from_posture(c))

    fixes = _order_fixes(fixes)
    return FixPlan(target=cfg.name, generated_at=now, run_dir=run_dir,
                   summary=_build_summary(fixes), fixes=fixes)
```

- [ ] **Step 6 — Run (GREEN):** `python -m pytest tests/test_agent_bundle.py -q` → PASS; poi `python -m pytest -q` (i test esistenti che chiamano `build_fix_plan(... )` senza `posture_checks` restano verdi — default None).

- [ ] **Step 7 — Commit** *(orchestratore):* `git add bastione/remediation/agent_bundle.py tests/test_agent_bundle.py && git commit -m "feat(m5): fix-plan consuma posture falliti + rotazioni M5 + RLS/GRANT 30-10 (§4.8)"`

### Task 19: L6 — playbook per i rule_id M4+M5 (§4.8)

**Builder: Sonnet** (docs). File `.md` nuovi (disgiunti) → parallelo.

**Files:** Create `playbooks/<RULE_ID>.md` (sotto); Test `tests/test_remediation_playbooks.py` (estendi).

Ogni playbook è un template **Jinja2** (motore `remediation/playbooks.py`) con le chiavi `{{ title }} {{ severity }} {{ target }} {{ table }} {{ location }} {{ evidence }}`; chiude SEMPRE con `bastione verify --target {{ target }}` e `<sub>Evidence (già redatta): {{ evidence }}</sub>`. Segui la forma di `playbooks/RLS_DISABLED.md` / `SECRET_STRIPE.md`.

**File da creare** (gli altri rule_id INFO/limite non hanno playbook — cadono nel fallback, §4.8):

*Supabase/auth:* `RPC_DATA_EXPOSED.md`, `RPC_ANON_INVOCABLE.md`, `SUPABASE_GRAPHQL_INTROSPECTION.md`, `SIGNUP_NO_EMAIL_CONFIRM.md`, `ANON_SIGNIN_ENABLED.md`
*server_exposure:* `SENSITIVE_ENDPOINT_EXPOSED.md`, `SOURCEMAP_EXPOSED.md`, `CORS_MISCONFIG.md`, `DEV_SERVER_EXPOSED.md`, `API_SPEC_EXPOSED.md`
*IDOR (M4):* `IDOR_CROSS_TENANT_READ.md`, `IDOR_CROSS_TENANT_WRITE.md`
*Segreti (M5):* `SECRET_SUPABASE_SECRET_KEY.md`, `SECRET_AWS_AKIA.md`, `SECRET_GITHUB.md`, `SECRET_NPM.md`, `SECRET_UPSTASH.md`, `SECRET_OPENAI.md`, `SECRET_ANTHROPIC.md`, `SECRET_TELEGRAM_BOT.md`, `SECRET_PRIVATE_KEY.md`, `SECRET_GOOGLE_API_KEY.md`, `SECRET_HIGH_ENTROPY.md`

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_remediation_playbooks.py` un test parametrizzato che esige il rendering di ogni rule_id:

```python
import pytest
from bastione.remediation.playbooks import render_playbook

_M5_RULE_IDS = [
    "RPC_DATA_EXPOSED", "RPC_ANON_INVOCABLE", "SUPABASE_GRAPHQL_INTROSPECTION",
    "SIGNUP_NO_EMAIL_CONFIRM", "ANON_SIGNIN_ENABLED",
    "SENSITIVE_ENDPOINT_EXPOSED", "SOURCEMAP_EXPOSED", "CORS_MISCONFIG",
    "DEV_SERVER_EXPOSED", "API_SPEC_EXPOSED",
    "IDOR_CROSS_TENANT_READ", "IDOR_CROSS_TENANT_WRITE",
    "SECRET_SUPABASE_SECRET_KEY", "SECRET_AWS_AKIA", "SECRET_GITHUB", "SECRET_NPM",
    "SECRET_UPSTASH", "SECRET_OPENAI", "SECRET_ANTHROPIC", "SECRET_TELEGRAM_BOT",
    "SECRET_PRIVATE_KEY", "SECRET_GOOGLE_API_KEY", "SECRET_HIGH_ENTROPY",
]

@pytest.mark.parametrize("rid", _M5_RULE_IDS)
def test_m5_playbook_renders(rid):
    ctx = {"title": "T", "severity": "HIGH", "target": "t", "rule_id": rid,
           "location": {"url": None, "endpoint": "/x", "file": "app.js", "line": None},
           "table": "clienti", "evidence": "redacted"}
    out = render_playbook(rid, ctx)
    assert out is not None and "bastione verify --target t" in out
```

- [ ] **Step 2 — Run (verify fail):** FAIL (template assenti → `render_playbook` ritorna None).

- [ ] **Step 3 — Impl: playbook "azionabili" (testo pieno).** Esempio canonico `playbooks/RPC_DATA_EXPOSED.md` (gli altri supabase/server/IDOR seguono questa forma, con i passi specifici indicati sotto):

```markdown
### Playbook — {{ title }}

**Cosa significa.** Una funzione RPC (`{{ location.endpoint or "/rest/v1/rpc/<fn>" }}`) invocata in GET con la chiave pubblica restituisce dati riconducibili a **dati personali**: l'anon legge, tramite la funzione, ciò che la RLS dovrebbe proteggere.

**Perché è pericoloso.** La funzione scavalca di fatto la RLS delle tabelle sottostanti ed espone dati degli utenti a chiunque abbia la chiave pubblica (dump, GDPR). Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. In Supabase, rivedi la funzione: se non deve essere pubblica, **revoca l'esecuzione all'anon**:
   ```sql
   REVOKE EXECUTE ON FUNCTION public.<fn>(<args>) FROM anon;
   ```
2. Se deve restare pubblica, assicurati che interroghi **solo** dati non personali e che rispetti la RLS (funzione `SECURITY INVOKER`, non `SECURITY DEFINER`, salvo necessità).
3. Dichiara l'attesa in Bastione: `[[expectations.rpc]] name="<fn>" anon_execute=true|false`.
4. Applica su **staging** e verifica che l'anon non riceva più dati personali.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RPC_DATA_EXPOSED` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
```

Corpi specifici per gli altri "azionabili" (stessa struttura, cambia il nucleo "come ripararlo"):
- **RPC_ANON_INVOCABLE** → revoca `EXECUTE` all'anon o dichiara `anon_execute` nel TOML (vale anche per `RPC_ANON_WRITE_CAPABLE`/`RPC_NOT_VERIFIABLE`, che usano questo `remediation_ref`).
- **SUPABASE_GRAPHQL_INTROSPECTION** → disabilita l'introspezione GraphQL in produzione (impostazione del servizio `pg_graphql`/edge); non serve all'app client.
- **SIGNUP_NO_EMAIL_CONFIRM** → Supabase Auth → attiva "Confirm email" (disattiva `mailer_autoconfirm`).
- **ANON_SIGNIN_ENABLED** → Supabase Auth → disabilita "Anonymous sign-ins" se non è voluto; altrimenti dichiaralo (`[expectations.auth] anonymous_signin=true`).
- **SENSITIVE_ENDPOINT_EXPOSED / DEV_SERVER_EXPOSED / API_SPEC_EXPOSED** → blocca l'accesso pubblico al path/ambiente (hosting rules / auth / rimozione dal deploy); non servire file di config o dev server in produzione.
- **SOURCEMAP_EXPOSED** → non pubblicare i `.map` in produzione (build senza source map o esclusi dal deploy).
- **CORS_MISCONFIG** → restringi `Access-Control-Allow-Origin` a origini note; mai `*` con credenziali.
- **IDOR_CROSS_TENANT_READ / _WRITE** → applica il controllo di tenancy lato server (filtra per `auth.uid()`/tenant su OGNI query) e policy RLS per-utente; mai fidarsi dell'`id` dal client.

- [ ] **Step 4 — Impl: playbook di rotazione segreti (template + tabella).** Tutti i `SECRET_*` condividono questo corpo; cambia solo `<provider>` e la riga "dove ruotare". `playbooks/SECRET_OPENAI.md` (esempio):

```markdown
### Playbook — {{ title }}

**Cosa significa.** È stata trovata una chiave segreta OpenAI{% if location.file %} in `{{ location.file }}`{% endif %}: una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con la chiave un attaccante consuma la tua quota, accede ai tuoi dati del provider e opera a tuo nome/spesa. La chiave è **compromessa** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** OpenAI dashboard → API keys → **revoca** la chiave esposta e **rigenerane** una nuova. Rimuoverla dal codice NON basta.
2. Conserva la nuova chiave **solo lato server** (env del backend); il client non la usa mai.
3. Rimuovi ogni riferimento dal frontend; le chiamate passano da un endpoint server-side.
4. Se era committata, ripulisci anche la history.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
```

Crea gli altri `SECRET_*.md` dallo stesso template, cambiando il **provider** e la **riga di rotazione**:

| File | provider | dove ruotare |
|---|---|---|
| `SECRET_SUPABASE_SECRET_KEY.md` | Supabase | Project Settings → API keys → rigenera la secret key, revoca l'attuale |
| `SECRET_AWS_AKIA.md` | AWS | IAM → disattiva/elimina la access key, creane una con permessi minimi |
| `SECRET_GITHUB.md` | GitHub | Settings → Developer settings → revoca e rigenera con scope minimo |
| `SECRET_NPM.md` | npm | Access Tokens → revoca e crea un token nuovo (read-only se basta) |
| `SECRET_UPSTASH.md` | Upstash | database → Details → rigenera il REST token |
| `SECRET_ANTHROPIC.md` | Anthropic | Console → API Keys → revoca e rigenera |
| `SECRET_TELEGRAM_BOT.md` | Telegram | @BotFather → `/revoke`, genera un nuovo token |
| `SECRET_GOOGLE_API_KEY.md` | Google | Cloud Console → Credentials → revoca e crea una chiave **ristretta** |
| `SECRET_PRIVATE_KEY.md` | (emittente) | revoca/ruota la chiave privata e rigenera la coppia |
| `SECRET_HIGH_ENTROPY.md` | (generico) | se è un segreto, ruotalo presso l'emittente e spostalo server-side; se è un falso positivo, aggiungilo all'allowlist |

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_remediation_playbooks.py -q` → PASS.

- [ ] **Step 6 — Commit** *(orchestratore):* `git add playbooks/ tests/test_remediation_playbooks.py && git commit -m "docs(m5): playbook per i rule_id M4+M5 (§4.8)"`

---

### Task 20: L6 — report: sezione "Limiti di verifica (§26)" (MD + HTML)

**Builder: Sonnet** (report/form). File disgiunti → parallelo.

**Files:** Modify `bastione/report/markdown.py` (nuova `is_verification_limit` + `_sezione_limiti`, chiamata in `to_markdown` riga ~94), `bastione/report/html.py` (sezione analoga, valori escapati); Test `tests/test_report.py`, `tests/test_report_html.py` (estendi).

**Obiettivo (R6/§4.8):** rendere espliciti nel report i **limiti onesti** — ciò che Bastione NON ha potuto verificare: i `*_SKIPPED` e gli INFO di tipo "non determinabile / non dichiarato" (es. `SUPABASE_KEY_NOT_FOUND`, `RPC_NOT_VERIFIABLE`, `AUTH_SETTINGS_NOT_READABLE`, `*_UNDECLARED`, `SUPABASE_SCHEMA_NOT_ENUMERABLE`).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_report.py`:

```python
from bastione.report.markdown import to_markdown, is_verification_limit
from bastione.models import Finding, Location
from bastione.enums import Severity, Confidence, Status

def _f(rule_id, sev=Severity.INFO, status=Status.NEW):
    return Finding(finding_id=rule_id, module="m", rule_id=rule_id, title=rule_id, severity=sev,
                   confidence=Confidence.TENTATIVE, target="t", location=Location(), evidence="e",
                   description="d", status=status)

def test_is_verification_limit_predicate():
    assert is_verification_limit(_f("NUCLEI_SKIPPED"))
    assert is_verification_limit(_f("RPC_NOT_VERIFIABLE"))
    assert is_verification_limit(_f("AUTH_EXPECTATION_UNDECLARED"))
    assert not is_verification_limit(_f("RLS_DISABLED", sev=Severity.CRITICAL))

def test_markdown_has_limits_section():
    md = to_markdown(target="t", posture_score=100.0,
                     findings=[_f("RPC_NOT_VERIFIABLE"), _f("RLS_DISABLED", Severity.CRITICAL)],
                     fixed=[], posture_checks=[], counts={})
    assert "Limiti di verifica" in md and "RPC_NOT_VERIFIABLE" in md
```

e a `tests/test_report_html.py` l'analogo (`to_html(...)` contiene "Limiti di verifica" ed escapa i valori).

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl `markdown.py`.** Aggiungi la predicata + la sezione, e chiamala in `to_markdown` (dopo `_sezione_fixed`, prima della checklist posture):

```python
# Suffissi/rule_id che denotano un LIMITE di verifica (R6/§26): non un difetto, ma
# qualcosa che Bastione NON ha potuto verificare.
_LIMIT_SUFFIXES = ("_SKIPPED", "_NOT_FOUND", "_NOT_READABLE", "_NOT_ENUMERABLE",
                   "_NOT_VERIFIABLE", "_UNDECLARED", "_UNDETERMINED")
_LIMIT_RULE_IDS = {"SUPABASE_SCHEMA_VIA_BUNDLE", "SUPABASE_LEGACY_KEYS_IN_USE",
                   "SUPABASE_JWT_LEGACY_HS256"}

def is_verification_limit(f) -> bool:
    """True se il finding è un LIMITE di verifica onesto (INFO), non un difetto (§26)."""
    if f.severity is not Severity.INFO:
        return False
    return f.rule_id in _LIMIT_RULE_IDS or f.rule_id.endswith(_LIMIT_SUFFIXES)

def _sezione_limiti(findings: list[Finding]) -> str:
    limiti = [f for f in findings if is_verification_limit(f)]
    if not limiti:
        return ""
    righe = ["## Limiti di verifica (§26)",
             "_Ciò che Bastione **non** ha potuto verificare in questa run (onestà difensiva R6):_",
             ""]
    for f in limiti:
        righe.append(f"- ⚠️ **{f.rule_id}** — {f.title}: {f.evidence}")
    return "\n".join(righe)
```

e in `to_markdown`, prima di `sezioni.append(_checklist_posture(posture_checks))`:

```python
    sezioni.append(_sezione_limiti(findings))
```

- [ ] **Step 4 — Impl `html.py`.** Importa la predicata (`from bastione.report.markdown import is_verification_limit`) e aggiungi una sezione analoga con **ogni valore escapato** via `_esc(...)` (XSS guard §23), inserita nello stesso punto (prima della checklist posture):

```python
def _sezione_limiti_html(findings) -> str:
    limiti = [f for f in findings if is_verification_limit(f)]
    if not limiti:
        return ""
    items = "".join(
        f"<li>⚠️ <strong>{_esc(f.rule_id)}</strong> — {_esc(f.title)}: {_esc(f.evidence)}</li>"
        for f in limiti)
    return ('<section class="limiti"><h2>Limiti di verifica (§26)</h2>'
            '<p>Ciò che Bastione <em>non</em> ha potuto verificare (R6):</p>'
            f'<ul>{items}</ul></section>')
```

e aggiungi il blocco nel corpo di `to_html` nello stesso ordine (prima della checklist posture).

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_report.py tests/test_report_html.py -q` → PASS.

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/report/markdown.py bastione/report/html.py tests/test_report.py tests/test_report_html.py && git commit -m "feat(m5): report — sezione Limiti di verifica (§26) in MD e HTML (R6)"`

---

## ONDA 3 — Integrazione

### Task 21: L1b — supabase core: key kind, GRANT-fragile, legacy, wiring sottomoduli (§4.3)

**Builder: Opus.** Dipende da Task 3 (recon), 4/5/6/7 (sottomoduli). **Blind-review rinforzata** (tocca la gemma e sfiora il canary §11.2): le invarianti MUTATING del canary NON cambiano.

**Files:** Modify `bastione/modules/supabase/module.py`; Test `tests/test_supabase.py` (estendi).

**Cinque cambi (nessuno tocca il canary §11.2):**
1. **`should_run`** gira anche senza chiave, per emettere il segnale onesto: `return fp.is_supabase or (cfg.supabase_url is not None)`.
2. **INFO onesti (R6):** `SUPABASE_URL_NOT_FOUND` / `SUPABASE_KEY_NOT_FOUND` quando mancano url/chiave → return.
3. **Legacy keys (migrazione):** se `fp.supabase_key_kind == "legacy_jwt"` → `SUPABASE_LEGACY_KEYS_IN_USE` INFO; se il JWT ha `alg=HS256` → `SUPABASE_JWT_LEGACY_HS256` INFO.
4. **"Protetto ma fragile" (30/10):** nel RLS read test, quando la tabella è protetta con status `401/403` (possibile sola assenza di GRANT, non RLS esplicita) la posture **passa con nota** e raccomandazione (verifica definitiva in M8).
5. **Wiring sottomoduli:** dopo RLS+canary, invoca `storage`/`rpc`/`auth_posture`/`graphql` su buckets/rpcs = UNIONE (bundle ∪ TOML ∪ attese), isolando ciascuna con try/except (resilienza §4.7; i sottomoduli si auto-gated, nessuna `IntrusionDenied` sfugge).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_supabase.py`:

```python
def test_key_not_found_emits_info(monkeypatch):
    fp = make_fp(is_supabase=True, anon_key=None, supabase_url=SUPA_URL)
    res = supa.SupabaseModule().run(make_ctx(fp=fp))
    assert any(f.rule_id == "SUPABASE_KEY_NOT_FOUND" and f.severity is Severity.INFO
               for f in res.findings)

def test_legacy_jwt_emits_migration_info(monkeypatch):
    fp = make_fp(anon_key=make_anon_jwt(), supabase_url=SUPA_URL)   # JWT HS256 role=anon
    fp.supabase_key_kind = "legacy_jwt"
    install_router(monkeypatch, schema=openapi_schema({"t": ["id"]}), rows={"t": (200, [])})
    res = supa.SupabaseModule().run(make_ctx(fp=fp))
    rids = {f.rule_id for f in res.findings}
    assert "SUPABASE_LEGACY_KEYS_IN_USE" in rids and "SUPABASE_JWT_LEGACY_HS256" in rids

def test_protected_fragile_note_on_401(monkeypatch):
    install_router(monkeypatch, schema=openapi_schema({"clienti": ["id"]}), rows={"clienti": (401, None)})
    res = supa.SupabaseModule().run(make_ctx())
    pc = next(p for p in res.posture_checks if p.check_id == "POSTURE_RLS_clienti")
    assert pc.passed and ("GRANT" in pc.detail or "fragile" in pc.detail.lower())

def test_submodules_wired(monkeypatch):
    install_router(monkeypatch, schema=openapi_schema({"t": ["id"]}), rows={"t": (200, [])})
    from bastione.models import Finding, Location
    sentinel = Finding(finding_id="s"*16, module="supabase", rule_id="STORAGE_PUBLIC_LISTABLE",
                       title="x", severity=Severity.HIGH, confidence=Confidence.FIRM, target="gestionale",
                       location=Location(endpoint="/storage/v1/object/list/b"), evidence="e", description="d")
    monkeypatch.setattr(supa.storage, "run_storage_checks", lambda *a, **k: ([sentinel], []))
    monkeypatch.setattr(supa.rpc, "run_rpc_checks", lambda *a, **k: ([], []))
    monkeypatch.setattr(supa.auth_posture, "run_auth_posture_checks", lambda *a, **k: ([], []))
    monkeypatch.setattr(supa.graphql, "run_graphql_checks", lambda *a, **k: ([], []))
    ctx = make_ctx(fp=make_fp(discovered_buckets=["b"]), max_intrusion=IntrusionLevel.PROBE,
                   ownership_verified=True)
    res = supa.SupabaseModule().run(ctx)
    assert any(f.rule_id == "STORAGE_PUBLIC_LISTABLE" for f in res.findings)
```

> Helper di test: aggiungi `make_anon_jwt()` (JWT HS256 role=anon, come `make_jwt` in `test_recon.py`) e, se serve, un parametro `supabase_key_kind`/`discovered_buckets` a `make_fp`. `install_router` esistente copre il resto.

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl: import dei sottomoduli** (in cima a `module.py`):

```python
from bastione.modules.supabase import auth_posture, graphql, rpc, storage
```

- [ ] **Step 4 — Impl: `should_run` + `run()` rifattorizzata.** Cambia `should_run` e riscrivi `run()` estraendo la logica RLS esistente in `_run_rls_surface` (il corpo attuale da "1) SURFACE MAP" fino al canary, con i `return ModuleResult(findings, posture)` trasformati in `return` — appende alle liste passate, non ritorna un ModuleResult):

```python
    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        # Gira anche senza chiave: così emette il segnale onesto SUPABASE_KEY_NOT_FOUND (R6).
        return fp.is_supabase or (cfg.supabase_url is not None)

    def run(self, ctx: RunContext) -> ModuleResult:
        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        cfg = ctx.target_cfg
        target = cfg.name
        supabase_url = ctx.fingerprint.supabase_url or cfg.supabase_url
        anon = ctx.fingerprint.anon_key

        if supabase_url is None:
            findings.append(self._not_found_info(
                "SUPABASE_URL_NOT_FOUND", "URL Supabase non trovato", target,
                "Nessun URL Supabase (né dal recon né dal TOML): la verifica Supabase NON è stata fatta."))
        if anon is None:
            findings.append(self._not_found_info(
                "SUPABASE_KEY_NOT_FOUND", "Chiave pubblica Supabase non trovata", target,
                "Nessuna chiave pubblica (legacy o publishable) estratta: la verifica RLS NON è stata fatta."))
        if supabase_url is None or anon is None:
            return ModuleResult(findings, posture)

        base = supabase_url.rstrip("/")
        headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
        read_open: set[str] = set()

        self._emit_key_kind_info(ctx, supabase_url, target, findings)
        self._run_rls_surface(ctx, base, headers, supabase_url, target, findings, posture, read_open)
        self._run_submodules(ctx, base, headers, target, findings, posture)
        return ModuleResult(findings, posture)
```

- [ ] **Step 5 — Impl: nuovi helper.**

```python
    @staticmethod
    def _not_found_info(rule_id, title, target, detail) -> Finding:
        loc = Location(endpoint="/rest/v1/")
        return Finding(
            finding_id=_finding_id("supabase", rule_id, loc), module="supabase", rule_id=rule_id,
            title=title, severity=Severity.INFO, confidence=Confidence.TENTATIVE, target=target,
            location=loc, evidence=detail, description=detail + " (R6: verifica INCOMPLETA)",
            remediation_ref=None, owasp=["A05:2021"], intrusion_used=IntrusionLevel.READ_ONLY)

    def _emit_key_kind_info(self, ctx, supabase_url, target, findings) -> None:
        """Chiavi legacy ancora in uso → INFO di migrazione (§4.3)."""
        if ctx.fingerprint.supabase_key_kind != "legacy_jwt":
            return
        loc = Location(endpoint="/rest/v1/", url=supabase_url)
        findings.append(Finding(
            finding_id=_finding_id("supabase", "SUPABASE_LEGACY_KEYS_IN_USE", loc),
            module="supabase", rule_id="SUPABASE_LEGACY_KEYS_IN_USE",
            title="Chiavi Supabase legacy ancora in uso", severity=Severity.INFO,
            confidence=Confidence.FIRM, target=target, location=loc,
            evidence="chiave pubblica in formato legacy JWT (eyJ…)",
            description="Il progetto usa ancora la chiave pubblica legacy (JWT). Le legacy "
                        "saranno rimosse 'late 2026': migra a sb_publishable_/sb_secret_.",
            remediation_ref=None, owasp=["A05:2021"], intrusion_used=IntrusionLevel.READ_ONLY))
        # alg del JWT: HS256 = firma legacy
        from bastione.recon.fingerprint import _decode_jwt_header  # vedi Step 6
        alg = (_decode_jwt_header(ctx.fingerprint.anon_key or "") or {}).get("alg")
        if alg == "HS256":
            findings.append(Finding(
                finding_id=_finding_id("supabase", "SUPABASE_JWT_LEGACY_HS256", loc),
                module="supabase", rule_id="SUPABASE_JWT_LEGACY_HS256",
                title="JWT Supabase con firma legacy HS256", severity=Severity.INFO,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence="alg=HS256", description="La chiave pubblica è un JWT HS256 (schema legacy). "
                "Con le nuove chiavi la firma passa ad asimmetrica: pianifica la migrazione.",
                remediation_ref=None, owasp=["A05:2021"], intrusion_used=IntrusionLevel.READ_ONLY))

    def _run_submodules(self, ctx, base, headers, target, findings, posture) -> None:
        """Invoca i sottomoduli PROBE/READ_ONLY (storage/rpc/auth/graphql). Ognuno si
        auto-gated (§4.0.7). Isolamento per resilienza (§4.7)."""
        cfg = ctx.target_cfg
        buckets = sorted(set(ctx.fingerprint.discovered_buckets) | set(cfg.supabase_buckets)
                         | {b.name for b in cfg.expect_buckets})
        rpcs = sorted(set(ctx.fingerprint.discovered_rpcs) | set(cfg.supabase_rpcs)
                      | {r.name for r in cfg.expect_rpcs})
        for fn, args in (
            (storage.run_storage_checks, (ctx, base, headers, buckets, target)),
            (rpc.run_rpc_checks, (ctx, base, headers, rpcs, target)),
            (auth_posture.run_auth_posture_checks, (ctx, base, headers, target)),
            (graphql.run_graphql_checks, (ctx, base, headers, target)),
        ):
            try:
                f, p = fn(*args)
                findings.extend(f); posture.extend(p)
            except Exception:  # noqa: BLE001 — un sottomodulo non blocca gli altri
                log.warning("supabase: sottomodulo %s fallito, saltato", fn.__name__, exc_info=True)
```

- [ ] **Step 6 — Impl: `_decode_jwt_header` nel recon** (riusa il pattern di `_decode_jwt_payload`, `recon/fingerprint.py`): aggiungi accanto a quello una funzione pubblica che decodifica il **segmento header** (`token.split(".")[0]`) → dict o None. È in `recon/fingerprint.py` (file già toccato da Task 3 — ma qui lo tocca Task 21: se Task 3 è già committato, è un'aggiunta pulita in coda alle funzioni pure; **se preferisci, metti `_decode_jwt_header` localmente in `supabase/module.py`** per non riaprire `fingerprint.py`). Scelta consigliata: **helper locale in `module.py`** (zero cross-task su `fingerprint.py`):

```python
import base64, binascii, json as _json
def _jwt_alg(token: str) -> str | None:
    try:
        head = token.split(".")[0]; head += "=" * (-len(head) % 4)
        data = _json.loads(base64.urlsafe_b64decode(head))
    except (IndexError, ValueError, binascii.Error):
        return None
    return data.get("alg") if isinstance(data, dict) else None
```

e usa `_jwt_alg(ctx.fingerprint.anon_key or "")` invece di `_decode_jwt_header(...)` sopra (sostituisci la riga). Per una chiave publishable (`sb_publishable_…`) `_jwt_alg` ritorna None → nessun finding HS256 (corretto).

- [ ] **Step 7 — Impl: "protetto ma fragile".** In `_rls_read_test`, cattura lo status e passalo alla posture protetta:

```python
        resp = _get(f"{base}{endpoint}?limit=1", headers)
        status = getattr(resp, "status_code", None)
        rows = self._readable_rows(resp)
        ...
        # ramo protetto (in fondo al metodo):
        posture_checks.append(self._rls_protected_posture(table, target, status))
```

e **riscrivi** `_rls_protected_posture` per la nota fragile:

```python
    @staticmethod
    def _rls_protected_posture(table: str, target: str, status: int | None = None) -> PostureCheck:
        fragile = status in (401, 403)
        if fragile:
            detail = (f"GET anonima a /rest/v1/{table}?limit=1 → {status}: tabella protetta, "
                      "ma la protezione potrebbe derivare dalla SOLA assenza di GRANT (default "
                      "Supabase dal 30/10/2026), non da una policy RLS esplicita → 'protetto ma "
                      "fragile'. Raccomandazione: abilita la RLS esplicitamente. Verifica definitiva in M8.")
        else:
            detail = (f"GET anonima a /rest/v1/{table}?limit=1 non ha restituito righe: "
                      "l'anon non legge → RLS protegge (§11.1).")
        return PostureCheck(
            check_id=f"POSTURE_RLS_{table}", title=f"RLS attiva sulla tabella '{table}'",
            passed=True, severity_if_failed=Severity.HIGH, target=target,
            detail=detail, remediation_ref="RLS_DISABLED")
```

(Nei due path `_rls_read_test` / `_rls_test_via_bundle` lo status è disponibile allo stesso punto; il via_bundle passa lo status analogamente.)

- [ ] **Step 8 — Run (GREEN):** `python -m pytest tests/test_supabase.py -q` → PASS (inclusi TUTTI i test canary §11.2 esistenti: il refactor NON cambia il loro comportamento). Poi `python -m pytest -q`.

- [ ] **Step 9 — Commit** *(orchestratore):* `git add bastione/modules/supabase/module.py tests/test_supabase.py && git commit -m "feat(m5): supabase core — key kind, legacy/HS256 INFO, GRANT-fragile, wiring storage/rpc/auth/graphql (§4.3)"`

### Task 22: L3 — `server_exposure`: path nuovi, dev server, API spec, body → detector (§4.5)

**Builder: Opus** (PROBE + P8). Dipende da Task 23 (detector nel REGISTRY a runtime).

**Files:** Modify `bastione/modules/server_exposure/module.py`; Test `tests/test_server_exposure.py` (estendi).

**Cambi:** (1) estendi `_SENSITIVE_PATHS` (varianti `.env`, metadati git); (2) nuovo `DEV_SERVER_EXPOSED` (HIGH); (3) nuovo `API_SPEC_EXPOSED` (LOW); (4) il **body** di un file di config esposto passa ai **detector L2** (una chiave trapelata viene identificata e messa in rotazione) — come fa già `_source_maps`, con la stessa redazione P8.

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_server_exposure.py` (riusa `_Resp`, `_ctx`):

```python
def test_env_body_forwarded_to_detectors(monkeypatch):
    import bastione.modules.server_exposure.module as m
    import bastione.modules.secrets.detectors.stripe  # registra SECRET_STRIPE in DETECTORS
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, {"content-type": "text/plain"}, text="STRIPE=sk_live_ABCdef0123456789XYZ")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert "SENSITIVE_ENDPOINT_EXPOSED" in rids and "SECRET_STRIPE" in rids
    secret = next(f for f in res.findings if f.rule_id == "SECRET_STRIPE")
    assert "sk_live_ABCdef0123456789XYZ" not in secret.evidence     # P8 redatto

def test_dev_server_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    def fetch(method, url, *, headers=None):
        if url.endswith("/@vite/client"):
            return _Resp(200, {"content-type": "application/javascript"}, text="export const x=1")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    dev = [f for f in res.findings if f.rule_id == "DEV_SERVER_EXPOSED"]
    assert dev and dev[0].severity.name == "HIGH"

def test_api_spec_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    def fetch(method, url, *, headers=None):
        if url.endswith("/openapi.json"):
            return _Resp(200, {"content-type": "application/json"}, text='{"openapi":"3.0"}')
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = m.ServerExposureModule().run(_ctx())
    spec = [f for f in res.findings if f.rule_id == "API_SPEC_EXPOSED"]
    assert spec and spec[0].severity.name == "LOW"
```

- [ ] **Step 2 — Run (verify fail):** FAIL.

- [ ] **Step 3 — Impl.** Estendi le liste di path (vicino a `_SENSITIVE_PATHS` riga 21) e aggiungi due liste nuove:

```python
_SENSITIVE_PATHS = ["/.env", "/.env.local", "/.env.production", "/.env.development",
                    "/.git/config", "/.git/HEAD", "/api/debug", "/server-status",
                    "/actuator", "/.aws/credentials", "/config.json"]
_API_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs"]
_DEV_SERVER_PATHS = ["/@vite/client", "/__vite_ping"]
```

In `run()`, dopo `self._sensitive_endpoints(...)` aggiungi:

```python
        self._dev_server(base, target, findings)
        self._api_spec(base, target, findings)
```

Modifica `_sensitive_endpoints` perché, dopo aver emesso `SENSITIVE_ENDPOINT_EXPOSED`, inoltri il body ai detector (come `_source_maps`):

```python
    def _sensitive_endpoints(self, base, target, findings) -> None:
        from bastione.modules.secrets.detectors.base import DETECTORS
        for path in _SENSITIVE_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            try:
                ctype = (resp.headers.get("content-type", "") or "").lower()
            except Exception:  # noqa: BLE001
                ctype = ""
            if "text/html" in ctype:
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "SENSITIVE_ENDPOINT_EXPOSED", loc),
                module="server_exposure", rule_id="SENSITIVE_ENDPOINT_EXPOSED",
                title=f"Endpoint sensibile accessibile: {path}", severity=Severity.HIGH,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (content-type {ctype or 'n/d'})",
                description=(f"Il path sensibile {path} risponde 200 (OWASP A05). Blocca l'accesso. "
                             "Il contenuto è passato ai detector segreti (P8: valori redatti)."),
                remediation_ref="SENSITIVE_ENDPOINT_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            # §4.5: inoltra il BODY ai detector L2 — una chiave trapelata va identificata.
            asset = TextAsset(source=path, content=getattr(resp, "text", "") or "")
            for det in DETECTORS:
                try:
                    for raw in det.scan(asset):
                        findings.append(self._secret_finding(det, raw, path, target))
                except Exception:  # noqa: BLE001
                    continue

    def _secret_finding(self, det, raw, path, target) -> Finding:
        loc = Location(endpoint=path, file=path)
        sev = raw.severity_override or det.severity
        return Finding(
            finding_id=_finding_id("server_exposure", raw.detector_id, loc),
            module="server_exposure", rule_id=raw.detector_id,
            title=f"{det.title} (in file di config esposto {path})", severity=sev,
            confidence=Confidence.FIRM, target=target, location=loc,
            evidence=f"{self._redact(raw.value)} (in {path})",
            description=f"Un file di config esposto ({path}) contiene un segreto "
                        f"{raw.detector_id}. Rimuovere il file dall'accesso pubblico e RUOTARE "
                        "il segreto. (P8: valore redatto.)",
            remediation_ref=raw.detector_id, owasp=["A05:2021"],
            gdpr_relevant=det.gdpr_relevant, intrusion_used=IntrusionLevel.PROBE)

    def _dev_server(self, base, target, findings) -> None:
        for path in _DEV_SERVER_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "DEV_SERVER_EXPOSED", loc),
                module="server_exposure", rule_id="DEV_SERVER_EXPOSED",
                title="Dev server raggiungibile pubblicamente", severity=Severity.HIGH,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (endpoint da dev server)",
                description=f"Il path {path} risponde 200: un dev server (es. Vite) è esposto in "
                            "produzione — source non minificato, HMR, superficie estesa. Servi solo "
                            "la build di produzione.",
                remediation_ref="DEV_SERVER_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            return   # un marker basta

    def _api_spec(self, base, target, findings) -> None:
        for path in _API_SPEC_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            try:
                ctype = (resp.headers.get("content-type", "") or "").lower()
            except Exception:  # noqa: BLE001
                ctype = ""
            if "text/html" in ctype:
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "API_SPEC_EXPOSED", loc),
                module="server_exposure", rule_id="API_SPEC_EXPOSED",
                title=f"Specifica API pubblicata: {path}", severity=Severity.LOW,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (content-type {ctype or 'n/d'})",
                description=f"La specifica API {path} è pubblica: utile a un attaccante per mappare "
                            "la superficie. Pubblicala solo se intenzionale.",
                remediation_ref="API_SPEC_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            return
```

Assicurati che `TextAsset` sia importato in testa (`from bastione.models import ... TextAsset`).

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_server_exposure.py -q` → PASS (i test esistenti — `hardened_app_no_findings`, `read_only_skipped_no_requests`, `sensitive_endpoint_exposed` con `.env` non-segreto — restano verdi: l'inoltro ai detector non crea finding segreti se il body non matcha).

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/server_exposure/module.py tests/test_server_exposure.py && git commit -m "feat(m5): server_exposure — path estesi, DEV_SERVER/API_SPEC, body→detector L2 (§4.5)"`

> Nota (non-M5): il modulo definisce `_ERROR_MARKERS` ma non emette mai `VERBOSE_ERROR_LEAK` (gap latente, L3). Fuori scope M5 — annotare per M6 (`headers`/valori).

---

### Task 23: L2 — wiring `detectors/__init__.py` (passo unico finale)

**Builder: Sonnet.** File unico; dipende da Task 8/9/10/11 (i file detector devono esistere).

**Files:** Modify `bastione/modules/secrets/detectors/__init__.py`; Test `tests/test_secrets.py` (estendi).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_secrets.py`:

```python
def test_m5_detectors_registered():
    import importlib
    import bastione.modules.secrets.detectors as pkg
    importlib.reload(pkg)   # assicura l'import del package
    from bastione.modules.secrets.detectors.base import DETECTORS
    ids = {d.detector_id for d in DETECTORS}
    for rid in ("SECRET_SUPABASE_SECRET_KEY", "SECRET_STRIPE", "SECRET_AWS_AKIA",
                "SECRET_GITHUB", "SECRET_NPM", "SECRET_UPSTASH", "SECRET_OPENAI",
                "SECRET_ANTHROPIC", "SECRET_GOOGLE_API_KEY", "SECRET_TELEGRAM_BOT",
                "SECRET_PRIVATE_KEY", "SECRET_HIGH_ENTROPY"):
        assert rid in ids
```

- [ ] **Step 2 — Run (verify fail):** FAIL (solo `SECRET_SERVICE_ROLE` registrato).

- [ ] **Step 3 — Impl:** `bastione/modules/secrets/detectors/__init__.py`:

```python
"""Package detector di segreti (§10). Importare questo package popola DETECTORS
con tutti i detector registrati via @register_detector (§10/§4.4)."""
from __future__ import annotations

from bastione.modules.secrets.detectors import service_role as _service_role  # noqa: F401
from bastione.modules.secrets.detectors import supabase_secret as _supabase_secret  # noqa: F401
from bastione.modules.secrets.detectors import stripe as _stripe  # noqa: F401
from bastione.modules.secrets.detectors import cloud_repo as _cloud_repo  # noqa: F401
from bastione.modules.secrets.detectors import ai_keys as _ai_keys  # noqa: F401
from bastione.modules.secrets.detectors import misc as _misc  # noqa: F401

__all__ = ["_service_role", "_supabase_secret", "_stripe", "_cloud_repo", "_ai_keys", "_misc"]
```

- [ ] **Step 4 — Run (GREEN):** `python -m pytest tests/test_secrets.py -q` → PASS; poi `python -m pytest -q`.

- [ ] **Step 5 — Commit** *(orchestratore):* `git add bastione/modules/secrets/detectors/__init__.py tests/test_secrets.py && git commit -m "feat(m5): registra i detector M5 in DETECTORS (passo unico, §4.4)"`

---

## ONDA 4 — Wiring finale

### Task 24: WF — orchestrator passa i PostureCheck a `build_fix_plan` + README (§4.1)

**Builder: Opus** (orchestrator). Dipende da Task 18 (firma `build_fix_plan`) e, a monte, da tutte le corsie.

**Files:** Modify `bastione/orchestrator.py` (`_remediate` righe 656-662); Modify `README.md`; Test `tests/test_orchestrator.py` (estendi).

> I sottomoduli supabase NON sono Module a sé (li importa `supabase/module.py`) → **nessun cambiamento a `_ensure_modules_loaded`**. I detector M5 entrano in `DETECTORS` via `import bastione.modules.secrets.detectors` (già in `_ensure_modules_loaded`, ora popolato da Task 23).

- [ ] **Step 1 — Test (RED):** aggiungi a `tests/test_orchestrator.py`:

```python
def test_remediate_forwards_posture_checks(monkeypatch, tmp_path):
    import bastione.orchestrator as orch
    from bastione.baseline.diff import BaselineResult
    from bastione.models import PostureCheck, TargetConfig
    from bastione.enums import Severity

    class _P:  # finto FixPlan
        fixes = []
    cap = {}
    monkeypatch.setattr(orch, "build_fix_plan",
        lambda findings, cfg, *, now, run_dir, posture_checks=None: cap.update(pc=posture_checks) or _P())
    monkeypatch.setattr(orch, "write_fix_bundle", lambda plan, rd: None)

    o = orch.Orchestrator(runs_root=tmp_path / "runs", baselines_root=tmp_path / "bl")
    o._cfg = TargetConfig(name="t", base_url="https://s.example", environment="staging", ownership="owned")
    o._run_dir = tmp_path
    pcs = [PostureCheck(check_id="POSTURE_HSTS", title="x", passed=False,
                        severity_if_failed=Severity.MEDIUM, target="t", detail="d")]
    # Costruisci un BaselineResult con findings=[], posture_checks=pcs (adatta ai campi
    # reali di baseline/diff.py:BaselineResult).
    o._result = BaselineResult(findings=[], fixed=[], posture_checks=pcs, counts={})
    o._remediate()
    assert cap["pc"] == pcs
```

> Se il costruttore di `BaselineResult` differisce, il builder legge `bastione/baseline/diff.py` e adatta la costruzione del fixture (i campi usati da `_remediate`/`_report` sono `findings`, `posture_checks`, `fixed`, `counts`).

- [ ] **Step 2 — Run (verify fail):** FAIL (`build_fix_plan` è chiamato senza `posture_checks` → `cap["pc"]` è None, non `pcs`).

- [ ] **Step 3 — Impl:** in `_remediate` (righe 656-661) aggiungi il parametro:

```python
        plan = build_fix_plan(
            self._result.findings,
            self._cfg,
            now=self._now(),
            run_dir=str(self._run_dir),
            posture_checks=self._result.posture_checks,
        )
```

- [ ] **Step 4 — Impl: README.** Aggiungi una riga nella sezione corsie/moduli: _"M5 (2026): recon riconosce le chiavi `sb_publishable_`/`sb_secret_`; sonde Supabase storage/RPC/auth/GraphQL (PROBE, oracle-first); catalogo segreti esteso con liveness presso i provider; `toolcheck` fail-closed (trivy ≥0.72, nuclei ≥3.10); il fix-plan consuma anche i posture falliti."_

- [ ] **Step 5 — Run (GREEN):** `python -m pytest tests/test_orchestrator.py -q` → PASS; poi la suite intera `python -m pytest -q` (ground-truth finale dell'orchestratore).

- [ ] **Step 6 — Commit** *(orchestratore):* `git add bastione/orchestrator.py README.md tests/test_orchestrator.py && git commit -m "feat(m5): orchestrator passa i PostureCheck a build_fix_plan; README corsie 2026 (§4.1)"`

---

## Chiusura milestone (dopo l'ultimo task verde)

Non è un task da builder — lo fa l'orchestratore della sessione:

- [ ] **Ground-truth finale:** `python -m pytest -q` sull'albero stabile — tutti verdi (≥ 925 preesistenti + i nuovi).
- [ ] **Blind-review di branch** sulle dimensioni correctness · sicurezza/P8/gate · robustezza (rinforzata su L1c probe e `agent_bundle`). I finding reali → fixer Opus sequenziati per file.
- [ ] **SESSION-STATE:** nuova §3-x per M5, §7 log, §6 `next_session_goal` = _"validazione live corsie M4+M5 (deciso D7), poi piano M6"_.
- [ ] **Blueprint §27:** aggiorna la roadmap (M5 CHIUSA; M6 next).
- [ ] **Commit + push su `main`** (auto, ai checkpoint).
- [ ] **Sospesi, con motivo nel riepilogo:** validazione live M5 (§4.11, richiede target owned + staging + token pubblicato + ok di Claudio); azione umana trivy ≥ 0.72.0 (Task 17).

---

## Self-Review (eseguita sul piano, spec alla mano)

**1. Copertura spec (§4).** Ogni sotto-sezione M5 ha un task: §4.2 W0→Task 1-2; §4.3 L1→Task 3 (recon), 4-7 (storage/rpc/auth/graphql), 21 (core+key kind+GRANT-fragile+legacy+wiring); §4.4 L2→Task 8-11 + 23 (registrazione); §4.5 L3→Task 22; §4.6 L4→Task 12-13; §4.7 L5→Task 2 (toolcheck), 14-17; §4.8 L6→Task 18-20; §4.9 (rule_id) coperti dai rispettivi task; §4.10 testabilità→ ogni task ha app sintetiche due-varianti + gate-test + P8-test; §4.11 validazione live→ fuori automazione (chiusura); §4.1 wiring→Task 21/23/24. R1-R7 in Global Constraints + per-task. **Nessun gap.**

**2. Placeholder scan.** Nessun "TODO/implementa dopo/gestisci gli edge case": ogni step di codice porta codice reale. Le uniche cose risolte-a-runtime sono dichiarate e deterministiche (SHA delle action via `gh api`; `requirements.lock` via `pip-compile`) — artefatti generati, non placeholder.

**3. Coerenza dei tipi.** `run_storage_checks`/`run_rpc_checks`/`run_auth_posture_checks`/`run_graphql_checks` hanno firma `(ctx, base, headers, [buckets|rpcs], target)` (auth/graphql senza la lista) e ritornano `tuple[list[Finding], list[PostureCheck]]`, invocate così in Task 21. `build_fix_plan(..., posture_checks=None)` (Task 18) ↔ chiamata con `posture_checks=` (Task 24). `RawSecret.severity_override` (Task 1) ↔ letto in `module.py` (Task 1) e scritto da `StripeDetector` (Task 8). `check_tool`→`ToolStatus(ok,version,reason)` (Task 2) ↔ usato in Task 14/15/16. `is_verification_limit` (Task 20, markdown) ↔ importato in html (Task 20). **Coerenti.**

**4. Review Focus.** Le 5 classi sono pinnate: #1 chiave attacker-controllabile → Task 3 (`ignores_service_role`) + Task 21 (owned-only host); #2 RPC effetti/write-capable → Task 5 (`denylisted_name_not_invoked`, `write_capable_tentative_no_post`); #3 bucket name escape → Task 4 (`bucket_name_cannot_escape_host`); #4 toolcheck illeggibile → Task 2 (`unreadable_fail_closed`, `garbage_fail_closed`); #5 nuclei severità/tag → Task 15 (`argv_covers_critical_but_excludes_intrusive`). **Tutte coperte.**

---

## Execution Handoff

**Piano completo e salvato in `docs/superpowers/plans/2026-10-11-bastione-m5-supabase-secrets-correctness.md`.**

Il metodo di esecuzione è **già fissato dal repo** (`BASTIONE-WORKFLOWS.md`, D8): **UN dynamic workflow** per M5, orchestrato dalla sessione Opus 4.8, con builder (Opus/Sonnet per task) → blind-review (Opus) → fixer (Opus) sequenziati per ownership di file, nelle 4 onde del DAG sopra. Equivale a **superpowers:subagent-driven-development** mappato sullo strumento `Workflow`. Ground-truth = l'orchestratore rilancia `python -m pytest -q`; i builder non eseguono git.

Per favore **rivedi il piano** e conferma che cattura ciò che vuoi — in particolare le quattro **decisioni chiuse nel piano** (lockfile pip-tools; timeout zap 30′; denylist RPC; `SIGNUP_NO_EMAIL_CONFIRM` sempre MEDIUM) e le tre **semplificazioni di liveness dichiarate (R6)** (SECRET_SUPABASE_SECRET_KEY e Upstash senza liveness; Google LOW senza promozione a HIGH su liveness). Se approvi, procedo a lanciare il workflow M5.

















