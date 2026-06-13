# BASTIONE — Blueprint v2.1

> **Codename:** BAS · **Versione:** 2.1 (blueprint) · **Stato:** decisioni bloccate, pronto per M0
> **Predecessore:** v1.2 (scanner). Questa è una riscrittura disambiguata + ampliamento di scopo: da *scanner one-shot* a **sistema di difesa continuo**. Il salto di versione è deliberato — vedi §0 e §27.
>
> **Changelog v2.0 → v2.1:** aggiunto l'**Agent Remediation Bundle** (§18-bis) — l'output `fix/` machine-consumable (`FIX-PLAN.md` + `fix-plan.json` + `migrations/*.sql`) pensato per essere dato in pasto a un agente di coding (Claude Code / Codex), con divisione netta agente↔umano, rotazione segreti come passo dedicato, e il **loop di verifica** (`bastione verify`) che chiude il cerchio finding → fix → `FIXED`. Aggiunta la fase `REMEDIATE` alla macchina a stati (§6) e i comandi `fix`/`verify` alla CLI (§25).
>
> **Rev. 2026-06-12 (v2.1, stessa versione):** chiarimenti post-audit di coerenza — gate vs declassamento (§6/§7), semantica `known`/`accepted` (§16/§25), baseline committabile per il CI gate (L05/§22), normalizzazione content-hash nel `finding_id` (§5.2/§16), fasi saltate e `--resume` (§24), risoluzione `<n>.local.toml` (§6/§29), contratti mancanti (§5.6), confine headers/cloudflare (§12), criterio severità RLS (§11.1), fallback bundle senza katana (§8), Appendice A allineata al dev-state. **Nota sul nome file:** resta `BASTIONE-BLUEPRINT-v2.md` per ogni revisione 2.x (i riferimenti incrociati citano il filename); la versione vera è in questa intestazione.
>
> **Tesi (una riga):** Bastione non è uno scanner che lanci una volta. È una **sentinella** che conosce la *baseline* delle tue app, **simula un attaccante esterno** contro infrastruttura che possiedi, **urla quando compare qualcosa di nuovo e pericoloso**, e ti dice **esattamente come ripararlo** — convergendo sempre in SARIF + report + alert.

---

## 0 · Cosa È / Cosa NON È

**È** un orchestratore *sottile* (colla + un modulo custom serio: la sonda Supabase) che, partendo da un URL di una **tua** applicazione:

1. fa **ricognizione** dello stack come farebbe un attaccante (fingerprint);
2. lancia gli scanner adatti a ciò che trova (selezione condizionale);
3. sonda lo strato dati Supabase/PostgREST come un esterno con la chiave pubblica;
4. cerca **segreti esposti** con un catalogo estensibile di detector (stack-agnostico);
5. **verifica i controlli che dovrebbero proteggerti** e ne traccia la *posture* nel tempo;
6. confronta i risultati con una **baseline** e segnala solo ciò che è **nuovo o regredito**;
7. ti consegna **remediation azionabili** e, se configurato, **ti avvisa** (Telegram/email/webhook).

**NON È**:
- un tool da puntare su infrastruttura **non tua**. Si testa **solo** ciò che possiedi, o per cui hai **autorizzazione scritta**. In Italia colpire sistemi altrui è accesso abusivo a sistema informatico (art. 615-ter c.p.), a prescindere dalle intenzioni. → §7 trasforma questo vincolo in **codice**, non in buoni propositi.
- un sostituto di un pentest umano di terza parte (§26, limiti onesti);
- un monolite che riscrive ciò che già esiste (Nuclei, ZAP, WPScan… restano tool esterni invocati, non riscritti);
- un servizio always-on. Niente daemon, niente DefectDojo in v2 (§27, rimandato al primo cliente pagante). Il monitoring è **scansione schedulata + diff baseline + alert**, compatibile con free-tier e cron/GitHub Actions.

### Perché il salto a v2 (cosa cambia rispetto a v1.2)
v1.2 trovava problemi *una volta*. Questo è un atto offensivo travestito da difensivo: vedi una lista di guai e non sai cosa è nuovo, cosa hai già accettato, cosa è regredito, né come ripararlo. v2 aggiunge i quattro pilastri che fanno la differenza tra "scanner" e "difesa": **baseline/drift** (§16), **posture verification** (§17), **remediation** (§18), **alerting + monitoring** (§19–20), più **portfolio** (§21) e **CI gate** (§22). Il motore black-box di v1.2 resta intatto: è il cuore di M0.

---

## 1 · Principi guida (LOCKED)

| # | Principio | Conseguenza implementativa |
|---|-----------|----------------------------|
| P1 | **Owned-only, by code.** | Ogni azione > read-only richiede un *ownership challenge* superato (§7.1). Produzione e target non posseduti sono un *hard block* che aborta. |
| P2 | **Read-only di default.** | Il livello di intrusione di default è `READ_ONLY`. Salire richiede flag espliciti e precondizioni verificate (§7). |
| P3 | **Oracle-first.** | La verità si misura contro un'*attesa dichiarata* (matrice TOML, §15). Senza matrice → modo adversario (ampiezza); con matrice → modo oracolo (profondità). Si sommano. |
| P4 | **Config-as-code, niente GUI.** | Tutto è in TOML versionabile. Nessuna interfaccia punta-e-clicca: forza P3 e rende ogni run riproducibile e auditabile. |
| P5 | **Colla sottile.** | I tool maturi non si riscrivono: si invocano, si normalizza l'output. L'unico custom serio è la sonda Supabase, perché lì *non esiste* un tool che capisca PostgREST/RLS. |
| P6 | **Difesa, non solo scoperta.** | Per ogni finding c'è una *remediation* (§18). Per ogni controllo c'è una *posture check* positiva (§17). La regressione di un controllo è un alert (§16). |
| P7 | **Solo delta.** | Dopo la prima baseline, l'attenzione umana va solo su ciò che è `NEW` o `DRIFT`. Risolve il problema "ri-triare gli stessi falsi positivi ogni volta". |
| P8 | **Segreti redatti.** | L'evidenza nei report è redatta (primi/ultimi 4 char) salvo flag locale esplicito. Un report non deve mai *essere* la fuga di dati. |

---

## 2 · Decisioni — LOCKED / OPEN

### LOCKED
- **L01** Linguaggio: **Python 3.11+**. Motivo: orchestrazione subprocess di binari esterni + libreria httpx per la sonda PostgREST + ecosistema SARIF/TOML/pydantic.
- **L02** Gestione dipendenze: **`uv`** (`pyproject.toml` + `uv sync`). Fallback documentato a `venv + pip`.
- **L03** Validazione config e modelli dati: **pydantic v2**. Ogni contratto è un modello tipato.
- **L04** Output canonico: **SARIF 2.1.0** + report **Markdown** + report **HTML single-file**. (Niente DefectDojo in v2.)
- **L05** Config target: **TOML** (`targets/<nome>.toml`). Segreti non committati (`.gitignore` su `targets/*.local.toml` e su `runs/`, che contiene le evidenze grezze). Le **`baselines/` si committano**: il formato (§16) contiene solo id/status/date, **mai evidenze** — ed è ciò che rende possibile il diff in CI (§22).
- **L06** Tool esterni invocati come subprocess, **rilevati a runtime** (`shutil.which`), **skip graceful con warning** se assenti — mai crash.
- **L07** Modello a 3 livelli di intrusione come **enum + gate eseguibile** (§7). Produzione = hard block.
- **L08** Ownership challenge **obbligatorio** per intrusione > `READ_ONLY` (§7.1).
- **L09** Moduli e detector sono **plugin a registrazione** (drop-in di un file) — §9, §10.
- **L10** Baseline e drift sono **prima classe** (§16): il diff è parte della pipeline, non un extra.
- **L11** Le scritture di prova (canary) sono **staging-only**, con canary marker + cleanup garantito, e sono `MUTATING` (🔴, M2).
- **L12** Liveness validation dei segreti è **read-only**, `PROBE` (🟡), **opt-in**.
- **L13** L'**Agent Remediation Bundle** (§18-bis) è parte della pipeline (fase `REMEDIATE`), non un extra. Contratti LOCKED: divisione netta **artefatto letterale** (SQL/header/config → pronti all'uso) vs **intent+hint** (fix di codice → l'agente li localizza nel sorgente, perché il black-box non ha il repo); campo `applicable_by` (agente/umano/misto); la **rotazione segreti** è sempre `priority=1` e ha un passo umano obbligatorio; ogni fix ha un **criterio di accettazione verificabile** (`bastione verify`).

### OPEN (da decidere insieme prima di toccarli)
- **O01** Notifier prioritario per te: Telegram, email SMTP, o webhook generico? (default proposto: **Telegram**, perché bot+chat_id è il setup più rapido e già lo usi per i progetti.)
- **O02** HTML report: tema scuro/chiaro, e se includere un *posture score gauge*. (Proposta: single-file, dark, con gauge.)
- **O03** Soglia di default del CI gate: `HIGH` o `CRITICAL`? (Proposta: `HIGH`.)
- **O04** Concorrenza moduli read-only: `asyncio` o `ThreadPoolExecutor`? (Proposta: `ThreadPoolExecutor`, più semplice da ragionare; i mutating sono comunque serializzati.)
- **O05** L'Agent Remediation Bundle (§18-bis) si genera **sempre** a fine run o solo con `--emit-fix` / `bastione fix`? (Proposta: **sempre** quando ci sono finding aperti — è leggero e a costo zero, e il valore percepito è alto. Disattivabile con `--no-fix`.) *Nota di confine con L13:* L13 blocca **che** il bundle sia parte della pipeline (fase `REMEDIATE`); questa OPEN decide **solo** il default sempre/opt-in. Le menzioni in §6 e §25 riportano la proposta, non una decisione presa.

---

## 3 · Stack & dipendenze (LOCKED)

**Runtime Python (in `pyproject.toml`):**
- `pydantic>=2.6` — modelli/validazione
- `httpx>=0.27` — chiamate alla sonda Supabase/HTTP (timeout, retry)
- `typer>=0.12` — CLI
- `rich>=13` — output terminale leggibile
- `tomli` (py<3.11) / `tomllib` (stdlib ≥3.11) — lettura TOML
- `jinja2>=3.1` — template report HTML/MD e playbook
- `python-dotenv>=1` — env per i notifier (token, SMTP)
- `dnspython>=2` — lookup DNS TXT per l'ownership challenge (§7.1; serve solo per run > read-only)

**Tool esterni (binari, opzionali, rilevati a runtime):**

| Tool | Usato in | Note |
|------|----------|------|
| `httpx` (projectdiscovery) | RECON | sonda HTTP veloce, multi-host. *Nota:* binario diverso dalla lib Python `httpx`; nel codice usare il path assoluto/flag. |
| `katana` | RECON | crawling/endpoint discovery |
| `whatweb` | RECON | fingerprint tecnologie |
| `nuclei` | M1 | template-based vuln scan |
| `wpscan` | WordPress (cond.) | richiede token API per CVE |
| `testssl.sh` | transport | TLS/cipher |
| `trivy` | M1 | dipendenze/misconfig (se white-box/repo locale) |
| `zaproxy` (ZAP) | M1 | DAST attivo (PROBE/MUTATING) |
| `sqlmap` | M2 | SOLO oracle+staging, gated |

Il modulo `recon`/i moduli devono degradare con eleganza: se `whatweb` manca, il fingerprint usa solo `httpx`+euristiche header; se `nuclei` manca, il modulo logga `SKIPPED (nuclei non installato)` e prosegue.

---

## 4 · Struttura del repository

```
bastione/
├── pyproject.toml
├── README.md
├── bastione/                       # package
│   ├── __init__.py
│   ├── cli.py                      # entrypoint typer (§25)
│   ├── config.py                   # load + validate TOML → TargetConfig (§5,§29)
│   ├── orchestrator.py             # macchina a stati (§6)
│   ├── models.py                   # TUTTI i contratti dati (§5)
│   ├── enums.py                    # Severity, Confidence, Status, IntrusionLevel, Phase
│   ├── gate.py                     # gate di intrusione + ownership challenge (§7)
│   ├── recon/
│   │   ├── __init__.py
│   │   └── fingerprint.py          # → Fingerprint (§8)
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── base.py                 # Module ABC + REGISTRY (§9)
│   │   ├── secrets/
│   │   │   ├── module.py           # SecretLeakModule (§10)
│   │   │   └── detectors/          # un file = un detector (plugin)
│   │   │       ├── base.py         # Detector ABC + REGISTRY
│   │   │       ├── supabase_service_role.py
│   │   │       ├── aws_akia.py
│   │   │       ├── stripe.py
│   │   │       ├── github.py
│   │   │       ├── upstash.py
│   │   │       ├── private_key.py
│   │   │       └── high_entropy.py
│   │   ├── supabase/module.py      # la gemma — sonda PostgREST (§11)
│   │   ├── cloudflare/module.py    # origin reachability / bypass WAF (§12 — gli header sono in headers/)
│   │   ├── headers/module.py       # security headers + TLS (§12)
│   │   ├── wordpress/module.py     # wrapper WPScan (§13)
│   │   ├── nuclei/module.py        # wrapper nuclei (§14)
│   │   └── zap/module.py           # wrapper ZAP (§14)
│   ├── normalize/sarif.py          # Finding[] → SARIF 2.1.0 (§23)
│   ├── posture/checks.py           # PostureCheck engine + score (§17)
│   ├── baseline/diff.py            # baseline load/save + drift (§16)
│   ├── remediation/
│   │   ├── playbooks.py            # mapping rule_id → playbook umano (§18)
│   │   └── agent_bundle.py         # FixBuilder REGISTRY → bundle fix/ per agente (§18-bis)
│   ├── report/
│   │   ├── markdown.py             # report MD (§23)
│   │   └── html.py                 # report HTML single-file (§23)
│   ├── notify/
│   │   ├── base.py                 # Notifier ABC (§19)
│   │   ├── telegram.py
│   │   ├── email.py
│   │   └── webhook.py
│   └── state.py                    # stato runtime per-scan, resume (§24 — NON è il SESSION-STATE di progetto)
├── targets/
│   ├── _example.toml               # template commentato (§29)
│   └── gestionale.local.toml       # config reale (gitignored)
├── portfolio.toml                  # lista target per scan-all (§21)
├── playbooks/                      # template MD remediation per rule_id (§18)
├── baselines/                      # <target>.baseline.json (§16)
└── runs/                           # output: runs/<target>/<timestamp>/{sarif,report.md,report.html,raw/,fix/,state.json}
                                    #   fix/ = FIX-PLAN.md + fix-plan.json + migrations/*.sql (§18-bis)
```

**Regola per Claude Code:** la struttura sopra è **normativa**. Non inventare cartelle. Un nuovo detector = nuovo file in `modules/secrets/detectors/`. Un nuovo modulo = nuova cartella in `modules/`. Nient'altro.

---

## 5 · Modello dati — i contratti (in `models.py`)

Questi sono i **contratti universali**. Ogni modulo *produce* `Finding` e/o `PostureCheck`; nessun modulo inventa il proprio formato. Tutte le classi sono `pydantic.BaseModel`.

### 5.1 Enum (in `enums.py`)
```python
class Severity(IntEnum):       # ordinabile, per soglie e score
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4

class Confidence(str, Enum):
    FIRM = "firm"              # verificato (es. RLS off confermato da una GET)
    TENTATIVE = "tentative"    # euristico (es. stringa ad alta entropia)

class Status(str, Enum):
    NEW = "new"                # assente dalla baseline
    KNOWN = "known"            # presente in baseline, non accettato
    ACCEPTED = "accepted"      # presente in baseline e accettato (rumore noto)
    FIXED = "fixed"            # in baseline ma non più riscontrato in questa run
    DRIFT = "drift"            # SOLO per posture check passante→fallito (PostureCheck.drift, §5.4/§16);
                               # mai assegnato a Finding.status — nei report/counts indica la regressione

class IntrusionLevel(IntEnum):
    READ_ONLY = 0              # 🟢 passivo: recon, GET, detection segreti
    PROBE     = 1              # 🟡 attivo non-mutante: liveness, tentativi di lettura RLS
    MUTATING  = 2              # 🔴 scrittura: canary INSERT/UPDATE/DELETE

class Phase(str, Enum):
    LOAD="load"; OWNERSHIP="ownership"; RECON="recon"; PLAN="plan"
    SCAN="scan"; NORMALIZE="normalize"; BASELINE="baseline"
    POSTURE="posture"; REPORT="report"; REMEDIATE="remediate"
    NOTIFY="notify"; PERSIST="persist"
```

### 5.2 `Location`
```python
HASH_SEGMENT = re.compile(r"[-.][0-9a-f]{6,}(?=\.\w+$)", re.I)  # "index-ab12cd.js" → "index.js"

class Location(BaseModel):
    url: str | None = None
    endpoint: str | None = None        # es. "/rest/v1/clienti"
    file: str | None = None            # es. "assets/index-ab12.js"
    line: int | None = None

    def canonical(self) -> str:
        # usata per il finding_id stabile (§16). NON include evidenza.
        # Il campo file è normalizzato dai suffissi content-hash dei bundle:
        # senza, ogni deploy rinomina il bundle, cambia il finding_id e genera
        # falsi NEW/FIXED — minando P7 (solo delta).
        file_norm = HASH_SEGMENT.sub("", self.file) if self.file else None
        return "|".join(str(x) for x in (self.url, self.endpoint, file_norm, self.line))
```

### 5.3 `Finding` (il contratto principale)
```python
class Finding(BaseModel):
    finding_id: str                    # vedi §16 — hash stabile per dedup/drift
    module: str                        # es. "supabase", "secrets"
    rule_id: str                       # es. "RLS_DISABLED", "SECRET_SERVICE_ROLE"
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    location: Location
    evidence: str                      # SEMPRE redatto in output salvo --unsafe-show-secrets
    description: str
    remediation_ref: str | None = None # chiave playbook (§18), es. "RLS_DISABLED"
    owasp: list[str] = []              # es. ["A01:2021","A05:2021"]
    gdpr_relevant: bool = False        # dati personali esposti? (rilevante per te)
    cvss: float | None = None
    intrusion_used: IntrusionLevel = IntrusionLevel.READ_ONLY
    first_seen: datetime | None = None # valorizzato in BASELINE
    last_seen: datetime | None = None
    status: Status = Status.NEW        # valorizzato in BASELINE
```

### 5.4 `PostureCheck` (la verifica positiva — §17)
```python
class PostureCheck(BaseModel):
    check_id: str                      # es. "POSTURE_HSTS", "POSTURE_SERVICE_ROLE_HIDDEN"
    title: str
    passed: bool
    severity_if_failed: Severity       # peso nel posture score
    target: str
    detail: str                        # cosa è stato verificato
    remediation_ref: str | None = None
    drift: bool = False                # True se in baseline era passed e ora è failed (§16) —
                                       # valorizzato in POSTURE; è qui che vive Status.DRIFT
```

### 5.5 Supporto
```python
class Fingerprint(BaseModel):          # output di RECON (§8)
    target: str
    resolved_urls: list[str]
    technologies: list[dict]           # [{"name","version","confidence"}]
    is_wordpress: bool = False
    is_supabase: bool = False          # PostgREST rilevato
    supabase_url: str | None = None
    anon_key: str | None = None        # pubblica per design, estratta dal bundle
    cloudflare_fronted: bool = False
    endpoints: list[str] = []
    response_headers: dict[str, str] = {}

class TextAsset(BaseModel):            # input ai detector di segreti (§10)
    source: str                        # url o path del file
    content: str

class RawSecret(BaseModel):
    detector_id: str
    value: str                         # valore grezzo (redatto in output)
    location: Location
    entropy: float | None = None

class LivenessResult(BaseModel):
    alive: bool
    mode: str | None = None            # es. "live", "test", "revoked"
    detail: str = ""

class RunContext(BaseModel):           # passato a ogni modulo
    target_cfg: "TargetConfig"
    fingerprint: Fingerprint
    max_intrusion: IntrusionLevel      # tetto effettivo della run (§7)
    run_dir: Path
    ownership_verified: bool
```

### 5.6 Config e aggregati (completano il contratto — niente shape improvvisate)
```python
class TableExpectation(BaseModel):     # [[expectations.table]] del TOML (§15)
    name: str
    anon_select: bool = False
    anon_insert: bool = False

class TargetConfig(BaseModel):         # prodotto da config.py: parse+validate del TOML (§29)
    name: str
    base_url: str
    environment: Literal["staging", "production"]
    ownership: Literal["owned", "authorized-written"]
    ownership_token: str | None = None # richiesto solo per run > READ_ONLY (§7.1)
    supabase_url: str | None = None    # [supabase].url, opzionale (il recon può scoprirlo)
    notify_channel: str = "none"       # [notify].channel
    notify_min_severity: Severity = Severity.HIGH   # [notify].min_severity (il flag --fail-on ha precedenza, §25)
    expectations: list[TableExpectation] = []       # §15 (M2)
    modules_disabled: list[str] = []   # [modules].disabled

class ModuleResult(NamedTuple):        # valore di ritorno di Module.run (§9)
    findings: list[Finding]
    posture_checks: list[PostureCheck]

class RunSummary(BaseModel):           # input dei Notifier (§19)
    target: str
    posture_score: float
    counts: dict                       # stessa shape di state.json (§24)
    drift_count: int
    report_path: str                   # link al report HTML
```

> **Disambiguazione chiave:** un modulo che vuole eseguire un'azione di livello L deve passare da `RunContext` → il gate (§7) decide se L è ammesso. Un modulo **non** legge flag globali da sé.

---

## 6 · Il motore: macchina a stati (in `orchestrator.py`)

Pipeline **ordinata, deterministica, idempotente, resumable**. Ogni fase ha pre/postcondizioni esplicite. La fase completata è salvata in `state.json` (§24): un re-run con `--resume` riparte dalla prima fase non completata.

| # | Fase | Precondizione | Azione | Postcondizione |
|---|------|---------------|--------|----------------|
| 1 | `LOAD` | esiste `targets/<n>.local.toml` **o** `targets/<n>.toml` (il `.local.toml` ha precedenza — è la config reale gitignored, §4/§29) | parse+validate → `TargetConfig`; **assert preconditions** (§7: `environment != production`; `ownership` dichiarato) | config valida in memoria |
| 2 | `OWNERSHIP` | `max_intrusion > READ_ONLY` | esegui ownership challenge (§7.1) | `ownership_verified=True` o **abort** |
| 3 | `RECON` | config valida | fingerprint (§8) → `Fingerprint` + `fingerprint.json` | fingerprint disponibile |
| 4 | `PLAN` | fingerprint pronto | per ogni modulo in REGISTRY: `should_run(fp,cfg)` → lista moduli attivi | piano deterministico |
| 5 | `SCAN` | piano pronto | esegui moduli: read-only in parallelo, `MUTATING` **serializzati**; ogni azione passa dal gate (§7) | `list[Finding]` + `list[PostureCheck]` grezzi |
| 6 | `NORMALIZE` | scan completo | redazione evidenze; dedup; mapping OWASP/CVSS | findings normalizzati |
| 7 | `BASELINE` | findings normalizzati | carica baseline; calcola `finding_id`; setta `status`, `first_seen/last_seen` (§16) | findings con stato |
| 8 | `POSTURE` | posture checks raccolti | confronta con posture-baseline → marca `DRIFT`; calcola **posture score** (§17) | score + drift |
| 9 | `REPORT` | tutto valorizzato | scrivi SARIF + MD + HTML in `run_dir` (§23) | report su disco |
| 10 | `REMEDIATE` | ≥1 finding aperto (`NEW`/`KNOWN`) con `remediation_ref` *(trigger "sempre" = proposta O05; `--no-fix` per saltare)* | costruisci il bundle `fix/` (`FIX-PLAN.md` + `fix-plan.json` + `migrations/*.sql`) per l'agente di coding (§18-bis) | bundle su disco |
| 11 | `NOTIFY` | notifier configurato **e** (≥1 finding `NEW`≥soglia **o** ≥1 `DRIFT`) | invia alert (§19) | alert inviato/loggato |
| 12 | `PERSIST` | — | salva `state.json`; se `--accept-baseline`, aggiorna baseline (§16) | stato persistito |

**Regole motore (LOCKED):**
- Un fallimento di un singolo modulo è **catturato e loggato come errore di modulo**; non interrompe gli altri (resilienza). Il finding-set finale include un meta-finding `MODULE_ERROR` (severity INFO) per tracciabilità.
- `SCAN` con `MUTATING` attivo richiede `ownership_verified=True` **e** `environment == staging`. **Chi fa cosa (disambiguazione):** il **declassamento è compito dell'orchestratore** — in `PLAN`, se le precondizioni non sono soddisfatte, abbassa il tetto dei moduli mutanti a `PROBE`/`READ_ONLY` con warning esplicito nel report. Il **gate (§7) non declassa mai**: se un'azione non ammessa lo raggiunge comunque, `authorize` solleva `IntrusionDenied`. Difesa in profondità: il declassamento è cortesia UX, l'abort del gate è la garanzia.

---

## 7 · Sicurezza operativa: livelli di intrusione + gate (in `gate.py`) — il cuore

Questo è il modulo che trasforma il vincolo legale/etico in **codice eseguibile**. Nessuna azione attraversa il sistema senza passare di qui.

```python
class IntrusionDenied(Exception): ...

def assert_preconditions(cfg: TargetConfig) -> None:
    # eseguito in LOAD — hard block
    if cfg.environment == "production":
        raise IntrusionDenied(
            "Bastione non opera su 'production'. Punta lo staging. "
            "(P1/P2 — produzione è sempre bloccata.)")
    if cfg.ownership not in ("owned", "authorized-written"):
        raise IntrusionDenied(
            "Manca dichiarazione di proprietà/autorizzazione. "
            "Imposta ownership='owned' o 'authorized-written'.")

def authorize(action: IntrusionLevel, ctx: RunContext) -> None:
    # chiamato da OGNI modulo prima di un'azione
    if action > ctx.max_intrusion:
        raise IntrusionDenied(f"Azione {action.name} > tetto run {ctx.max_intrusion.name}")
    if action >= IntrusionLevel.PROBE and not ctx.ownership_verified:
        raise IntrusionDenied("PROBE/MUTATING richiede ownership challenge superato (§7.1)")
    if action >= IntrusionLevel.MUTATING and ctx.target_cfg.environment != "staging":
        raise IntrusionDenied("MUTATING consentito solo su environment='staging'")
```

> **Il gate non declassa, aborta.** L'eventuale declassamento "morbido" (mutating → probe con warning) avviene **prima**, nell'orchestratore in fase `PLAN` (§6). Se un'azione arriva qui senza i requisiti, l'unica risposta è `IntrusionDenied`: il gate è il backstop, non un negoziatore.

**Matrice operativa (la tua tabella a 3 livelli, resa eseguibile):**

| Livello | Simbolo | Esempi di azione | Gate |
|---------|---------|------------------|------|
| `READ_ONLY` | 🟢 | recon, GET su PostgREST, parsing bundle, detection segreti | sempre permesso entro il tetto |
| `PROBE` | 🟡 | liveness segreti (GET a Stripe/GitHub con la *tua* chiave trovata), tentativi di lettura cross-RLS, ZAP passive | richiede ownership verificata + tetto ≥ PROBE |
| `MUTATING` | 🔴 | canary INSERT/UPDATE/DELETE, ZAP active/attack, sqlmap | staging-only + ownership + tetto = MUTATING + conferma |
| **BLOCKED** | ⛔ | target non posseduto, produzione | **hard block in `assert_preconditions`** |

Il tetto della run è impostato da `--max-intrusion` (default `read-only`). Per `MUTATING` serve **anche** conferma interattiva, oppure il flag esplicito `--i-own-this-its-staging` per esecuzioni non interattive (CI/cron) — che è autodescrittivo e finisce nei log.

### 7.1 Ownership challenge (in `gate.py`)
Prova *minima ma verificabile* di proprietà, richiesta per qualsiasi intrusione > `READ_ONLY`. Stessa logica con cui Search Console / Let's Encrypt verificano il dominio. È **sia** una garanzia di sicurezza **sia** una funzionalità vendibile (auditabile: dimostra che hai toccato solo ciò che eri autorizzato a toccare).

Due metodi, almeno uno deve passare:
1. **File well-known:** la config dichiara `ownership_token = "<uuid>"`; Bastione fa GET di `https://<host>/.well-known/bastione-ownership.txt` e verifica che contenga il token.
2. **DNS TXT:** record `_bastione.<host>` con valore = token.

```python
def verify_ownership(cfg: TargetConfig) -> bool:
    if cfg.ownership_token is None:
        return False
    return _check_wellknown(cfg) or _check_dns_txt(cfg)
```
Se entrambi falliscono → `OWNERSHIP` aborta la run con messaggio che spiega come pubblicare il token. Il **recon read-only** (M0) **non** richiede il challenge: leggere ciò che è pubblico non è intrusione.

---

## 8 · Fase RECON / fingerprint (in `recon/fingerprint.py`)

**Input:** `target` (URL base). **Output:** `Fingerprint` + `runs/<t>/<ts>/fingerprint.json`. **Intrusione:** `READ_ONLY`.

Passi (degradano se un tool manca):
1. `httpx` (projectdiscovery) → URL risolti, status, header, redirect chain → popola `resolved_urls`, `response_headers`, `cloudflare_fronted` (header `cf-ray`/`server: cloudflare`).
2. `whatweb` → `technologies`, `is_wordpress` (presenza WordPress).
3. `katana` → crawling → `endpoints`. Da qui si estraggono i bundle JS (`assets/*.js`). **Fallback senza katana (built-in, obbligatorio):** parsing dei tag `<script src>` delle pagine in `resolved_urls` via httpx (lib). La scoperta dei bundle — e quindi il passo 4 — **non deve dipendere** da un tool opzionale: altrimenti la Definition of Done di M0 (anon key estratta) diventerebbe irraggiungibile con un binario assente.
4. **Estrazione Supabase (custom, read-only):** scarica i bundle JS referenziati e cerca:
   - `https://<ref>.supabase.co` → `supabase_url`, setta `is_supabase=True`;
   - la **anon key** (JWT con claim `"role":"anon"`) → `anon_key`. È **pubblica per design** (sta nel client): estrarla è esattamente ciò che fa un attaccante, ed è legittimo perché è esposta apposta.

> **Nota di framing (LOCKED, da non confondere mai nel codice/report):** la **anon key** è pubblica → la sonda la usa per testare *cosa* l'anon può raggiungere (è RLS che deve proteggere). La **service_role key** NON deve mai stare nel client: se la trovi nel bundle (§10) è una fuga **critica**, l'unico "superuser" raggiungibile dall'esterno.

---

## 9 · Selezione moduli (in `modules/base.py`)

Tutti i moduli ereditano da `Module` e si auto-registrano nel `REGISTRY` (decoratore). `PLAN` interroga `should_run`.

```python
class Module(ABC):
    name: str
    max_intrusion: IntrusionLevel          # la più alta che il modulo può richiedere
    @abstractmethod
    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool: ...
    @abstractmethod
    def run(self, ctx: RunContext) -> ModuleResult: ...   # ModuleResult = (findings, posture_checks)

REGISTRY: dict[str, Module] = {}
def register(cls): REGISTRY[cls.name] = cls(); return cls
```

Esempi di `should_run` (deterministici):
- `secrets` → **sempre** `True` (stack-agnostico).
- `supabase` → `fp.is_supabase and fp.anon_key is not None`.
- `wordpress` → `fp.is_wordpress`.
- `cloudflare`/`headers` → `True` se ci sono `resolved_urls`.
- `nuclei`/`zap` → `True` ma solo da M1 in poi e se il binario esiste.

---

## 10 · Modulo Secret-leak — §18 del v1.2, qui catalogo estensibile (in `modules/secrets/`)

Il modulo a più alta leva e l'unico vero punto di generalizzazione stack-agnostica. Due stadi:
- **Stadio 1 — Detection (sempre attivo, `READ_ONLY`):** scansiona ogni `TextAsset` (bundle JS, pagine, file esposti, `.env` raggiungibili, `.git/config`, sourcemap) con tutti i `Detector` registrati.
- **Stadio 2 — Liveness (opt-in, `PROBE` 🟡):** per i segreti che lo supportano, verifica *read-only* se sono vivi. Disattivo salvo `--max-intrusion ≥ probe` **e** ownership verificata.

### 10.1 Detector contract (in `modules/secrets/detectors/base.py`)
```python
class Detector(ABC):
    detector_id: str                # es. "SECRET_SERVICE_ROLE"
    title: str
    severity: Severity
    gdpr_relevant: bool = False
    @abstractmethod
    def scan(self, asset: TextAsset) -> list[RawSecret]: ...
    def validate_liveness(self, s: RawSecret) -> LivenessResult | None:
        return None                 # default: nessuna verifica liveness

DETECTORS: list[Detector] = []
def register_detector(cls): DETECTORS.append(cls()); return cls
```

### 10.2 Catalogo iniziale (un file per detector — drop-in)
| `detector_id` | Pattern/criterio | Severity | Liveness (read-only, PROBE) |
|---|---|---|---|
| `SECRET_SERVICE_ROLE` | JWT con `"role":"service_role"` | **CRITICAL** | GET `…/rest/v1/?` con `Range:0-0` e header service_role: se 200 con privilegi → `alive` |
| `SECRET_AWS_AKIA` | `AKIA[0-9A-Z]{16}` | HIGH | (nessuna chiamata AWS in v2 — solo flag) |
| `SECRET_STRIPE` | `sk_live_…` / `sk_test_…` / `rk_…` | HIGH/CRITICAL | GET `https://api.stripe.com/v1/account` → live/test/revoked |
| `SECRET_GITHUB` | `ghp_…`,`gho_…`,`ghs_…`,`github_pat_…` | HIGH | GET `https://api.github.com/user` → identità/scope |
| `SECRET_UPSTASH` | URL+token REST Upstash | HIGH | GET read-only di un comando innocuo (`PING`) |
| `SECRET_PRIVATE_KEY` | blocco `-----BEGIN … PRIVATE KEY-----` | **CRITICAL** | nessuna |
| `SECRET_HIGH_ENTROPY` | stringa ≥ soglia entropia di Shannon, fuori da allowlist | LOW (`TENTATIVE`) | nessuna |

**Regole (LOCKED):**
- Liveness fa **solo GET / chiamate identità**, mai operazioni mutanti, anche quando la chiave lo permetterebbe.
- L'evidenza di ogni `RawSecret` è **redatta** in output (`sk_live_…1a2b`). Reveal completo solo con `--unsafe-show-secrets` (uso locale, mai in CI).
- Entropia: allowlist per ridurre rumore (hash di asset, UUID noti, chiavi pubbliche). `SECRET_HIGH_ENTROPY` è sempre `TENTATIVE`.

---

## 11 · Modulo Supabase probe — la gemma (in `modules/supabase/module.py`)

Il differenziatore: **nessun scanner generico capisce PostgREST/RLS**. Qui sta il valore proprietario. Tutto **read-only** in M0; le scritture sono M2 e gated.

**Precondizione:** `fp.is_supabase and fp.anon_key`. Usa `anon_key` (pubblica) come farebbe un esterno.

### 11.1 Controlli READ_ONLY (M0) — produce sia Finding sia PostureCheck
1. **OpenAPI surface map:** PostgREST espone lo schema alla root (`GET <supabase_url>/rest/v1/`). Parsalo per enumerare **tutte le tabelle/view e RPC esposte**. Questo è oro: ti dà l'intera superficie senza indovinare.
2. **RLS read test (il controllo principe):** per ogni tabella scoperta, `GET <supabase_url>/rest/v1/<tabella>?limit=1` con la anon key.
   - 200 con righe → **`RLS_DISABLED`** o policy SELECT troppo permissiva → Finding. **Criterio severità (LOCKED):** `CRITICAL` se la tabella contiene dati personali (euristica su nomi colonna: email, nome, telefono, cf… → anche `gdpr_relevant=True`) **o** se viola un'attesa della matrice §15; altrimenti `HIGH`.
   - 200 vuoto / 401 / 403 → **PostureCheck `POSTURE_RLS_<tabella>` = passed**.
3. **Storage buckets:** `GET <supabase_url>/storage/v1/bucket` e tentativo di listing oggetti dei bucket pubblici (read-only). Oggetti elencabili/scaricabili senza auth → `STORAGE_PUBLIC_LISTABLE` (severity per sensibilità).
4. **RPC enumeration:** dalle RPC nello schema, flagga quelle invocabili da anon. Tentativo **read-only** di chiamata solo se chiaramente non-mutante (euristica su nome: `get_`, `list_`, `search_`); altrimenti solo *flag di esistenza*. SECURITY DEFINER non è verificabile black-box → finding `TENTATIVE` con nota.
5. **Auth posture:** signup aperto? endpoint admin esposti? (read-only) → PostureCheck/Finding.
6. **service_role hidden (PostureCheck):** conferma che la service_role **non** è raggiungibile dal bundle (incrocio con §10). Passa = `POSTURE_SERVICE_ROLE_HIDDEN`.

### 11.2 Controlli MUTATING (M2, 🔴, staging-only + ownership)
- **Canary write test:** anon `POST` di una riga con marker (`__bastione_canary_<runid>`), poi verifica se è stato accettato (= policy INSERT mancante → `RLS_WRITE_OPEN`), poi **cleanup garantito** (DELETE del canary; se il DELETE fallisce, finding `CANARY_CLEANUP_FAILED` con istruzioni manuali). Idem UPDATE/DELETE mirati al solo canary.
- Passa dal gate `authorize(MUTATING, ctx)`: aborta se non staging / non owned.

> **Disambiguazione per Claude Code:** in M0 implementa **solo** §11.1. Lascia §11.2 come stub che solleva `NotImplementedError("M2")`. Non anticipare scritture.

---

## 12 · Modulo Cloudflare / headers / transport (in `modules/cloudflare/`, `modules/headers/`)

`READ_ONLY`. Produce soprattutto **PostureCheck** (positivi) + Finding dove mancano.

**Confine tra i due moduli (LOCKED):** security headers + TLS → modulo `headers` (gira su qualsiasi target con `resolved_urls`); origin reachability → modulo `cloudflare` (gira solo se `cloudflare_fronted`). Nessuna sovrapposizione: gli header li emette **solo** `headers`.
- **Security headers:** verifica presenza/valore di `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/CSP `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`. Ognuno → PostureCheck pass/fail (replica della logica di securityheaders.com, senza dipendere dal servizio).
- **TLS:** se `testssl.sh` presente, esegui e mappa cipher deboli/protocolli obsoleti → Finding. Altrimenti, check minimo via httpx (versione TLS negoziata).
- **Origin reachability (Cloudflare):** se `cloudflare_fronted`, verifica che l'IP origine non sia raggiungibile direttamente bypassando Cloudflare (euristica DNS/storico). Origine esposta → `ORIGIN_BYPASSABLE` (HIGH): vanifica il WAF.

---

## 13 · Modulo WordPress (in `modules/wordpress/module.py`)
`should_run = fp.is_wordpress`. Wrapper di **WPScan** (`PROBE`). Senza token API → versione/enumerazione base, con warning che le CVE richiedono token. Normalizza l'output JSON di WPScan in `Finding`.

---

## 14 · Moduli black-box esterni (M1) (in `modules/nuclei/`, `modules/zap/`)
Colla sottile attorno a binari maturi. Ognuno:
1. controlla `which`; se assente → `SKIPPED` (Finding INFO), prosegue;
2. invoca con output JSON in `run_dir/raw/`;
3. parsa e normalizza → `Finding[]` (mapping severità tool → `Severity`, dedup via `finding_id`).
- **nuclei:** template-based, `PROBE` (passive/safe templates di default). Active templates solo con tetto ≥ MUTATING.
- **ZAP:** passive scan = `PROBE`; active/attack = `MUTATING` (gated).
- **trivy:** solo se è disponibile il sorgente/repo locale (white-box, M3) → dipendenze/misconfig.

---

## 15 · Modo Oracolo: matrice di attese (M2) (in `config.py` + consumo nei moduli)

Senza matrice = **adversario** (ampiezza: "questo è raggiungibile"). Con matrice = **oracolo** (profondità: "questo è raggiungibile **e non dovrebbe esserlo**"). La matrice vive nel TOML del target:

```toml
[expectations]
# per-tabella: chi DOVREBBE poter leggere/scrivere
[[expectations.table]]
name = "clienti"
anon_select = false          # l'anon NON deve leggere → se legge = CRITICAL confermato
anon_insert = false
[[expectations.table]]
name = "listino_pubblico"
anon_select = true           # lettura attesa → 200 con righe = OK, non un finding
```

Effetto: in `BASELINE`/`NORMALIZE`, un risultato che **viola** un'attesa sale di confidenza a `FIRM` e di severità; un risultato **conforme** all'attesa viene declassato/soppresso. È ciò che chiude gli ambigui da solo.

---

## 16 · Baseline & drift detection — il kernel di difesa (in `baseline/diff.py`)  ★NEW

Il pezzo che trasforma lo scanner in difesa. Risolve P7 (solo delta) e abilita il monitoring (§20).

**`finding_id` stabile (LOCKED):**
```python
finding_id = sha256(f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]
```
Esclude l'evidenza apposta: lo stesso problema mantiene lo stesso id tra run anche se il testo dell'evidenza cambia. → tracciabilità nel tempo. `location.canonical()` normalizza inoltre i content-hash dei bundle (§5.2): senza, ogni deploy rinominerebbe `index-ab12.js` e lo stesso segreto produrrebbe un falso `NEW` + un falso `FIXED` a ogni build.

**Formato baseline** `baselines/<target>.baseline.json`:
```json
{
  "target": "gestionale",
  "updated_at": "…",
  "findings": { "<finding_id>": {"status":"accepted|known","first_seen":"…"} },
  "posture": { "<check_id>": {"passed": true} }
}
```

**Algoritmo di diff (fase BASELINE + POSTURE):**
- finding presente in baseline → eredita `first_seen`, `status` = `accepted`/`known`; `last_seen` = ora.
- finding assente in baseline → `status = NEW`, `first_seen = last_seen = ora`.
- finding in baseline ma **non** in questa run → emesso come `FIXED` (positivo! da mostrare nel report come "risolto").
- posture check che in baseline era `passed:true` e ora è `false` → **`DRIFT`** (campo `PostureCheck.drift=True`, §5.4; finisce in `counts.drift` e nella sezione DRIFT del report): è l'alert più importante per la difesa.

**Aggiornamento baseline:** mai automatico, e in **due gradini distinti** (così `KNOWN` e `ACCEPTED` restano entrambi raggiungibili):
1. `--accept-baseline` (in PERSIST) scrive i `NEW` correnti in baseline con `status="known"`: smettono di gridare come NEW ma restano **aperti e visibili** nel report.
2. La promozione ad `accepted` (rumore noto, silenziato dagli alert) è **selettiva e deliberata**: `bastione baseline --target <n> --accept <finding_id>` (§25), un finding alla volta.

Flusso umano: rivedi i NEW → `--accept-baseline` per riconoscerli (`known`) → accetti singolarmente il rumore (`accepted`) → da lì in poi ti avvisa solo del *nuovo nuovo*.

---

## 17 · Posture checks & posture score (in `posture/checks.py`)  ★NEW

La metà "difensiva" che v1.2 non aveva: non solo "cosa è rotto", ma **conferma di cosa è giusto**, e un punteggio che peggiora visibilmente quando qualcosa regredisce.

- Ogni modulo emette `PostureCheck` per i controlli che verifica (HSTS presente, RLS attiva su tabella X, service_role nascosta, signup chiuso…).
- **Posture score** (0–100), pesato per `severity_if_failed`:
  ```
  score = 100 * Σ(peso dei check passati) / Σ(peso di tutti i check)
  pesi: INFO=1, LOW=2, MEDIUM=3, HIGH=5, CRITICAL=8
  ```
- Lo score va nel report (gauge) e nello storico (`runs/<t>/*/state.json`): un calo tra run è un segnale immediato. Un check che passa→fallisce è anche un `DRIFT` (§16).

Questo è ciò che rende Bastione "appetibile": un numero che sale quando ti difendi meglio, e cala quando regredisci — più una checklist verde di ciò che è a posto, non solo una lista rossa.

---

## 18 · Remediation playbooks (in `remediation/playbooks.py` + `playbooks/`)  ★NEW

Per ogni `rule_id`/`check_id` rilevante, un playbook **azionabile** (template MD in `playbooks/<rule_id>.md`, renderizzato con Jinja2 e iniettato nel report accanto al finding). Senza remediation è uno scanner; **con** remediation è difesa.

Ogni playbook contiene: **cosa significa**, **perché è pericoloso**, **come ripararlo passo-passo** (per il tuo stack: dove cliccare nella dashboard Supabase, quale SQL eseguire per la policy RLS, dove spostare la service_role lato server, quale header settare in Cloudflare), **come verificare il fix** (idealmente: ri-eseguire Bastione e vedere il finding passare a `FIXED`).

Set iniziale (allineato ai finding più probabili sul tuo portfolio):
`RLS_DISABLED`, `RLS_WRITE_OPEN`, `SECRET_SERVICE_ROLE`, `SECRET_STRIPE`, `STORAGE_PUBLIC_LISTABLE`, `ORIGIN_BYPASSABLE`, `POSTURE_HSTS` (mancante), `MISSING_CSP`, `SIGNUP_OPEN`.

Esempio `playbooks/RLS_DISABLED.md` (estratto strutturale):
```markdown
## {{title}} — {{location.endpoint}}
**Rischio:** la tabella è leggibile da chiunque con la anon key (pubblica).
**Fix (Supabase):**
1. Dashboard → Authentication → Policies → tabella `{{table}}`
2. Abilita RLS: `ALTER TABLE {{table}} ENABLE ROW LEVEL SECURITY;`
3. Aggiungi policy SELECT restrittiva (esempio per dati per-utente):
   `CREATE POLICY sel_own ON {{table}} FOR SELECT USING (auth.uid() = user_id);`
**Verifica:** ri-esegui `bastione scan --target {{target}}` → il finding deve diventare FIXED.
```

---

## 18-bis · Agent Remediation Bundle — il documento per l'agente di coding (in `remediation/agent_bundle.py`)  ★NEW

§18 produce remediation per un **umano** (clicca qui nella dashboard). Questa sezione produce remediation per un **agente di coding** (Claude Code, Codex, …): un bundle machine-consumable che l'agente esegue *senza interpretare*. È la stessa conoscenza di remediation, in due rese diverse — umana (in-report, §18) e agente (cartella `fix/`, qui). La chiave di mapping è la stessa: `rule_id` → `remediation_ref`.

### 18-bis.1 Principio di divisione (LOCKED) — perché due classi di fix

Bastione opera black-box: **vede l'app dall'esterno, non ha il repository sorgente.** Da questo discende la regola che disambigua tutto il bundle:

- **Artefatto letterale** — quando il fix *non* dipende dal layout del sorgente, Bastione lo emette **pronto all'uso**: il `CREATE POLICY` SQL completo, il valore esatto dell'header, la regola Cloudflare. L'agente (o tu) lo applica così com'è.
- **Intent + hint** — quando il fix *vive nel codice* (es. una service_role hardcoded da spostare server-side), Bastione **non** può produrre una diff letterale: ha visto la chiave nel bundle compilato, non sa in quale file sorgente nasce. Emette quindi **intento + indizi di ricerca + file probabili + criterio di accettazione**, e lascia che l'agente — che *ha* il repo — faccia la localizzazione. Onesto e netto: nessuna diff inventata.

Questa divisione **è** ciò che rende il bundle affidabile: l'agente non riceve mai istruzioni ambigue, riceve o un artefatto da applicare o un compito ben definito con un test di successo.

### 18-bis.2 Output: la cartella `fix/`

In fase `REMEDIATE`, per ogni finding **aperto** (`NEW` o `KNOWN`; mai `ACCEPTED`/`FIXED`) con un `remediation_ref`, si scrive:

```
runs/<target>/<ts>/fix/
├── FIX-PLAN.md          # umano + agente: piano ordinato, con preambolo-istruzioni per l'agente
├── fix-plan.json        # contratto machine-readable (schema bastione-fixplan/1)
└── migrations/          # SOLO per fix_type=sql_migration: file .sql letterali pronti
    └── <finding_id>_<slug>.sql
```

`FIX-PLAN.md` è il documento "da dare in pasto" che hai chiesto. `fix-plan.json` è per chi vuole pilotarlo a programma (CI, un orchestratore di agenti). I `.sql` sono artefatti applicabili direttamente (`supabase db push`, SQL editor).

### 18-bis.3 Contratti dati (in `models.py`)

```python
class FixType(str, Enum):
    SQL_MIGRATION   = "sql_migration"     # artefatto letterale: file .sql pronto
    CONFIG_CHANGE   = "config_change"     # header/impostazione: valore letterale
    INFRA_CHANGE    = "infra_change"      # Cloudflare/DNS: valore letterale
    CODE_CHANGE     = "code_change"       # intent + hint: l'agente localizza nel repo
    SECRET_ROTATION = "secret_rotation"   # rotazione chiave: passo umano obbligatorio

class Applicability(str, Enum):
    AGENT        = "agent"          # un agente di coding lo applica end-to-end
    HUMAN        = "human"          # richiede una console/dashboard del provider
    AGENT_HUMAN  = "agent+human"    # l'agente prepara, l'umano completa (o viceversa)

class Verification(BaseModel):
    method: str = "bastione-rescan"
    command: str                    # es. "bastione verify --target gestionale"
    expect: str                     # es. "finding a1b2c3 → FIXED"

class FixEntry(BaseModel):
    finding_id: str                 # stesso id stabile del Finding (§16) — chiude il loop
    rule_id: str
    severity: Severity
    title: str
    fix_type: FixType
    applicable_by: Applicability
    priority: int                   # 1 = primo. secret_rotation è SEMPRE 1.
    depends_on: list[str] = []      # finding_id da risolvere prima (es. ruota PRIMA di ripulire)
    context: dict                   # {resource, endpoint, file, evidence_redacted}
    instructions: dict              # shape dipende da fix_type (§18-bis.4)
    verification: Verification

class FixPlan(BaseModel):
    schema_version: str = "bastione-fixplan/1"
    target: str
    generated_at: datetime
    run_dir: str
    summary: dict                   # {total, agent_applicable, human_required, by_severity}
    fixes: list[FixEntry]           # ordinati per priority, poi severity
```

### 18-bis.4 Builder a registrazione (in `remediation/agent_bundle.py`)

Parallelo ai playbook umani: un `FixBuilder` per `rule_id`, auto-registrato. Ogni builder sa il proprio `fix_type`, `applicable_by`, e come rendere `instructions`. Un nuovo fix = un nuovo builder (drop-in).

```python
class FixBuilder(ABC):
    rule_id: str
    fix_type: FixType
    applicable_by: Applicability
    @abstractmethod
    def build(self, f: Finding, cfg: TargetConfig) -> FixEntry: ...

FIX_BUILDERS: dict[str, FixBuilder] = {}
def register_fix(cls): FIX_BUILDERS[cls.rule_id] = cls(); return cls
```

**Shape di `instructions` per `fix_type` (LOCKED):**

| `fix_type` | Campi di `instructions` | Chi applica |
|---|---|---|
| `sql_migration` | `migration_sql` (letterale), `rollback_sql`, `apply_to` (`"staging first"`), `file` (path al `.sql` emesso) | 🟢 agente |
| `config_change` | `mechanism` (es. `"_headers file"`/`"middleware"`), `key`, `value` (letterale) | 🟢 agente |
| `infra_change` | `platform` (es. `"cloudflare"`), `mechanism`, `key`, `value`, `as_code_option` (es. `"wrangler.toml"`) | 🟢/🟡 agente o misto |
| `code_change` | `intent`, `search_hints[]`, `files_likely[]`, `literal_diff_available=false`, `note` | 🟢 agente (localizza nel repo) |
| `secret_rotation` | `provider`, `compromised=true`, `human_action`, `agent_followup`, `warning` | 🔴 umano + agente |

### 18-bis.5 Casi speciali (LOCKED)

- **Rotazione segreti = `priority=1`, sempre.** Se una chiave è trapelata (§10), il fix **non** è "rimuoverla dal codice": la chiave è **compromessa** e va **ruotata** (revocata + rigenerata) nella console del provider — passo che un agente di coding **non** può fare. Il `FixEntry` è `secret_rotation`/`AGENT_HUMAN`: l'umano ruota, poi l'agente sposta la nuova chiave server-side e rimuove ogni riferimento client. Il `warning` lo dice esplicito. Ogni altro fix che dipende da quella chiave la mette in `depends_on`.
- **Fix di codice senza sorgente.** `code_change` non porta mai una diff letterale (`literal_diff_available=false`): l'agente ha il repo, lo localizza con `search_hints`. Bastione non finge di sapere dove.
- **Confine col gate (§7).** L'agente che *applica* i fix è un agente diverso da Bastione e opera sul **codice/staging**, non punta target. Il preambolo del `FIX-PLAN.md` (§18-bis.6) gli impone gli stessi paletti: mai produzione, lavora su branch, applica le migration prima su staging, e la verifica passa **sempre** da un re-scan.

### 18-bis.6 `FIX-PLAN.md` — formato normativo

Il documento si apre con un **preambolo-istruzioni per l'agente** (è il "system prompt" del compito), poi separa nettamente ciò che deve fare prima l'umano da ciò che può fare l'agente, e chiude con il loop di verifica. Template (normativo):

```markdown
# Bastione — Piano di Remediation · target: {{target}} · {{generated_at}}

## Istruzioni per l'agente di coding (leggi prima di agire)
Stai correggendo vulnerabilità di sicurezza trovate da Bastione su un'app **di proprietà del committente**.
REGOLE:
1. Non toccare MAI ambienti di produzione. Lavora su un branch dedicato; le migration SQL vanno applicate prima su **staging**.
2. Applica SOLO i fix marcati 🟢 "Applicabile dall'agente". I fix 🔴 "Richiede azione umana" NON sono tuoi: segnalali e fermati su quelli.
3. Per i fix di codice non hai una diff pronta: usa `search_hints` e `files_likely` per localizzare il punto nel sorgente, poi applica l'intento descritto.
4. Ogni fix ha un **Criterio di accettazione**. Dopo aver applicato, NON dichiarare risolto: sarà l'utente a eseguire `bastione verify` e a confermare il passaggio a FIXED.
5. Rispetta l'ordine di priorità e le dipendenze (`depends_on`).

---
## 🔴 Da fare prima — richiede azione umana
### [P1] {{title}}  ·  `{{rule_id}}`  ·  {{severity}}
- **Cosa:** {{instructions.human_action}}
- **Perché non può farlo l'agente:** {{instructions.warning}}
- **Dopo, per l'agente:** {{instructions.agent_followup}}
- **Criterio di accettazione:** `{{verification.command}}` → {{verification.expect}}

---
## 🟢 Applicabili dall'agente (in ordine)
### [P{{priority}}] {{title}}  ·  `{{rule_id}}`  ·  {{severity}}
- **Tipo:** {{fix_type}}
- **Dove:** {{context.resource}} {{context.endpoint}} {{context.file}}
<!-- sql_migration -->
- **Applica questa migration** (file: `{{instructions.file}}`, prima su staging):
  ```sql
  {{instructions.migration_sql}}
  ```
  Rollback: `{{instructions.rollback_sql}}`
<!-- config_change / infra_change -->
- **Imposta** `{{instructions.key}}` = `{{instructions.value}}` via {{instructions.mechanism}}.
<!-- code_change -->
- **Intento:** {{instructions.intent}}
- **Cerca:** {{instructions.search_hints}} — **file probabili:** {{instructions.files_likely}}
- **Nota:** {{instructions.note}}
- **Criterio di accettazione:** `{{verification.command}}` → {{verification.expect}}

---
## Verifica finale
Dopo aver applicato i fix 🟢 e completato i 🔴, l'utente esegue:
`bastione verify --target {{target}}`
Il piano è chiuso quando tutti i `finding_id` elencati risultano **FIXED**.
```

### 18-bis.7 Esempio reso (due finding tipici del tuo portfolio)

> Mostra a Claude Code il formato esatto da generare. Caso A: RLS mancante (agente, SQL letterale). Caso B: service_role trapelata (umano ruota + agente ripulisce).

```markdown
## 🔴 Da fare prima — richiede azione umana
### [P1] Service role key esposta nel bundle JS  ·  `SECRET_SERVICE_ROLE`  ·  CRITICAL
- **Cosa:** Supabase → Project Settings → API → rigenera la `service_role` key e revoca quella attuale.
- **Perché non può farlo l'agente:** la chiave trapelata è compromessa; rimuoverla dal codice NON basta, va ruotata nella console.
- **Dopo, per l'agente:** salva la nuova chiave in env server-side (mai nel client); rimuovi ogni riferimento alla service_role dal frontend.
- **Criterio di accettazione:** `bastione verify --target gestionale` → finding 7f3a…e1 → FIXED

## 🟢 Applicabili dall'agente (in ordine)
### [P2] RLS disabilitata su `clienti`  ·  `RLS_DISABLED`  ·  CRITICAL
- **Tipo:** sql_migration  ·  **Dove:** tabella `clienti` (`/rest/v1/clienti`)
- **Applica questa migration** (file: `migrations/9a2f_rls_clienti.sql`, prima su staging):
  ```sql
  ALTER TABLE public.clienti ENABLE ROW LEVEL SECURITY;
  CREATE POLICY sel_own ON public.clienti
    FOR SELECT USING (auth.uid() = user_id);
  ```
  Rollback: `DROP POLICY IF EXISTS sel_own ON public.clienti;`
- **Criterio di accettazione:** `bastione verify --target gestionale` → finding 9a2f…b0 → FIXED
```

### 18-bis.8 Il loop di verifica (`bastione verify`)

Il pezzo che chiude il cerchio e rende il bundle *self-checking*: `bastione verify --target <n>` ri-esegue la scansione (read-only) e stampa una tabella `finding_id → {still_open | FIXED | new}`, confrontando con l'ultima baseline/run. Un fix è "chiuso" solo quando il suo finding passa a `FIXED` — non quando l'agente *dice* di averlo applicato. Workflow completo:

```
bastione scan → fix/FIX-PLAN.md → [agente applica 🟢 + umano fa 🔴] → bastione verify → loop finché tutto FIXED
```

È questo a trasformare l'output da "ecco i tuoi bug" in "ecco i tuoi bug, con la patch e la prova che è chiusa".

---

## 19 · Notifiche / alerting (in `notify/`)  ★NEW

Chiude il loop del monitoring: quando una scansione schedulata trova qualcosa di **nuovo o regredito**, ti avvisa. Niente di sempre-acceso: gira nello stesso processo della scansione.

```python
class Notifier(ABC):
    @abstractmethod
    def send(self, summary: RunSummary) -> None: ...
NOTIFIERS = {"telegram": TelegramNotifier, "email": EmailNotifier, "webhook": WebhookNotifier}
```
- **Trigger (fase NOTIFY):** `≥1 finding NEW con severity ≥ soglia` **oppure** `≥1 DRIFT`. Altrimenti silenzio (no rumore).
- **Telegram** (proposto default, O01): `BOT_TOKEN`+`CHAT_ID` da `.env`. Messaggio compatto: target, score, #NEW per severità, #DRIFT, link al report HTML.
- **Email** (SMTP) / **Webhook** (POST JSON con il `RunSummary`) come alternative.
- Config per-target: `[notify] channel="telegram" min_severity="high"`. **Precedenza soglia (LOCKED):** il flag CLI `--fail-on` vince sul TOML; `min_severity` è il default quando il flag è assente. Una sola soglia effettiva per run, usata sia dal gate (§22) sia dal notify.

---

## 20 · Monitoring / scansioni schedulate  ★NEW

Il monitoring **è** semplicemente: *scan schedulato → diff baseline (§16) → notify (§19)*. Nessun daemon, nessun DB, coerente con free-tier e con la filosofia "niente infrastruttura prematura".

Due ricette fornite nel README:
- **crontab** (self-host): `0 3 * * * cd /opt/bastione && uv run bastione scan --target gestionale --max-intrusion read-only`
- **GitHub Actions** (`.github/workflows/bastione.yml`): job schedulato (`schedule: cron`) che esegue lo scan, carica il SARIF su GitHub Security (code scanning) come artefatto, e fallisce/avvisa sui NEW. Segreti (token Telegram, ecc.) nei *repository secrets*.

Risultato: ogni notte sai se è comparsa una nuova esposizione su una delle tue app, **senza** dover ricordarti di lanciare nulla.

---

## 21 · Portfolio mode (multi-target)  ★NEW

Hai molte app (Numely, Gestionale, Chirsan, i siti…). `portfolio.toml` elenca i target; `bastione scan-all` esegue ognuno e produce un **report consolidato** + i singoli, con una **tabella di postura del portfolio** (score per app, #CRITICAL aperti, #DRIFT). Una sola occhiata per sapere quale app ha bisogno di attenzione.

```toml
# portfolio.toml
targets = ["gestionale", "numely", "chirsan"]
[defaults]
max_intrusion = "read-only"
notify_channel = "telegram"
```

---

## 22 · CI/CD gate mode  ★NEW

Shift-left: Bastione gira in pipeline e **blocca il deploy** se compaiono nuovi problemi gravi.
`bastione scan --target gestionale --ci --fail-on high`

**Exit codes (LOCKED):**
| Code | Significato |
|------|-------------|
| 0 | nessun finding `NEW` ≥ soglia, nessun `DRIFT` |
| 1 | gate fallito: ≥1 `NEW` ≥ soglia **o** ≥1 `DRIFT` |
| 2 | errore config/precondizione (incl. produzione bloccata) |
| 3 | ownership challenge fallito |
| 4 | errore esecuzione tool/interno |

In CI, `--ci` implica non-interattivo: niente prompt; per intrusione > read-only serve `--i-own-this-its-staging` esplicito. `--ci` **rifiuta** `--unsafe-show-secrets` (exit 2): il reveal è solo locale.

**Da dove arriva la baseline in CI:** `baselines/<target>.baseline.json` è **committata nel repo** (L05 — il formato §16 non contiene evidenze). Senza baseline versionata ogni run CI vedrebbe tutto come `NEW` e il gate fallirebbe sempre.

---

## 23 · Output: SARIF + report MD/HTML (in `normalize/sarif.py`, `report/`)

- **SARIF 2.1.0** (`run_dir/bastione.sarif`): mapping `Finding` → `result`; `rule_id` → `reportingDescriptor`; `severity`→`level` (`CRITICAL/HIGH`→`error`, `MEDIUM`→`warning`, `LOW/INFO`→`note`); `location`→`physical/logical location`; `partialFingerprints.findingId = finding_id` (così GitHub traccia i finding nel tempo come Bastione). Caricabile su GitHub code scanning.
- **Markdown** (`report.md`): sommario (score, conteggi per stato/severità), poi `NEW`/`DRIFT` in testa (sono ciò che conta), poi `KNOWN`, poi `FIXED` (vittorie), poi checklist posture verde/rossa. Ogni finding ha il suo playbook inline.
- **HTML single-file** (`report.html`): stesso contenuto, autocontenuto (CSS/JS inline, niente CDN), con **posture gauge** e filtri per stato/severità. È il formato condivisibile (anche con un futuro cliente).

> Tutti e tre i report rispettano la **redazione** (§10/P8): nessun segreto in chiaro salvo `--unsafe-show-secrets`.

---

## 24 · Stato runtime per-scan (in `state.py`)

`runs/<target>/<timestamp>/state.json` — abilita `--resume` e lo storico dello score. **Attenzione al nome:** questo è lo stato *di una singola scansione* (`bastione-state/1`), **non** il `BASTIONE-SESSION-STATE.md` di progetto (`bastione-devstate/1`, vedi Appendice A).
```json
{
  "schema": "bastione-state/1",
  "target": "gestionale",
  "started_at": "…", "finished_at": "…",
  "max_intrusion": "read-only",
  "ownership_verified": false,
  "phases_completed": ["LOAD","RECON","PLAN","SCAN","NORMALIZE","BASELINE","POSTURE","REPORT","NOTIFY","PERSIST"],
  "phases_skipped": ["OWNERSHIP","REMEDIATE"],
  "posture_score": 78.0,
  "counts": {"new": 2, "known": 5, "fixed": 1, "drift": 0,
             "by_severity": {"critical":1,"high":2,"medium":3,"low":2,"info":0}},
  "tools_available": {"whatweb": true, "nuclei": false, "zap": false}
}
```
*(`by_severity` conta i finding emessi nella run — qui 2+5+1=8 — esclusi i posture check.)*

`--resume` legge l'ultimo `state.json` del target e riparte dalla prima fase che **non** compare né in `phases_completed` né in `phases_skipped`. Le fasi condizionali (OWNERSHIP, REMEDIATE, NOTIFY) quando la precondizione non scatta vengono registrate in `phases_skipped`, **non** omesse: altrimenti un resume di una run completata rientrerebbe in una fase mai dovuta.

---

## 25 · CLI (in `cli.py`, typer)

```
bastione scan       --target <nome>
                    [--max-intrusion read-only|probe|mutating]   (default: read-only)
                    [--i-own-this-its-staging]                    (richiesto per mutating non-interattivo)
                    [--accept-baseline]                           (promuove i NEW correnti a baseline)
                    [--fail-on info|low|medium|high|critical]     (soglia gate/notify; ha precedenza su [notify].min_severity; default proposto high = O03)
                    [--ci]                                        (non-interattivo, exit codes §22; incompatibile con --unsafe-show-secrets)
                    [--resume]                                    (riprende dalla prima fase né completata né saltata, §24)
                    [--no-fix]                                    (salta la generazione del bundle fix/ §18-bis; default "genera sempre" = proposta O05)
                    [--unsafe-show-secrets]                       (reveal segreti — solo locale, mai con --ci)

bastione verify     --target <nome>                              (re-scan read-only; tabella finding_id → still_open|FIXED|new, §18-bis.8)
bastione fix        --run <path>                                 (rigenera il bundle fix/ da un run esistente, §18-bis)
bastione scan-all   [--portfolio portfolio.toml]                 (§21)
bastione report     --run <path>                                 (rigenera MD/HTML da un run)
bastione baseline   --target <nome> [--show|--reset|--accept <finding_id>]   (--accept: promozione selettiva known → accepted, §16)
bastione doctor                                                  (verifica quali tool esterni sono installati)
bastione list-modules / list-detectors / list-fixes             (introspezione del REGISTRY)
```

---

## 26 · Limiti onesti (cosa il black-box NON trova)

Da scrivere nel README e nel report, senza vendere fumo:
- **Logica di business e autorizzazione fine** (IDOR semantici, workflow): il black-box vede *cosa* è raggiungibile, non *cosa avrebbe senso* — per quello serve la matrice oracolo (§15) o l'occhio umano.
- **SECURITY DEFINER / privilegi interni Postgres:** non verificabili dall'esterno → flag `TENTATIVE`.
- **0-day e catene complesse:** Bastione orchestra controlli noti; non sostituisce un pentest umano di terza parte.
- **Falsi positivi entropia:** mitigati da allowlist, ma `SECRET_HIGH_ENTROPY` resta `TENTATIVE`.
- **Copertura tool:** se un binario manca, quel pezzo è `SKIPPED` — il report lo dichiara, non lo nasconde.

L'onestà qui *è* una feature: il posture score non gonfia, e un finding `TENTATIVE` non grida "CRITICAL".

---

## 27 · Roadmap a milestone

**M0 — Vista dell'attaccante (read-only).** `LOAD → RECON → secrets (solo detection) → supabase §11.1 read → headers/cloudflare → NORMALIZE → BASELINE → POSTURE → REPORT(SARIF+MD)`. Tutto `READ_ONLY`, nessun ownership challenge necessario. **Valore immediato sullo staging del Gestionale Officina.** *(= M0 del v1.2, già concordato.)*

**M1 — Profondità + difesa di base.** Tool esterni (nuclei, ZAP passive, testssl, WPScan, trivy); liveness segreti (`PROBE`, gated); **baseline/drift completo** (§16, il kernel); **remediation playbooks** umani (§18); **Agent Remediation Bundle** + `bastione verify` (§18-bis, il documento per l'agente di coding + loop di chiusura); **report HTML** + posture gauge (§17/§23).

**M2 — Sistema di difesa continuo.** Modo **oracolo** (§15); **canary write** (`MUTATING`, staging+ownership, §11.2); **monitoring schedulato** + **notifiche** (§19–20); **portfolio mode** (§21); **CI gate** (§22).

**M3 — Espansioni (deferred, trigger-based).** DefectDojo *solo* al primo cliente che paga per report ricorrenti; corsia **white-box** (Semgrep/trivy sul sorgente); **attack-surface inventory** tracciato nel tempo (subdomain/endpoint/bucket).

> **Ordine d'oro per Claude Code:** non saltare avanti. M0 deve girare end-to-end (anche con un solo detector e la sola RLS read) **prima** di toccare M1. La tentazione di implementare tutto il catalogo o le scritture subito è l'over-engineering contro cui questo blueprint mette in guardia (P5).

---

## 28 · Workflow Claude Code — permission matrix operativa

Regole per l'agente che implementa/esegue. Mappano la matrice §7 sulle azioni dell'agente.

| Operazione dell'agente | Livello | Comportamento |
|---|---|---|
| leggere/scrivere file nel repo `bastione/`, eseguire test unitari, `bastione doctor` | 🟢 auto | procedi |
| eseguire `bastione scan --max-intrusion read-only` su un target **tuo** in staging | 🟢 auto | procedi (è read-only su owned) |
| eseguire con `--max-intrusion probe` (liveness, ZAP passive) | 🟡 conferma | chiedi conferma + verifica ownership challenge in config |
| eseguire con `--max-intrusion mutating` (canary, ZAP active, sqlmap) | 🔴 conferma forte | conferma esplicita + assert `environment=staging` + ownership |
| qualsiasi azione verso un host **non** dichiarato `owned`/`authorized-written`, o `production` | ⛔ bloccato | rifiuta e spiega (§7 `assert_preconditions`) |
| installare tool esterni di sistema (nuclei, ZAP…) | 🟡 conferma | proponi comandi, lascia decidere a te |

**Stop rules (LOCKED):** se `environment` non è dichiarato, o il target non risolve, o manca `ownership_token` **per una run che chiede > read-only** → **fermati e chiedi**, non assumere. (Per il read-only puro — tutto M0 — il token non è richiesto: §7.1. La sua assenza non blocca.) Mai puntare un target che non sia esplicitamente tuo nel TOML.

---

## 29 · Config di esempio completa (`targets/_example.toml`)

```toml
# Risoluzione: `--target <nome>` carica targets/<nome>.local.toml se esiste
# (config reale, gitignored), altrimenti targets/<nome>.toml (§6 LOAD).

# ─── Identità target ────────────────────────────────────────────────
name        = "gestionale"
base_url    = "https://staging.gestionale-officina.example"
environment = "staging"                # "staging" | "production"(BLOCCATO) 
ownership   = "owned"                   # "owned" | "authorized-written"
ownership_token = "b3f1c2a4-…"          # pubblicato su /.well-known/bastione-ownership.txt o DNS TXT _bastione

# ─── Supabase (opzionale: se non dichiarato, lo scopre il recon) ─────
[supabase]
url = "https://abcdef.supabase.co"      # opzionale; il recon può estrarlo dal bundle
# anon_key: NON metterla qui — la estrae il recon (è pubblica)

# ─── Notifiche ──────────────────────────────────────────────────────
[notify]
channel      = "telegram"               # telegram | email | webhook | none
min_severity = "high"                   # soglia per alert/CI

# ─── Modo oracolo (opzionale → abilita la profondità) ───────────────
[expectations]
[[expectations.table]]
name = "clienti"
anon_select = false
anon_insert = false
[[expectations.table]]
name = "listino_pubblico"
anon_select = true
anon_insert = false

# ─── Override moduli (opzionale) ────────────────────────────────────
[modules]
disabled = []                           # es. ["zap"] per saltarlo
```

---

## Appendice A · Seed del dev-state (primo avvio)

> Seed per il JSON **`bastione-devstate/1`** in §6 del `BASTIONE-SESSION-STATE.md` — lo stato di *sviluppo del progetto*, handoff tra sessioni di coding. **Non confonderlo** con lo stato runtime per-scan di §24 (`bastione-state/1`): schemi distinti apposta, campi distinti (`phases_completed` esiste solo nel runtime). Build order, guardrail e prossime azioni vivono nelle sezioni in prosa del SESSION-STATE (§2/§4), non in questo JSON.

```json
{
  "schema": "bastione-devstate/1",
  "project": "Bastione (BAS)",
  "blueprint_version": "2.1",
  "updated": "<AAAA-MM-GG>",
  "current_milestone": "M0",
  "code_started": false,
  "build_steps_m0": {
    "total": 16,
    "done": 0,
    "next": "1. SCAFFOLD"
  },
  "decisions_locked": 13,
  "open_decisions": ["O01","O02","O03","O04","O05"],
  "open_blocking_m0": [],
  "target_under_test": "gestionale (staging)",
  "guardrails_active": true
}
```

— *Fine blueprint v2.1.*
