# BASTIONE — DYNAMIC WORKFLOWS (metodo di sviluppo)

> **Metodologia (LOCKED):** lo sviluppo è orchestrato con i **Dynamic Workflows** — lo **strumento `Workflow`** di Claude Code (orchestrazione deterministica in JavaScript), non una validazione sequenziale a mano. L'**orchestratore** è la **sessione Claude Code su Opus 4.8** che lancia lo strumento, fa ground-truth coi test e committa/pusha.
> **Come si avvia:** lo strumento parte **solo con opt-in esplicito** → in sessione ultracode è **automatico**; altrimenti nel prompt di inizio sessione si dice letteralmente *"usa lo strumento Workflow"* (così l'orchestratore reale viene invocato, non simulato con subagent singoli).
> **UN workflow per milestone** (LOCKED, Claudio 2026-06-14): **NON** uno per step. Tutti gli step della milestone confluiscono in un solo workflow, con gli agenti in parallelo *dove i file lo consentono*.
> **Cap reali dello strumento:** **concorrenza = `min(16, core_CPU − 2)` per workflow** (16 è il *tetto*, non una garanzia: con pochi core la parallelizzazione effettiva è minore) · **1.000 agent totali per run**.
> **Ground-truth:** il verdetto è dell'oracolo — l'orchestratore riesegue **`python -m pytest -q`** (su Windows: `python -m pytest -q`, **NON** uv — uv è assente; python 3.14 ha pytest/pydantic) — **più** la blind-review adversariale. **MAI** il self-report dell'agente.
> Codename BAS · allineato a `BASTIONE-BLUEPRINT-v2.md` (v2.1) e `BASTIONE-SESSION-STATE.md` · Aggiornato: 2026-06-18

---

## 1 · Meccanica (come funziona davvero)

Quattro fasi: **plan → distribute → verify → integrate**. L'orchestratore scompone la milestone in **task atomici indipendenti**, li lancia in **ondate concorrenti (≤ cap)**, fa verificare ogni output contro il suo **gate**, e **integra solo se il gate è verde**.

- Il piano del workflow vive in variabili JS **fuori dal context** dell'orchestratore (è esattamente come funziona lo script dello strumento `Workflow`).
- Mappatura sui **primitivi reali** dello strumento: un'**ondata di task indipendenti** = `parallel([...])` (barriera, attende tutti) **oppure** `pipeline(items, build, verify, fix)` quando build→verify→fix scorrono **per-item senza barriera** (default consigliato). Un **`agent()` per task**; il **`phase()`** raggruppa i task nella vista di avanzamento.
- Gli agenti consumano molto più usage di una sessione normale → **partire scoped, monitorare l'usage**.
- **Una milestone = una sessione-workflow** (LOCKED, Claudio 2026-06-14).

> **Specificità Bastione:** il working tree è **condiviso** tra gli agenti. Decomponi **per ownership di file** per massimizzare il parallelismo *sicuro*: builder su file disgiunti girano in parallelo; builder che editano lo **stesso** file (es. `cli.py`) vanno **sequenziati** dentro il workflow (§4).

## 2 · Unità di lavoro: il task atomico (test-first)

Ogni task nasce **con il suo GATE scritto PRIMA del build** (TDD: RED→GREEN). Schema:

```
TASK
  id            : Tn.m
  dominio       : a quale file / §N del blueprint appartiene
  dipende_da    : [id, …]            ← definisce l'ondata
  output        : artefatto prodotto (modulo / funzione / test)
  GATE          : asserzione automatica di accettazione (IL test) — vedi §3
  modello       : Sonnet | Opus   (builder; il verifier è SEMPRE Opus — §5. No Haiku)
  done          : gate verde + integrato
```

| campo | significato |
|---|---|
| **id** | `Tn.m` (milestone *n*, task *m*) |
| **dominio** | file o §N del blueprint che il task tocca (criterio di scope) |
| **dipende_da** | lista di id; insieme vuoto ⇒ task radice ⇒ può partire nell'ondata 1 |
| **output** | artefatto su disco: modulo, funzione, suite di test |
| **GATE** | l'asserzione di accettazione eseguibile (§3); per Bastione è quasi sempre *test offline* |
| **modello** | builder Sonnet o Opus (§5); **il verifier è SEMPRE Opus** |
| **done** | gate verde **e** integrato (file su disco + `python -m pytest -q` verde + diff ispezionato) |

## 3 · Pipeline per task — il modello di GATE di Bastione

> Questa è la **divergenza chiave** dal template ASV: il gate di Bastione **non** è pgTAP / Playwright / DB-locale. È **test offline Python** (`python -m pytest -q`) + **blind-review adversariale** + (per i deliverable human-facing) **ispezione dell'artefatto reale**.

```
        ┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────┐
 spec→  │  BUILD  │ ──▶ │ VERIFY (×k)  │ ─✗─▶│  FIX-LOOP    │ ──▶ │ INTEGRATE │
        │ builder │     │ blind-author │     │ fixer Opus   │     │  orchestr.│
        │  (TDD)  │     │ vs il GATE   │     │ fino a verde │     │  pytest   │
        └─────────┘     └──────┬───────┘     └──────────────┘     └───────────┘
                               └──✓────────────────────────────────────▲
```

- **BUILD** — il builder lavora in **TDD** (RED→GREEN): scrive il codice **e** i test, tutto **offline** (confini I/O monkeypatchati, nessun target puntato).
- **VERIFY** — **blind-author review adversariale**: il verifier rivede l'artefatto **contro la spec, SENZA il ragionamento dell'autore**. **k dimensioni** tipiche: *correctness* · *sicurezza/guardrail* · *robustezza/contratto* (**k = 2–3**; **di più** per artefatti safety-critical come la **scrittura canary §11.2**). **Ogni finding va ri-verificato/refutato**: un dubbio respinto in verifica non blocca il merge (è successo in M0 sul gate).
- **FIX-LOOP** — **fixer Opus**, invocato **SOLO su fallimento**, itera build→test finché il gate è verde.
- **INTEGRATE** — è l'**ORCHESTRATORE** a chiudere il cerchio: riesegue **`python -m pytest -q`** come **ground-truth** (mai fidarsi del self-report), ispeziona il **diff dei punti di sicurezza**, e per i deliverable **human-facing genera l'artefatto reale e lo ispeziona** (es. `FIX-PLAN.md`, `report.html` provato con payload XSS ostile).

**La blind-review intercetta difetti VERI prima del merge** — esempi reali da M0–M2:
- **Cleanup-safety del canary (M2 step 2, 2 difetti CRITICAL/medium):** la review adversaria ha trovato che un `DELETE` 2xx-ma-0-righe era trattato come successo (→ riga canary **orfana**) e che mancava il `try/finally` tra POST e DELETE. Fixati con test di regressione; aggiunto `CANARY_CLEANUP_FAILED`.
- **SSRF/owned-only sul claim `ref` (M1 step 2):** l'URL Supabase derivato dal claim JWT non era validato → fix `fullmatch [a-z0-9]+`.
- **Path-traversal + SSTI sul `rule_id` dei playbook (M1 step 4):** whitelist + containment.
- **`nuclei -include-tags safe` è additivo, non restrittivo (M1 step 6):** avrebbe girato template *attivi* sotto un modulo PROBE/passive → fix `-exclude-tags` + cap di severità.
- **Rollback multi-linea (M2 step 0):** rompeva il Markdown del `FIX-PLAN.md` → reso fenced.

## 4 · Ondate & DAG

I task si organizzano in un **grafo di dipendenze**; gli indipendenti girano in **parallelo (≤ cap)**. Il **fan-out = numero di task realmente indipendenti** in quell'ondata, **non un numero forzato**.

> **Vincolo Bastione (LOCKED):** working tree **CONDIVISO**. I builder che editano lo **STESSO** file (es. `cli.py`) vanno **SEQUENZIATI** dentro il workflow — editi paralleli sullo stesso file confliggono, e un builder che lancia `pytest` mentre un altro edita vede stati a metà. **Builder su file disgiunti + tutte le review (k dimensioni) girano in parallelo.**
>
> **Lo stesso vale per i FIXER (LOCKED, lezione Sessione 10):** in O4 i fixer per-area possono toccare **gli stessi file** (es. un fix "surface" e un fix "completeness" entrambi su `models.py`/`tests/test_surface.py`; o l'area "integration" su `cli.py`/`orchestrator.py` mentre un'altra area li importa). Parallelizzarli alla cieca = **race**: lo strumento li esegue concorrenti, ciascuno rilancia `pytest` su uno stato a metà e i self-report risultano **incoerenti** (in M3: "831" vs "826+3fail"). Decomponi i fixer **per ownership di file** come i builder: paralleli solo se gli insiemi di file sono **disgiunti**, altrimenti **sequenziali**. In ogni caso il verdetto è dell'**orchestratore** che rilancia `python -m pytest -q` sull'albero **stabile** a workflow concluso (mai i self-report dei fixer concorrenti).
>
> *Pattern reale (M2 steps 4–6):* `Track A` step4→step5 **sequenziali** su `cli.py` ‖ `Track B` step6 docs/yaml; poi **4 blind-review per-area in parallelo**. *Pattern reale (M1 §18-bis):* **2 builder sequenziali** (core → wiring) nello stesso workflow, poi review.

## 5 · Model policy (LOCKED da Claudio)

| Ruolo / tipo di task | Modello |
|---|---|
| **Verifier** (ogni task) | **Opus 4.8 — SEMPRE** (le honesty gain di 4.8 rendono affidabile il gate) |
| **Orchestratore** | **Opus 4.8** (= la sessione Claude Code che lancia lo strumento) |
| **Fixer** | **Opus 4.8** |
| Builder — **logica delicata** (`gate.py`, Supabase RLS/canary §11.2, baseline/diff §16, `agent_bundle` §18-bis) | **Opus 4.8** |
| Builder — **task meccanici** (boilerplate, colla attorno a binari, docs/yaml, form/report) | **Sonnet** |

> **Niente Haiku:** per codice che deve passare un gate, **Sonnet è il pavimento** (sotto-dimensionare sposta il costo nel fix-loop). La colonna `modello` nei task-graph indica solo il **builder**; il verifier è **sempre Opus**.

## 6 · Confini del workflow — cosa NON fa un builder 🔒

> La sezione più importante: fonde i confini del workflow con i **guardrail Bastione §7/§28** e le **lezioni apprese** in M0–M2. Lo strumento esegue gli agenti **fino a completamento senza fermarsi a chiedere**: i confini vanno quindi **iniettati in OGNI prompt agente**, non assunti.

- I builder **SCRIVONO** file su disco (con lo strumento Write, al path esatto assegnato) e li **verificano coi test OFFLINE**.
- **NON** eseguono **MAI** git: `add` / `commit` / `push` / `checkout` / `reset` / `branch` / `tag`. *(Lezione M1: un fixer aveva committato+pushato da sé uno step. La regola NON è sufficiente come assunto → va scritta esplicitamente in OGNI prompt builder/fixer: "lascia le modifiche nel working tree, il versionamento lo fa l'orchestratore".)*
- Toccano **SOLO i file in-scope del task**, nessun file estraneo. *(Lezione M2: in 2 step un agente ha editato `PROMPT-01/02` fuori scope, cancellando anche un promemoria → rilevato via `git diff --stat`, ripristinato con `git checkout --`.)*
- **NON** puntano **MAI** un target live, **NON** superano `READ_ONLY`, **NON** lanciano scansioni/azioni outward-facing, **NON** installano nulla. Le **scritture canary §11.2 restano monkeypatchate offline** — **nessuna scrittura reale** dentro l'automazione.
- I **guardrail §7/§28** (produzione = hard block; owned-only by code; read-only di default; staging-only per le scritture; segreti redatti P8; liveness solo lettura; resilienza→`MODULE_ERROR` INFO; manca un dato critico → fermati e chiedi) vanno **INIETTATI in OGNI prompt agente**.

**Checkpoint umano DENTRO la sessione:** **PRIMA del dispatch** (PLAN → *"fermati e mostrami il piano"*) + i singoli **gradini safety-critical** (le prime scritture canary). Il checkpoint umano si è spostato a fine milestone (rimosso il promemoria per-step "un pezzettino alla volta").

**A fine workflow l'ORCHESTRATORE:**
1. fa **`git diff --stat`**;
2. committa con **PATH ESPLICITI** dei soli file attesi;
3. ispeziona e **ripristina (`git checkout --`)** ogni modifica fuori scope;
4. riesegue **`python -m pytest -q`** (ground-truth) + ispeziona il diff dei punti di sicurezza; per i deliverable human-facing genera e ispeziona l'artefatto reale.

> **Outward-facing = FUORI dall'automazione.** Le azioni live su staging (capstone, validazione MUTATING reale) **non** sono task da builder: richiedono **target dichiarato `owned`** + **`ownership_token` pubblicato** + **`environment=staging`** + **ok esplicito di Claudio**. Senza, il gate **aborta** correttamente (provato).

## 7 · Milestone → workflow (fan-out reale)

> Conteggi presi da `BASTIONE-SESSION-STATE.md` — fatti, non stime. Stato attuale: **831 test verdi**, tutto offline.

| Milestone | Stato | Task/step | Gate di milestone | File di dettaglio |
|---|---|---|---|---|
| **M0 · Vista dell'attaccante (read-only)** | ✅ **done** (validata live read-only) | ~16 step (build-order) | scan E2E read-only senza crash + **DoD §3** (SARIF+MD+state reali) | SESSION-STATE §2/§3 |
| **M1 · Profondità + difesa di base** | ✅ **done** (validata live read-only) | 7 step | profondità + difesa: table-discovery, liveness PROBE, baseline/drift, playbook, agent-bundle, black-box, report HTML | SESSION-STATE §3-bis |
| **M2 · Sistema di difesa continuo** | ✅ **code-complete (offline)** · capstone live pendente | 7 step | **629 test verdi** + canary §11.2 offline + oracolo/notifier/CI-gate/portfolio/monitoring | SESSION-STATE §3-ter |
| **M3 · Espansioni** | ✅ **code-complete (offline)** · esecuzioni live trigger-gated | 5 step (T0 + 4 corsie + integraz.) | **831 test verdi** + semgrep/trivy §14 + attack-surface §16 (`surface`) + DefectDojo §19 exporter+push gated (`export-defectdojo`) | SESSION-STATE §3-quater |

## 8 · Task-graph M3 — ✅ COSTRUITO (Sessione 10), esecuzioni live trigger-gated

> **Premessa (aggiornata Sessione 10):** **M3 è stata COSTRUITA offline** in un solo dynamic workflow (semgrep, trivy, attack-surface, DefectDojo). Il *"deferred/trigger-based"* del canone riguardava l'**esecuzione live/outward-facing** (trigger: *sorgente disponibile* / *1° cliente*), **non** il codice: ogni GATE è un **test offline** + binario/sorgente assente → **`SKIPPED` INFO onesto** (mai crash), sul modello della colla sottile §14 (nuclei/ZAP). Le 4 corsie sotto sono quindi **fatte** (✅ dettaglio in SESSION-STATE §3-quater); restano gated **solo gli usi live** (girare semgrep/trivy su sorgente owned via `TargetConfig.source_path`; POST a un DefectDojo reale). Regola d'oro **P5** rispettata: non si è "saltato avanti" a caso — il deferral è stato sollevato da Claudio (owner), che resta il decisore.

| id | dipende_da | output | GATE | modello |
|---|---|---|---|---|
| **M3.1** ✅ | — | Corsia white-box **Semgrep** (colla sottile drop-in §14: self-gate PROBE, `which`→`SKIPPED` INFO se assente, JSON in `run_dir/raw/`, parse→`Finding[]`) | test offline su JSON Semgrep campione → `Finding[]` corretti; **`which` assente → `SKIPPED` INFO**, nessun crash | **Sonnet** |
| **M3.2** ✅ | — | Corsia white-box **trivy** (filesystem/repo, **solo se sorgente disponibile**) | test offline su output trivy campione → `Finding[]`; sorgente assente → no-op/SKIPPED; `which` assente → `SKIPPED` INFO | **Sonnet** |
| **M3.3** ✅ | — | **Attack-surface inventory** tracciato nel tempo (subdomain / endpoint / bucket) | test offline: due snapshot → diff stabile e deterministico (nuovo/rimosso); nessuna scrittura, nessun target live | **Opus** |
| **M3.4** ✅ | — | **DefectDojo exporter + push gated** (push live trigger = **1° cliente pagante**) | test offline: `Finding[]` → payload DefectDojo valido (schema); endpoint assente/non configurato → `SKIPPED` INFO | **Sonnet** |

---

**🔴 CAPSTONE — validazione LIVE MUTATING del canary write (§11.2)**

**NON è un task da builder** (è outward-facing). È **gated** su: **`ownership_token` pubblicato** (`/.well-known/bastione-ownership.txt` o DNS TXT `_bastione`) + **`environment=staging`** dichiarato + **ok esplicito di Claudio** (owned-only). Esercita per la prima volta la scrittura canary reale con **cleanup garantito**. Se i requisiti mancano, **il gate aborta correttamente** (provato offline). Resta **fuori dall'automazione** del workflow.

---

*Cross-reference: `BASTIONE-BLUEPRINT-v2.md` §6 (macchina a stati) · §7/§7.1 (gate, il cuore di sicurezza) · §27 (roadmap a milestone) · §28 (permission matrix operativa) · `BASTIONE-SESSION-STATE.md` (log M0–M2) · memoria `bastione-dev-workflow`. Ultimo aggiornamento: 2026-06-18.*
