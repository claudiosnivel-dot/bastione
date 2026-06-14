# BASTIONE — SESSION-STATE

> **Codename:** BAS · **Traccia blueprint:** v2.1 · **Milestone attiva:** **M1** · **M0:** ✅ **DONE (validata live)** · **Aggiornato:** 2026-06-14
> **Stato (una riga):** **M1 in corso** — **step 1/7 (table-discovery dal bundle) DONE**. Quando l'introspezione OpenAPI è chiusa (401), il recon ora estrae i nomi tabella dai `.from('...')` nei bundle same-host (`Fingerprint.discovered_tables`) e la sonda Supabase ci esegue l'RLS read test per nome (severità HIGH, colonne non note → no euristica GDPR, evidence redatta) + un finding onesto `SUPABASE_SCHEMA_VIA_BUNDLE` sulla copertura parziale; se non trova tabelle nemmeno nel bundle resta `SUPABASE_SCHEMA_NOT_ENUMERABLE`. Path felice (surface 200) invariato. **287 test verdi** (workflow dinamico: build TDD → blind-review 3D → fix, 2 finding INFO chiusi). **Validato LIVE read-only su asv-officina (401): il fallback ha scoperto 31 tabelle dal bundle e trovato 6 esposizioni HIGH `RLS_DISABLED` su viste aggregate (RLS sulle tabelle base attiva, ma 6 viste leggibili dall'anon — classico bypass RLS via viste senza `security_invoker`) che M0 non vedeva.** Report locale (gitignored). **Quick-fix §17 FATTO** (workflow TDD→review→ , 291 test): RLS disabilitata ora emette anche un `PostureCheck POSTURE_RLS_<tab>` **fallito** (severità allineata al finding) → lo score scende e passa→fallito diventa DRIFT (§16). **Ri-validato live: score sceso da 100.0 → 83.7.** **Prossimo: M1 step 2 — liveness segreti (PROBE, gated, §10.2/§7.1).** 🎯 **Obiettivo prossima sessione: CHIUDERE M1** (step 2..7 in task atomici via dynamic workflow).
>
> **⚠️ Due "stati" diversi — non confonderli:**
> - **Questo file** (`SESSION-STATE.md`) = stato di *sviluppo del progetto*, handoff tra sessioni di coding. È ciò che Claude Code legge in testa a ogni sessione per sapere dove siamo.
> - `runs/<target>/<ts>/state.json` = stato *runtime di una singola scansione* (resumability), definito in §24 del blueprint. Altra cosa.

---

## 0 · Kickoff — cosa fare per PRIMO in questa sessione

Se stai aprendo Bastione ora e non c'è ancora codice:
1. Leggi il blueprint `BASTIONE-BLUEPRINT-v2.md` — in particolare §4 (struttura repo, **normativa**), §5 (contratti dati), §6 (macchina a stati), §7 (gate — **il cuore di sicurezza**).
2. Esegui il **Build order M0** (§2 di questo file) **in ordine**. Non saltare avanti: l'ordine rispetta le dipendenze.
3. Rispetta i **Guardrails** (§4 di questo file) a ogni passo. Sono vincoli di sicurezza, non opzionali.
4. Obiettivo di fine percorso M0: la **Definition of Done** (§3 di questo file).

> Regola d'oro (P5 del blueprint): questo è *colla sottile + un modulo custom serio* (la sonda Supabase). Non over-ingegnerizzare. M0 deve girare **end-to-end** anche con **un solo detector** e la **sola** RLS read prima di aggiungere qualunque altra cosa.

---

## 1 · Stato corrente (snapshot)

| Dimensione | Stato |
|---|---|
| Blueprint | **v2.1**, completo, decisioni bloccate. 31 sezioni (§0–§29 + §18-bis). |
| Codice | **M0 completa** (step 1–16 + wiring) + **M1 step 1** (table-discovery dal bundle → RLS fallback su 401): scaffold, enums/models, config, gate, state, recon (+`extract_table_names`), modules/base, secrets, supabase (+fallback via-bundle), headers/cloudflare, sarif, report, baseline, posture, orchestrator, cli; **287 test verdi** + **run live M0 eseguita**. |
| Milestone attiva | **M1** — la difesa continua (build order in §3-bis). Fatto: step 1 (table-discovery). M0 (vista read-only) ✅ chiusa e validata live. |
| Focus immediato | **M1 step 2 — liveness segreti** (`PROBE` 🟡, gated da ownership challenge §7.1): `validate_liveness` per i detector che lo supportano (service_role/stripe/github), solo GET/identità, dietro `--max-intrusion ≥ probe` + ownership verificata. **1ª attivazione reale del gate PROBE.** |
| Target di collaudo | Staging del **Gestionale Officina** (Supabase + Cloudflare). |
| Decisioni OPEN | O01–O05 (§5 di questo file) — **nessuna blocca M0**. |
| Tool esterni | Da verificare con `bastione doctor` una volta che la CLI esiste. M0 dipende solo da: `httpx`/`katana`/`whatweb` (degradano se assenti). |

---

## 2 · Build order M0 — checklist ordinata (dependency-correct)

> Ogni step cita la sezione del blueprint che lo specifica. Spunta `[x]` quando fatto + testato. **Non riordinare:** ogni step dipende dai precedenti.

```
[x]  1. SCAFFOLD          repo §4 + pyproject (uv, §2/§3) + package skeleton + .gitignore (runs/ targets/*.local.toml — baselines/ NON si ignora: si committa, niente evidenze, §16/§22)
[x]  2. ENUMS+MODELS      enums.py (§5.1) + models.py (§5: Finding, PostureCheck, Fingerprint, RunContext, …) — TUTTO il resto dipende da qui
[x]  3. CONFIG            config.py: load+validate TOML → TargetConfig (§5.6, §29); risoluzione <n>.local.toml > <n>.toml (§6 LOAD); targets/_example.toml
[x]  4. GATE 🔒           gate.py: assert_preconditions + authorize + verify_ownership (§7, §7.1) — DEVE esistere PRIMA di ogni modulo
[x]  5. STATE+ORCH        state.py (§24) + orchestrator.py: macchina a stati shell con le 12 fasi (§6), per ora fasi non implementate = pass
[x]  6. RECON             recon/fingerprint.py: read-only, httpx/whatweb/katana + estrazione anon key dal bundle (§8) → Fingerprint
[x]  7. MODULE BASE       modules/base.py: Module ABC + REGISTRY + should_run (§9)
[x]  8. SECRETS (det.)    modules/secrets/: Detector ABC + REGISTRY + **1 detector reale** SECRET_SERVICE_ROLE — solo detection, no liveness (§10)
[x]  9. SUPABASE 💎        modules/supabase/module.py §11.1: OpenAPI surface map + **RLS read test** (la gemma). §11.2 = stub NotImplementedError("M2")
[x] 10. HEADERS/CF        modules/headers/ + modules/cloudflare/: security headers → PostureCheck (§12). [TLS minimo + origin reachability = M1, vedi log]
[x] 11. SARIF            normalize/sarif.py: Finding[] → SARIF 2.1.0 + partialFingerprints.findingId (§23)
[x] 12. REPORT MD        report/markdown.py: sommario + NEW/KNOWN/FIXED + checklist posture (§23)
[x] 13. BASELINE (min.)  baseline/diff.py: finding_id stabile (§16) + status NEW/KNOWN/FIXED + DRIFT + first/last_seen
[x] 14. POSTURE SCORE    posture/checks.py: aggregazione PostureCheck + score 0–100 pesato (§17)
[x] 15. CLI             cli.py (typer): cabla `scan` (read-only) + `doctor` + `list-modules`/`list-detectors` (§25)
[x] 16. E2E M0 ▶         **FATTO**: smoke E2E offline ✓ + **run live read-only** su asv-officina.pages.dev (owned, 2026-06-14) → SARIF+MD+state reali. Nota: anon REST 401 → RLS-per-tabella non enumerabile su questo target (finding onesto SUPABASE_SCHEMA_NOT_ENUMERABLE; table-discovery dal bundle = M1)
  +   WIRING ORCH       orchestrator.py: fasi RECON→PERSIST cablate (PLAN should_run · SCAN ThreadPoolExecutor read-only + MODULE_ERROR · NORMALIZE dedup + POSTURE_SERVICE_ROLE_HIDDEN · BASELINE · POSTURE · REPORT) (§6)
```

**Note di sequenza (perché quest'ordine):**
- **Gate (4) prima di tutto il resto operativo:** nessun modulo deve poter agire senza che il gate esista. È il vincolo legale/etico reso codice (P1/P2).
- **Models (2) prima dei moduli:** il contratto `Finding`/`PostureCheck` è l'interfaccia universale; senza, ogni modulo improvviserebbe il proprio formato.
- **Recon (6) prima dei moduli a contenuto:** la selezione (`should_run`) dipende dal `Fingerprint`.
- **Secrets con UN solo detector (8):** prova che il pattern plugin funziona end-to-end; il resto del catalogo è M1.
- **Supabase §11.1 only (9):** in M0 niente scritture. Lo stub di §11.2 impedisce all'agente di anticipare i canary.
- **Baseline minimale (13):** in M0 basta NEW/KNOWN per dare senso al report; il kernel drift (passa→fallito) è M1.

---

## 3 · Definition of Done — M0

✅ **M0 DONE** — tutte vere, verificate con codice + test (267 verdi) e con la **run live read-only** su `asv-officina.pages.dev` (owned, 2026-06-14).

- [x] `bastione scan --target gestionale --max-intrusion read-only` gira **end-to-end** senza crash. *(eseguito live ✓ + smoke E2E offline)*
- [x] Il recon produce un `Fingerprint` con `is_supabase=True` e la `anon_key` estratta dal bundle. *(live: anon_key + supabase_url estratti dal bundle reale ✓)*
- [x] Il detector `SECRET_SERVICE_ROLE` gira su tutti i `TextAsset` (live: 0 leak → service_role NON esposta ✓).
- [x] La sonda Supabase §11.1 mappa la superficie PostgREST ed esegue l'**RLS read test** su ogni tabella scoperta → `Finding`/`PostureCheck`. *(capability provata offline; **sul target live l'anon riceve 401 sulla root REST** → schema non enumerabile → emesso il finding onesto `SUPABASE_SCHEMA_NOT_ENUMERABLE`. Table-discovery dal bundle per i target hardened = M1.)*
- [x] I moduli headers/cloudflare emettono PostureCheck per gli header di sicurezza. *(live: 8 check verdi)*
- [x] Output su disco in `runs/<target>/<ts>/`: **`bastione.sarif`** valido + **`report.md`** + **`state.json`** *(generati live ✓)*.
- [x] Il report mostra il **posture score** (100.0 live) e separa NEW da KNOWN.
- [x] **Tutto read-only**: nessuna scrittura, nessun ownership challenge richiesto.
- [x] Tool esterni assenti → degradano, **mai** crash (`bastione doctor` lo riflette; live: whatweb/katana assenti, fallback `<script src>` ha comunque trovato il bundle).
- [x] Le evidenze dei segreti/dati personali nel report sono **redatte** (P8).

**M0 chiusa e validata live.** Milestone → **M1**. La sola verifica non esercitata sul campo è l'RLS-per-tabella, perché *questo* target blocca l'introspezione anon (401) — onestamente segnalato; lo sblocca la table-discovery dal bundle (priorità M1 #1, **fatta nello step 1 M1**).

---

## 3-bis · Build order M1 — checklist (da §27, dependency-correct)

> Derivato dalla roadmap §27 + la priorità #1 emersa dalla run live M0. Value-first e dependency-aware. **Una sessione ≠ una milestone:** incrementi piccoli e rivedibili. Spunta `[x]` quando fatto + testato.

```
[x] 1. TABLE-DISCOVERY dal bundle   §8 + §11.1    extract_table_names + Fingerprint.discovered_tables + RLS fallback su 401 (287 test, done 2026-06-14)
[x] 2. LIVENESS segreti (PROBE)     §10.2 + §7.1  validate_liveness service_role gated PROBE + 1ª attivazione gate PROBE (319 test, done 2026-06-14)
[x] 3. BASELINE/DRIFT completo      §16           comando `bastione baseline` (--show/--reset/--accept) gradino-2 KNOWN→ACCEPTED; kernel drift/first-last-seen era già completo (341 test, done 2026-06-14)
[x] 4. REMEDIATION playbooks        §18           remediation/playbooks.py (Jinja2) + 9 template MD iniettati nel report (NEW/KNOWN/drift), fallback intatto (389 test, done 2026-06-14)
[ ] 5. AGENT BUNDLE + `verify`      §18-bis       cartella fix/ + FIX-PLAN.md + loop `bastione verify`
[ ] 6. MODULI black-box             §14           nuclei/ZAP passive/testssl/WPScan/trivy (indip., SKIP se assenti)
[ ] 7. REPORT HTML + posture gauge  §17/§23 (O02) single-file dark + gauge; consuma tutto → per ultimo
```

> Note di sequenza: lo **step 5 dipende dal 4** (il bundle agente consuma i playbook). Lo **step 6 è indipendente** (colla sottile attorno a binari, riordinabile/parallelizzabile). Lo **step 7 è presentazione** → per ultimo (rende il set più ricco di finding/playbook/posture). Gli step 1→5 sono il cuore difensivo.

---

## 4 · Guardrails / Stop rules (LOCKED — mai violare)

Da §7 e §28 del blueprint. Valgono sia per Bastione in esecuzione sia per l'agente che lo costruisce:

1. **Produzione = hard block.** `environment="production"` → `assert_preconditions` aborta. Mai puntare produzione.
2. **Owned-only by code.** Si testa solo un target dichiarato `owned`/`authorized-written` nel TOML. Host non dichiarato → **fermati e chiedi**, non assumere.
3. **Read-only di default.** Tetto di default `READ_ONLY`. Salire (`PROBE`/`MUTATING`) richiede flag espliciti + ownership challenge superato.
4. **Scritture solo staging.** I canary (M2) sono staging-only, con marker + cleanup garantito. In M0 sono **stub** che sollevano `NotImplementedError`.
5. **Segreti redatti.** Mai evidenze in chiaro nei report salvo `--unsafe-show-secrets` (solo locale, mai CI).
6. **Liveness = solo lettura.** Le validazioni di liveness fanno solo GET/identità, mai operazioni mutanti, anche quando la chiave lo permetterebbe.
7. **Resilienza, non silenzio.** Il fallimento di un modulo è catturato e loggato (meta-finding `MODULE_ERROR` INFO), non interrompe gli altri né viene nascosto.
8. **Se manca un dato critico** (`environment`, target che non risolve, o `ownership_token` quando la run chiede > read-only — in M0 read-only il token non serve, §7.1) → **fermati e chiedi**. Mai improvvisare un target.

---

## 5 · Decisioni OPEN (bloccate su Claudio) — nessuna blocca M0

| # | Decisione | Proposta default | Tocca | Blocca M0? |
|---|---|---|---|---|
| O01 | Notifier prioritario | **Telegram** (bot+chat_id, già lo usi) | §19, M2 | No |
| O02 | Tema HTML + posture gauge | single-file, dark, con gauge | §23, M1 | No |
| O03 | Soglia default CI gate | **HIGH** | §22, M2 | No |
| O04 | Concorrenza moduli read-only | **ThreadPoolExecutor** | §6 SCAN | No (si procede con la proposta) |
| O05 | Fix bundle: sempre o opt-in | **sempre** se ci sono finding aperti (`--no-fix` per saltare) | §18-bis, M1 | No |

> **M0 è completamente sbloccato:** tutte le OPEN riguardano M1/M2. Si parte senza attendere decisioni. Le confermiamo prima di toccare le rispettive sezioni.

---

## 6 · Stato dev (machine-parseable)

> Stato *di sviluppo del progetto* (non confondere con il runtime `state.json` per-scan, §24). Aggiornalo a fine sessione.

```json
{
  "schema": "bastione-devstate/1",
  "project": "Bastione (BAS)",
  "blueprint_version": "2.1",
  "updated": "2026-06-14",
  "current_milestone": "M1",
  "m0_done": true,
  "m0_validated_live": "asv-officina.pages.dev (owned, read-only, 2026-06-14)",
  "code_started": true,
  "tests_green": 389,
  "build_steps_m0": {
    "total": 16,
    "done": 16,
    "next": "completato (milestone M0 chiusa)"
  },
  "build_steps_m1": {
    "total": 7,
    "done": 4,
    "next": "step 5 — agent bundle + verify (§18-bis): FixBuilder registry, fase REMEDIATE scrive fix/ (FIX-PLAN.md+fix-plan.json+migrations/), comando bastione verify"
  },
  "m1_priority_1": "table-discovery dai nomi tabella nel bundle JS (.from('...')) per testare l'RLS quando l'introspezione OpenAPI e' chiusa (401) — emersa dalla run live — DONE (M1 step 1, 2026-06-14): extract_table_names + Fingerprint.discovered_tables + fallback sonda Supabase",
  "next_session_goal": "CHIUDERE M1 — step 2..7 (liveness PROBE, baseline/drift completo, remediation playbooks, agent bundle+verify, moduli black-box, report HTML+gauge) in task atomici via dynamic workflow (regola permanente di Claudio)",
  "open_blocking": "nessuno (M0 chiuso; M1 step 2..7 sbloccati). Confermare le OPEN prima di toccare le rispettive sezioni (es. O02 tema HTML → step 7).",
  "dev_workflow": "dynamic workflow (builder Sonnet/Opus + verifier/fixer Opus); orchestratore=main loop fa commit/push",
  "decisions_locked": 13,
  "open_decisions": ["O01","O02","O03","O04","O05"],
  "target_under_test": "gestionale (staging) = asv-officina.pages.dev",
  "guardrails_active": true
}
```

---

## 7 · Log di sessione (append-only — la più recente in alto)

> Una riga per sessione: cosa è cambiato, cosa è stato deciso, dove riprendere.

- **2026-06-14 — Sessione 5 (cont.): quick-fix §17 (posture score onesto).** Bug emerso dalla validazione live dello step 1 (posture 100/100 con 6 HIGH aperti) → fixato via workflow dinamico (build TDD → 2 review adversariali → 0 finding, nessun fix). In `modules/supabase/module.py`: il ramo "tabella esposta" di `_rls_read_test` emette ora — oltre al Finding `RLS_DISABLED` — anche un `PostureCheck POSTURE_RLS_<tab>` **passed=False**, con `severity_if_failed` calcolata UNA volta (`_rls_disabled_severity`: CRITICAL dati personali / HIGH; via_bundle→HIGH) e **condivisa** tra finding e posture (peso §17 proporzionale). Mutua esclusione protetto/esposto garantita; `drift` lasciato alla fase BASELINE (passa→fallito = DRIFT §16, gratis). **Zero modifiche** a posture/checks.py, report/markdown.py (rende già ❌), baseline/diff.py. **+4 test (291 verdi)**, nessun test esistente da aggiornare. **Ri-validato live read-only su asv-officina: posture score sceso da 100.0 → 83.7** (i 6 RLS esposti ora compaiono come ❌ nella checklist e pesano nello score; drift=0 perché non c'è ancora baseline). Tutto committato+pushato.
- **2026-06-14 — Sessione 5 (M1 step 1: table-discovery dal bundle).** Aperta M1 e derivato il build order M1 (7 step, §3-bis, da §27). Eseguito **step 1** via workflow dinamico (build TDD → blind-review adversariale su 3 dimensioni → fix): **(1)** `extract_table_names` pura in `recon/fingerprint.py` (§8) — estrae i nomi da `.from('NAME')`/`.from("NAME")` (identificatore relazione PostgREST, opz. prefisso schema), scarta i falsi positivi dei builtin JS (`Array.from`, typed-array…) via post-filtro per offset esatto del `.from(`, dedup+sort deterministico, zero I/O; **(2)** campo `Fingerprint.discovered_tables` (§5) popolato da `fingerprint()` aggregando su **tutti** i bundle same-host (rimosso l'early-break; **owned-only intatto**, nessun nuovo download verso host non dichiarati); **(3)** wiring **fallback** nella sonda Supabase (§11.1): surface 401/non-enumerabile + tabelle dal bundle → RLS read test per nome (severità **HIGH**, colonne non note → no euristica GDPR, **evidence redatta P8**, `intrusion_used=READ_ONLY`) + finding onesto **INFO/TENTATIVE `SUPABASE_SCHEMA_VIA_BUNDLE`** sulla copertura parziale (solo tabelle referenziate nel client JS); nessuna tabella nemmeno nel bundle → resta `SUPABASE_SCHEMA_NOT_ENUMERABLE` (description aggiornata). **Path felice (surface 200) invariato** (decisione LOCKED: solo fallback). Stub canary §11.2 intatto (`NotImplementedError("M2")`). Blind-review: **sicurezza/guardrail 0 finding**; 2 finding **INFO** (falso positivo builtin con spazio/commento prima di `.from(` — non realistico su bundle minificato; commento "negative lookbehind" stantio) → entrambi **fixati** con 2 test di regressione. Ground-truth orchestratore: **287 test verdi** (era 267, +20), tutto offline/read-only. **Validazione live read-only su asv-officina (owned/staging, autorizzata esplicitamente da Claudio — il classificatore owned-only aveva prima bloccato la run perché `--target gestionale` ≠ "asv-officina" nominato: guardrail che funziona):** surface 401 → fallback su **31 tabelle dal bundle** → **6 esposizioni HIGH `RLS_DISABLED`** su viste aggregate (RLS sulle tabelle base OK, ma 6 viste leggibili dall'anon — bypass RLS via viste senza `security_invoker`; alcune potrebbero contenere dati personali → da verificare colonne, salirebbero a CRITICAL) + 25 protette + finding onesto INFO `SUPABASE_SCHEMA_VIA_BUNDLE` (31 tabelle). M0 qui non vedeva nulla (401→non enumerabile): lo step 1 ha trasformato il buco in finding reali e azionabili. Evidence redatta (P8), report in `runs/` gitignored (nomi esatti delle viste vulnerabili NON nel repo). **Bug del nostro tool emerso live (da fixare in M1, §17): posture score = 100 nonostante 6 HIGH** — `RLS_DISABLED` non emette un PostureCheck fallito, solo un finding, quindi non abbassa lo score (fuorviante). **Prossimo: M1 step 2 — liveness segreti (PROBE 🟡, gated da ownership §7.1, §10.2): 1ª attivazione reale del gate PROBE.** *(Nota: valutare se anticipare il fix posture §17 prima dello step 2.)*
- **2026-06-14 — Sessione 4 (cont.): run live + CHIUSURA M0 → M1.** Claudio ha fornito il target reale `asv-officina.pages.dev` (Cloudflare Pages) e l'autorizzazione owned-only. Creato `targets/gestionale.local.toml` (gitignored) e lanciata `bastione scan --target gestionale --max-intrusion read-only` **live, read-only**. Risultati reali: pipeline E2E senza crash; recon ha estratto **anon key (role:anon) + supabase_url (`ztfjrlpyfobtqsfqxfqh.supabase.co`) dal bundle** (fallback `<script src>` ha funzionato anche con whatweb/katana assenti); Cloudflare-fronted + **tutti i 6 security header presenti** → posture **100.0**; **nessuna service_role esposta** (POSTURE_SERVICE_ROLE_HIDDEN ✓); SARIF+MD+state generati. **La sonda Supabase ha scoperto che la root REST risponde 401 all'anon** (schema non introspezionabile) → la surface-map non enumera tabelle. Diagnosi: il mio probe *manuale* all'host supabase è stato **bloccato dal classificatore owned-only** (host non dichiarato) — guardrail che funziona; ho proceduto via tool dopo che Claudio ha dichiarato owned anche il backend. **Rifinitura M0 (workflow Opus, scelta da Claudio):** la sonda ora, quando la superficie non è enumerabile (401/irraggiungibile), emette un **finding onesto `SUPABASE_SCHEMA_NOT_ENUMERABLE` (INFO/TENTATIVE)** invece di tacere — dichiara che l'RLS per-tabella NON è verificata (verifica incompleta). **267 test verdi.** Re-run live → report con 1 finding INFO onesto + 8 posture check verdi. **M0 chiusa e validata live.** **Priorità M1 #1 (emersa qui):** table-discovery dai nomi tabella nel bundle JS (`.from('...')`) per testare l'RLS sui target che chiudono l'introspezione. Tutto committato/pushato.
- **2026-06-14 — Sessione 4 (M0 code-complete via dynamic workflow).** Nuovo flusso di lavoro adottato (regola permanente di Claudio): ogni milestone in task atomici, chiusi via **dynamic workflow** — builder (Sonnet 4.6 o Opus 4.8 per complessità) → **blind-author review (Opus)** → **fixer (Opus)**; l'orchestratore (main loop, Opus 4.8) decompone, fa ground-truth coi test e committa/pusha. Commit/push automatici ai checkpoint. Decomposti ed eseguiti step **6→15 + wiring orchestratore** in 6 fasi: F1 `modules/base.py` (§9); F2 (parallela) `secrets`+`SECRET_SERVICE_ROLE` (§10) · `supabase` surface map+RLS read test (la gemma, §11.1, Opus) · `headers`/`cloudflare` (§12) · `baseline/diff` finding_id+NEW/KNOWN/FIXED/DRIFT (§16, Opus) · `posture/checks` score pesato (§17); F3 `normalize/sarif` SARIF 2.1.0 (§23) · `report/markdown` (§23); F4 **wiring orchestratore** RECON→PERSIST (§6: PLAN should_run · SCAN ThreadPoolExecutor read-only + MODULE_ERROR resiliente · NORMALIZE dedup + cross-check POSTURE_SERVICE_ROLE_HIDDEN §11.1.6 · BASELINE · POSTURE · REPORT, Opus); F5 `cli.py` typer scan/doctor/list-modules/list-detectors (§25, Opus); F6 capstone (cleanup + smoke E2E offline + review integrata). **Bug reali trovati dalle blind-review e corretti dai fixer (tutti con test di regressione):** (T-wire) REMEDIATE/NOTIFY saltati su run fresca perché `state.counts` letto prima di PERSIST → ora da `self._result.counts`; (CLI) exit-code non conformi §22 → `PreconditionDenied` (produzione→exit 2, ownership→exit 3) + CI gate su NEW≥soglia OPPURE drift (non più su KNOWN/ACCEPTED) con `new_by_severity`; (capstone) **resumability rotta dopo SCAN** → `_rehydrate_scan_chain` ricostruisce in memoria PLAN→SCAN→NORMALIZE prima di BASELINE. Cleanup: secrets niente doppio-fetch + `finding_id` allineato alla formula LOCKED §16 (rimosso `target`); cloudflare-fronted check → severity INFO (no inflazione score, §26); RunContext `ownership_verified` cablato. Scope M0 confermato (golden rule P5): supabase = solo surface map + RLS read test (storage/RPC/auth posture §11.1.3-6 → M1); headers TLS minimo + cloudflare origin-reachability → M1. **264 test verdi**, tutto offline/read-only, **nessun target live puntato**, tutto committato+pushato (8 commit). **M0 code-complete.** Resta lo **step 16 (E2E su staging reale)**: non automatizzabile (owned-only) — serve `targets/gestionale.local.toml` + ok di Claudio; poi si verifica la DoD sui dati reali e milestone → M1.
- **2026-06-13 — Sessione 3 (step 6: recon / fingerprint read-only).** Implementato in TDD `recon/fingerprint.py` (§8). Funzioni pure (la *gemma*, testate con input reali, niente mock): `extract_script_srcs` (fallback bundle **obbligatorio senza katana**), `extract_supabase_url`, `extract_anon_key` (JWT `role:anon` — **ignora di proposito la service_role**, §8/§10), `detect_cloudflare`, `is_wordpress`. Orchestratore `fingerprint()` con confini I/O monkeypatchabili (`_fetch`/`_run_whatweb`/`_run_katana`, degrado grazioso L06) + scrittura `fingerprint.json`. Scelta M0 (flaggata a Claudio): passo 1 con httpx-**lib**, non il binario projectdiscovery (ridondante; la lib copre URL finale/header/redirect/Cloudflare per un singolo base_url). Revisione adversariale multi-agente (3 dimensioni: correctness · sicurezza/guardrail · robustezza/contratto; ogni finding ri-verificato/refutato): **4 fix applicati** — **(F1)** `is_supabase` legato all'URL PostgREST, non più OR con `anon_key` (eliminato lo stato incoerente `True`+`supabase_url=None` che avrebbe fatto partire il modulo supabase senza URL, §9/§11.1); **(F4)** **filtro same-host** sui bundle (owned-only §7: niente GET verso CDN di terzi non dichiarati); **(F3)** test del bundle `None` in mezzo a più bundle (path DoD-critico); **(F2)** `_parse_whatweb` tollerante per-riga (una riga malformata non scarta le valide). Confermati corretti e già testati: distinzione anon/service_role, no command-injection nei subprocess (argv-list), test 100% offline. Segnalato come **hardening futuro** (non M0-blocking — `runs/` è gitignored, artifact solo locale): redazione `Set-Cookie` in `fingerprint.json`. **77 test verdi**, tutto offline/read-only, nessun target puntato. Step 5 (state+orchestrator) committato+pushato a inizio sessione; da questa sessione commit/push automatici (regola di Claudio). Prossimo: **step 7** — `modules/base.py` (Module ABC + REGISTRY + should_run, §9). Nessuna OPEN blocca M0.
- **2026-06-13 — Sessione 2 (step 5: state + orchestrator shell).** Implementati in TDD `state.py` (§24: `RunState` schema `bastione-state/1`, save/load, `next_phase` per `--resume`) e `orchestrator.py` (§6: macchina a stati shell con le 12 fasi — `LOAD`+`OWNERSHIP`+`PERSIST` cablate, `RECON…NOTIFY` stub no-op; **gate cablato in LOAD** → produzione aborta senza scrivere su disco; condizionali registrate in `phases_skipped` non omesse; logica `--resume`). Shell verificato end-to-end su `_example` → `state.json` valido. Revisione adversariale multi-agente (3 dimensioni, ogni finding ri-verificato): **1 bug major trovato e corretto** — `REMEDIATE`/`NOTIFY` avevano la precondizione cablata ma nessun handler no-op, così al `--resume` con `counts` non nulli la fase sollevava `RuntimeError` abortendo la run (resumability rotta, §6/§24); aggiunti a `_SHELL_STUB` + **test di regressione**. **56 test verdi.** Tutto offline/read-only, nessun target puntato, nessuna scrittura. Prossimo passo: **step 6** — `recon/fingerprint.py` read-only → `Fingerprint` (§8). Nessuna OPEN blocca M0.
- **2026-06-13 — Sessione 1 (primo codice).** Eseguiti gli **step 1–4** del build order M0 in **TDD** (RED→GREEN per ogni modulo): scaffold (pyproject `uv` + dev-deps in `[dependency-groups]`, `.gitignore` che ignora `runs/`+`targets/*.local.toml` ma **non** `baselines/`, README, `baselines/.gitkeep`); `enums.py` (§5.1) + `models.py` (§5.2–5.6, incl. `Location.canonical()` con normalizzazione content-hash); `config.py` (precedenza `.local.toml`, flatten TOML→`TargetConfig`, **separato dal gate**) + `targets/_example.toml` (§29); `gate.py` (§7/§7.1: `assert_preconditions`+`authorize`+`verify_ownership`, con httpx/dnspython **lazy** e degrado grazioso L06). **43 test verdi.** Revisione adversariale multi-agente (5 dimensioni + adversario anti-bypass sul gate, ogni finding ri-verificato): **0 difetti reali sul gate** (un dubbio sollevato e respinto in verifica); **1 incoerenza minore** README↔pyproject (fallback `pip install -e ".[dev]"` non installa i `[dependency-groups]`) → **corretta**. **Stop al checkpoint gate** (PROMPT-00 §5) per revisione di Claudio. **Nessuna scrittura, tutto read-only; nessun target puntato.** Prossimo passo: **step 5** — `state.py` (§24) + `orchestrator.py` shell con le 12 fasi (§6), fasi non implementate = `pass`. Nessuna OPEN blocca M0.
- **2026-06-12 — Sessione 0-bis (revisione documentale).** Audit di coerenza sui 5 file: risolte le contraddizioni gate-vs-declassamento (§6/§7), semantica `known`/`accepted` + `baseline --accept` (§16/§25), baseline committabile per CI (L05/§22), fasi saltate per `--resume` (§24), Appendice A allineata a `bastione-devstate/1`; aggiunti §5.6 (TargetConfig/ModuleResult/RunSummary), normalizzazione content-hash nel finding_id (§5.2), fallback bundle senza katana (§8), criterio severità RLS (§11.1), confine headers/cloudflare (§12), precedenza `--fail-on` (§19), dnspython (§3); corretti refuso cirillico (§29) e conteggio sezioni. Stop rule `ownership_token` ora qualificata (> read-only). **Nessun codice scritto.** Prossimo passo: invariato, step 1 (scaffold).
- **2026-06-12 — Sessione 0.** Blueprint portato a **v2.1**: riscrittura disambiguata da scanner one-shot a sistema di difesa continuo, + aggiunto **Agent Remediation Bundle** (§18-bis) e fase `REMEDIATE`. Creato questo SESSION-STATE. **Nessun codice scritto.** Prossimo passo: step 1 del build order (scaffold repo + pyproject uv). Nessuna OPEN blocca M0.

---

*— SESSION-STATE allineato al blueprint v2.1. Aggiornare a ogni sessione di sviluppo.*
