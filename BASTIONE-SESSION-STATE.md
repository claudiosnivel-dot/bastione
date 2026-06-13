# BASTIONE — SESSION-STATE

> **Codename:** BAS · **Traccia blueprint:** v2.1 · **Milestone attiva:** **M0** · **Aggiornato:** 2026-06-13
> **Stato (una riga):** step **1–6 di M0** implementati e testati in TDD (scaffold + enums/models + config + gate + state/orchestrator shell + **recon/fingerprint read-only**), 77 test verdi; fermo al **checkpoint di fine step 6** in attesa di revisione. Prossimo: step 7 (MODULE BASE — `modules/base.py`: `Module` ABC + `REGISTRY` + `should_run`, §9).
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
| Codice | **Step 1–6 di M0 fatti** (scaffold, enums/models, config, gate, state/orchestrator shell, recon/fingerprint); 77 test verdi. |
| Milestone attiva | **M0** — vista read-only dell'attaccante. |
| Focus immediato | Step 7 del build order: `modules/base.py` — `Module` ABC + `REGISTRY` (decoratore `register`) + `should_run` (§9). |
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
[ ]  7. MODULE BASE       modules/base.py: Module ABC + REGISTRY + should_run (§9)
[ ]  8. SECRETS (det.)    modules/secrets/: Detector ABC + REGISTRY + **1 detector reale** SECRET_SERVICE_ROLE — solo detection, no liveness (§10)
[ ]  9. SUPABASE 💎        modules/supabase/module.py §11.1: OpenAPI surface map + **RLS read test** (la gemma). §11.2 = stub NotImplementedError("M2")
[ ] 10. HEADERS/CF        modules/headers/ + modules/cloudflare/: security headers + TLS minimo + origin reachability → PostureCheck (§12)
[ ] 11. SARIF            normalize/sarif.py: Finding[] → SARIF 2.1.0 + partialFingerprints.findingId (§23)
[ ] 12. REPORT MD        report/markdown.py: sommario + NEW/KNOWN/FIXED + checklist posture (§23)
[ ] 13. BASELINE (min.)  baseline/diff.py: finding_id stabile (§16) + status NEW/KNOWN + first/last_seen. Drift completo → M1
[ ] 14. POSTURE SCORE    posture/checks.py: aggregazione PostureCheck + score 0–100 pesato (§17)
[ ] 15. CLI             cli.py (typer): cabla `scan` (read-only) + `doctor` + `list-modules`/`list-detectors` (§25)
[ ] 16. E2E M0 ▶         run end-to-end su staging Gestionale → primo report SARIF+MD. → vedi Definition of Done (§3)
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

M0 è "fatto" quando **tutte** queste sono vere:
- [ ] `bastione scan --target gestionale --max-intrusion read-only` gira **end-to-end** sullo staging senza crash.
- [ ] Il recon produce un `Fingerprint` con `is_supabase=True` e la `anon_key` estratta dal bundle.
- [ ] Il detector `SECRET_SERVICE_ROLE` gira su tutti i `TextAsset` (anche se non trova nulla: nessun falso crash).
- [ ] La sonda Supabase §11.1 mappa la superficie PostgREST e esegue l'**RLS read test** su ogni tabella scoperta, emettendo `Finding` (RLS aperta) o `PostureCheck` (RLS ok).
- [ ] I moduli headers/cloudflare emettono PostureCheck per gli header di sicurezza.
- [ ] Output su disco in `runs/gestionale/<ts>/`: **`bastione.sarif`** valido + **`report.md`** leggibile + **`state.json`**.
- [ ] Il report mostra il **posture score** e separa NEW da KNOWN.
- [ ] **Tutto read-only**: nessuna scrittura, nessun ownership challenge richiesto (M0 legge solo ciò che è pubblico).
- [ ] Tool esterni assenti → `SKIPPED` con warning, **mai** crash (`bastione doctor` lo riflette).
- [ ] Le evidenze dei segreti nel report sono **redatte** (P8).

Quando tutte spuntate → aggiorna questo file (milestone → M1) e logga la sessione (§7).

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
  "updated": "2026-06-13",
  "current_milestone": "M0",
  "code_started": true,
  "build_steps_m0": {
    "total": 16,
    "done": 6,
    "next": "7. MODULE BASE"
  },
  "decisions_locked": 13,
  "open_decisions": ["O01","O02","O03","O04","O05"],
  "open_blocking_m0": [],
  "target_under_test": "gestionale (staging)",
  "guardrails_active": true
}
```

---

## 7 · Log di sessione (append-only — la più recente in alto)

> Una riga per sessione: cosa è cambiato, cosa è stato deciso, dove riprendere.

- **2026-06-13 — Sessione 3 (step 6: recon / fingerprint read-only).** Implementato in TDD `recon/fingerprint.py` (§8). Funzioni pure (la *gemma*, testate con input reali, niente mock): `extract_script_srcs` (fallback bundle **obbligatorio senza katana**), `extract_supabase_url`, `extract_anon_key` (JWT `role:anon` — **ignora di proposito la service_role**, §8/§10), `detect_cloudflare`, `is_wordpress`. Orchestratore `fingerprint()` con confini I/O monkeypatchabili (`_fetch`/`_run_whatweb`/`_run_katana`, degrado grazioso L06) + scrittura `fingerprint.json`. Scelta M0 (flaggata a Claudio): passo 1 con httpx-**lib**, non il binario projectdiscovery (ridondante; la lib copre URL finale/header/redirect/Cloudflare per un singolo base_url). Revisione adversariale multi-agente (3 dimensioni: correctness · sicurezza/guardrail · robustezza/contratto; ogni finding ri-verificato/refutato): **4 fix applicati** — **(F1)** `is_supabase` legato all'URL PostgREST, non più OR con `anon_key` (eliminato lo stato incoerente `True`+`supabase_url=None` che avrebbe fatto partire il modulo supabase senza URL, §9/§11.1); **(F4)** **filtro same-host** sui bundle (owned-only §7: niente GET verso CDN di terzi non dichiarati); **(F3)** test del bundle `None` in mezzo a più bundle (path DoD-critico); **(F2)** `_parse_whatweb` tollerante per-riga (una riga malformata non scarta le valide). Confermati corretti e già testati: distinzione anon/service_role, no command-injection nei subprocess (argv-list), test 100% offline. Segnalato come **hardening futuro** (non M0-blocking — `runs/` è gitignored, artifact solo locale): redazione `Set-Cookie` in `fingerprint.json`. **77 test verdi**, tutto offline/read-only, nessun target puntato. Step 5 (state+orchestrator) committato+pushato a inizio sessione; da questa sessione commit/push automatici (regola di Claudio). Prossimo: **step 7** — `modules/base.py` (Module ABC + REGISTRY + should_run, §9). Nessuna OPEN blocca M0.
- **2026-06-13 — Sessione 2 (step 5: state + orchestrator shell).** Implementati in TDD `state.py` (§24: `RunState` schema `bastione-state/1`, save/load, `next_phase` per `--resume`) e `orchestrator.py` (§6: macchina a stati shell con le 12 fasi — `LOAD`+`OWNERSHIP`+`PERSIST` cablate, `RECON…NOTIFY` stub no-op; **gate cablato in LOAD** → produzione aborta senza scrivere su disco; condizionali registrate in `phases_skipped` non omesse; logica `--resume`). Shell verificato end-to-end su `_example` → `state.json` valido. Revisione adversariale multi-agente (3 dimensioni, ogni finding ri-verificato): **1 bug major trovato e corretto** — `REMEDIATE`/`NOTIFY` avevano la precondizione cablata ma nessun handler no-op, così al `--resume` con `counts` non nulli la fase sollevava `RuntimeError` abortendo la run (resumability rotta, §6/§24); aggiunti a `_SHELL_STUB` + **test di regressione**. **56 test verdi.** Tutto offline/read-only, nessun target puntato, nessuna scrittura. Prossimo passo: **step 6** — `recon/fingerprint.py` read-only → `Fingerprint` (§8). Nessuna OPEN blocca M0.
- **2026-06-13 — Sessione 1 (primo codice).** Eseguiti gli **step 1–4** del build order M0 in **TDD** (RED→GREEN per ogni modulo): scaffold (pyproject `uv` + dev-deps in `[dependency-groups]`, `.gitignore` che ignora `runs/`+`targets/*.local.toml` ma **non** `baselines/`, README, `baselines/.gitkeep`); `enums.py` (§5.1) + `models.py` (§5.2–5.6, incl. `Location.canonical()` con normalizzazione content-hash); `config.py` (precedenza `.local.toml`, flatten TOML→`TargetConfig`, **separato dal gate**) + `targets/_example.toml` (§29); `gate.py` (§7/§7.1: `assert_preconditions`+`authorize`+`verify_ownership`, con httpx/dnspython **lazy** e degrado grazioso L06). **43 test verdi.** Revisione adversariale multi-agente (5 dimensioni + adversario anti-bypass sul gate, ogni finding ri-verificato): **0 difetti reali sul gate** (un dubbio sollevato e respinto in verifica); **1 incoerenza minore** README↔pyproject (fallback `pip install -e ".[dev]"` non installa i `[dependency-groups]`) → **corretta**. **Stop al checkpoint gate** (PROMPT-00 §5) per revisione di Claudio. **Nessuna scrittura, tutto read-only; nessun target puntato.** Prossimo passo: **step 5** — `state.py` (§24) + `orchestrator.py` shell con le 12 fasi (§6), fasi non implementate = `pass`. Nessuna OPEN blocca M0.
- **2026-06-12 — Sessione 0-bis (revisione documentale).** Audit di coerenza sui 5 file: risolte le contraddizioni gate-vs-declassamento (§6/§7), semantica `known`/`accepted` + `baseline --accept` (§16/§25), baseline committabile per CI (L05/§22), fasi saltate per `--resume` (§24), Appendice A allineata a `bastione-devstate/1`; aggiunti §5.6 (TargetConfig/ModuleResult/RunSummary), normalizzazione content-hash nel finding_id (§5.2), fallback bundle senza katana (§8), criterio severità RLS (§11.1), confine headers/cloudflare (§12), precedenza `--fail-on` (§19), dnspython (§3); corretti refuso cirillico (§29) e conteggio sezioni. Stop rule `ownership_token` ora qualificata (> read-only). **Nessun codice scritto.** Prossimo passo: invariato, step 1 (scaffold).
- **2026-06-12 — Sessione 0.** Blueprint portato a **v2.1**: riscrittura disambiguata da scanner one-shot a sistema di difesa continuo, + aggiunto **Agent Remediation Bundle** (§18-bis) e fase `REMEDIATE`. Creato questo SESSION-STATE. **Nessun codice scritto.** Prossimo passo: step 1 del build order (scaffold repo + pyproject uv). Nessuna OPEN blocca M0.

---

*— SESSION-STATE allineato al blueprint v2.1. Aggiornare a ogni sessione di sviluppo.*
