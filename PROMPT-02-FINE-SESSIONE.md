# PROMPT 02 — FINE SESSIONE (Bastione)

> **Come usare questo file:** incollalo alla **fine di ogni sessione** di lavoro su Bastione, prima di chiudere. Serve a lasciare un handoff pulito: senza questo passo, la prossima sessione riparte cieca. È un rituale di **chiusura** — non iniziare nuovo lavoro qui.

---

Stiamo chiudendo questa sessione di lavoro su **Bastione (BAS)**. Il contesto per la prossima sessione vive **solo** in `BASTIONE-SESSION-STATE.md`, quindi prima di fermarti aggiornalo con cura ed esegui il self-audit. Non scrivere nuovo codice di feature da qui in poi.

## 1. Aggiorna `BASTIONE-SESSION-STATE.md`
Fai tutte e tre le cose:

**a) Build order (§2/§3-bis/§3-ter/…)** — sulla checklist della **milestone attiva**, spunta `[x]` ogni step **completato e testato** (gate `python -m pytest -q` verde). Se uno step è iniziato ma non finito, lascialo `[ ]` e annota lo stato parziale a fianco (es. "parziale: manca il test di regressione").

**b) Stato dev — JSON `bastione-devstate/1` (§6)** — aggiorna:
- `updated` (data di oggi),
- `tests_green` (il conteggio **reale** restituito da `python -m pytest -q`, non il self-report di un agente),
- `build_steps_<milestone attiva>` (`done`/`total`/`next`: il prossimo step da fare, o "completato" se la milestone è chiusa),
- `current_milestone` (cambialo **solo** se la milestone attiva è davvero completa secondo la sua Definition of Done; una milestone *code-complete* con un capstone live pendente resta tale finché il capstone non è eseguito),
- `open_blocking` (aggiungi qui qualsiasi cosa che ora blocca l'avanzamento).

**c) Log di sessione (§7)** — aggiungi **una riga in cima** (la più recente in alto), nel formato:
`- AAAA-MM-GG — Sessione N: <cosa è cambiato>. <decisioni prese>. Prossimo: <step>. <eventuali blocchi>.`

## 2. Riepilogami la sessione (chiaro e onesto)
- **Fatto:** cosa hai implementato e testato (con esito dei test).
- **Non fatto / problemi noti:** cosa è rimasto aperto, bug, debito tecnico, scorciatoie prese.
- **Bloccato su di me:** qualsiasi decisione OPEN o input che serve da me prima di proseguire.
- **Prossimo passo:** lo step preciso da cui ripartirà la prossima sessione.
- **Esito del workflow di milestone:** se in questa sessione hai usato il dynamic workflow (un workflow per milestone, vedi `BASTIONE-WORKFLOWS.md`), riassumi: **task buildati**; **gate passati** (`python -m pytest -q` verde — conteggio reale prima/dopo); **difetti che la blind-review ha intercettato** prima del merge e **come sono stati chiusi** (fix + test di regressione); eventuali **fix dell'orchestratore** (correzioni decise dal main loop sul ground-truth, non da un agente).

## 3. Self-audit dei guardrail (verifica di sicurezza di fine sessione)
Conferma esplicitamente, per questa sessione (da §7/§28 — LOCKED):
- [ ] Nessuna azione ha toccato un `environment="production"`.
- [ ] Nessun target non dichiarato `owned`/`authorized-written` è stato puntato.
- [ ] Il **tetto di intrusione** è stato rispettato: read-only di default; salire a `PROBE`/`MUTATING` è avvenuto **solo** con flag espliciti **e** ownership challenge superato.
- [ ] Le **scritture canary §11.2** sono restate **offline/monkeypatch** — nessuna scrittura live fuori da un capstone esplicitamente autorizzato da Claudio su staging (`ownership_token` pubblicato + `environment=staging` + ok esplicito).
- [ ] Nessun **segreto in chiaro** è finito in file committabili: `.gitignore` copre `runs/` e `targets/*.local.toml`; `baselines/` è committabile (formato §16, **senza evidenze**).
- [ ] Nessun output contiene **evidenze di segreti non redatte** (P8).

Se una di queste è violata, **segnalalo in cima al riepilogo** come problema da risolvere subito.

## 4. Lascia il repo pulito
- Esegui `git diff --stat` e indica le modifiche **non committate**, distinguendo i file **attesi** (in scope per il lavoro della sessione) da eventuali file **fuori scope**.
- **Scoping dei commit (lezione M1/M2):** l'orchestratore committa con **path espliciti** dei soli file attesi, **dopo** aver letto `git diff --stat`. Ogni modifica fuori scope fatta da un agente va ispezionata e **ripristinata** (`git checkout -- <file>`). I builder/fixer **non committano mai**: il versionamento è esclusivamente dell'orchestratore. **Una unità logica verde → un commit.**
- Proponi un **messaggio di commit** conciso (in inglese, convenzione imperativa, es. `add gate: preconditions + ownership challenge`).
- Se ci sono file temporanei o di scratch, elencali.
- Non lasciare test rossi senza averli annotati nel log.

> I confini del flusso (ruoli, parallelismo per ownership di file, ground-truth, scoping commit) sono normati in `BASTIONE-WORKFLOWS.md` **§6**.

Quando hai aggiornato il SESSION-STATE, dato il riepilogo, completato il self-audit e proposto il commit: la sessione è chiusa. Ci ritroviamo la prossima volta con `PROMPT-01-INIZIO-SESSIONE`.
