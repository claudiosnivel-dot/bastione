# PROMPT 02 — FINE SESSIONE (Bastione)

> **Come usare questo file:** incollalo alla **fine di ogni sessione** di lavoro su Bastione, prima di chiudere. Serve a lasciare un handoff pulito: senza questo passo, la prossima sessione riparte cieca. È un rituale di **chiusura** — non iniziare nuovo lavoro qui.

---

Stiamo chiudendo questa sessione di lavoro su **Bastione (BAS)**. Il contesto per la prossima sessione vive **solo** in `BASTIONE-SESSION-STATE.md`, quindi prima di fermarti aggiornalo con cura ed esegui il self-audit. Non scrivere nuovo codice di feature da qui in poi.

## 1. Aggiorna `BASTIONE-SESSION-STATE.md`
Fai tutte e tre le cose:

**a) Build order (§2)** — spunta `[x]` ogni step **completato e testato** in questa sessione. Se uno step è iniziato ma non finito, lascialo `[ ]` e annota lo stato parziale a fianco (es. "parziale: manca il test").

**b) Stato dev — JSON `bastione-devstate/1` (§6)** — aggiorna:
- `updated` (data di oggi),
- `code_started` (true se hai scritto codice),
- `build_steps_m0.done` (conteggio) e `build_steps_m0.next` (il prossimo step da fare),
- `current_milestone` (cambialo solo se la milestone è davvero completa secondo la Definition of Done, §3),
- `open_blocking_m0` (aggiungi qui qualsiasi cosa che ora blocca l'avanzamento di M0).

**c) Log di sessione (§7)** — aggiungi **una riga in cima** (la più recente in alto), nel formato:
`- AAAA-MM-GG — Sessione N. <cosa è cambiato>. <decisioni prese>. Prossimo passo: <step>. <eventuali blocchi>.`

## 2. Riepilogami la sessione (chiaro e onesto)
- **Fatto:** cosa hai implementato e testato (con esito dei test).
- **Non fatto / problemi noti:** cosa è rimasto aperto, bug, debito tecnico, scorciatoie prese.
- **Bloccato su di me:** qualsiasi decisione OPEN o input che serve da me prima di proseguire.
- **Prossimo passo:** lo step preciso da cui ripartirà la prossima sessione.

## 3. Self-audit dei guardrail (verifica di sicurezza di fine sessione)
Conferma esplicitamente, per questa sessione:
- [ ] Nessuna azione ha toccato un `environment="production"`.
- [ ] Nessun target non dichiarato `owned`/`authorized-written` è stato puntato.
- [ ] Tutto ciò che è stato eseguito era read-only (in M0) — nessuna scrittura reale; i canary restano stub `NotImplementedError`.
- [ ] Nessun segreto in chiaro è finito in file committabili; `.gitignore` copre `runs/` e `targets/*.local.toml` (le `baselines/` sono committabili: il formato §16 non contiene evidenze).
- [ ] Nessun output contiene evidenze di segreti non redatte.

Se una di queste è violata, **segnalalo in cima al riepilogo** come problema da risolvere subito.

## 4. Lascia il repo pulito
- Indica le modifiche **non committate** e proponi un **messaggio di commit** conciso (in inglese, convenzione imperativa, es. `add gate: preconditions + ownership challenge`).
- Se ci sono file temporanei o di scratch, elencali.
- Non lasciare test rossi senza averli annotati nel log.

Quando hai aggiornato il SESSION-STATE, dato il riepilogo, completato il self-audit e proposto il commit: la sessione è chiusa. Ci ritroviamo la prossima volta con `PROMPT-01-INIZIO-SESSIONE`.
