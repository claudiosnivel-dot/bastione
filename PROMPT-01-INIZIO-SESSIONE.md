# PROMPT 01 — INIZIO SESSIONE (Bastione)

> **Come usare questo file:** incollalo all'**inizio di ogni sessione** di lavoro su Bastione. Serve a orientare un contesto fresco (non hai memoria della sessione precedente) e a ripartire dal punto giusto **senza** fare assunzioni sbagliate.

---

Stiamo riprendendo il lavoro su **Bastione (BAS)**, l'orchestratore di security testing difensivo. Non hai memoria delle sessioni precedenti: tutto il contesto vive nei file canonici. Prima di scrivere **una sola riga di codice**, esegui questo rituale di orientamento.

## 1. Leggi e orientati (in quest'ordine)
1. `BASTIONE-SESSION-STATE.md` — **interamente**. È la fonte di verità su dove siamo: milestone attiva, build order con gli step già spuntati, prossimo step, log delle sessioni, decisioni OPEN.
2. Le sezioni del `BASTIONE-BLUEPRINT-v2.md` rilevanti per il **prossimo step** indicato nel SESSION-STATE (i §N sono citati accanto a ogni build step).

Se uno dei due file non è nel contesto, o se il SESSION-STATE è incoerente con lo stato reale del codice, **fermati e segnalamelo** prima di procedere.

## 2. Ri-acquisisci i guardrail (ad alta voce — è una garanzia di sicurezza)
Bastione lancia controlli attivi: a ogni sessione fresca ri-conferma esplicitamente i vincoli di §4 del SESSION-STATE (= §7/§28 del blueprint). Scrivi nella risposta che li rispetterai:
- Produzione = blocco assoluto · Owned-only (host non dichiarato → fermati e chiedi) · Read-only di default · Scritture canary = M2 (in M0 stub `NotImplementedError`) · Segreti redatti · Se manca un dato critico → fermati e chiedi.

Questo non è cerimoniale: un contesto fresco senza re-conferma può derivare. Ri-ancorati.

## 3. Riportami lo stato (breve, prima di agire)
Dammi un orientamento in poche righe:
- **Milestone** attiva e **build step**: fatti `done/totale`, **prossimo** step.
- Eventuali **blocchi** o decisioni OPEN che toccano il prossimo step.
- L'**ultima riga di log** della sessione precedente (dove avevamo lasciato).
- Lo **stato del repo** (se ci sono modifiche non committate, test rossi, ecc.).

## 4. Proponi il prossimo task e ATTENDI il via
Sulla base del `next` nel build order, proponi **il prossimo task concreto**:
- cosa implementerai, quali file toccherai, quali §N del blueprint segui;
- come lo testerai;
- dove ti fermerai (definisci un checkpoint rivedibile, non 8 step in fila).

Poi **fermati e aspetta il mio ok.** Non iniziare a scrivere codice finché non confermo o aggiusto la direzione. Se ho richieste diverse dal `next` previsto, le do qui.

> Promemoria: questa è una sessione, non l'intera milestone. Lavoriamo a incrementi piccoli e rivedibili (3h/settimana). Meglio un pezzo solido e testato che molti pezzi abbozzati. E a fine sessione: `PROMPT-02-FINE-SESSIONE` per lasciare il contesto pulito.
