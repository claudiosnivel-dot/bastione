# PROMPT 01 — INIZIO SESSIONE (Bastione)

> **Come usare questo file:** incollalo all'**inizio di ogni sessione** di lavoro su Bastione. Serve a orientare un contesto fresco (non hai memoria della sessione precedente) e a ripartire dal punto giusto **senza** fare assunzioni sbagliate. Lo sviluppo di Bastione è **workflow-first**: la milestone si costruisce con **un dynamic workflow**, non a mano step per step.

---

Stiamo riprendendo il lavoro su **Bastione (BAS)**, l'orchestratore di security testing difensivo. Non hai memoria delle sessioni precedenti: tutto il contesto vive nei file canonici. Prima di scrivere **una sola riga di codice** — e prima ancora di lanciare qualunque workflow — esegui questo rituale di orientamento.

## 1. Leggi e orientati (in quest'ordine)
1. `BASTIONE-SESSION-STATE.md` — **interamente**. È la fonte di verità su dove siamo: milestone attiva, build order con gli step già spuntati, prossimo step, log delle sessioni, decisioni OPEN.
2. `BASTIONE-WORKFLOWS.md` — **il metodo di sviluppo workflow-first**. Da leggere **a ogni sessione**: definisce **come** si costruisce (ruoli builder/verifier/fixer, modelli, ondate parallele, cap dello strumento, ground-truth). Senza questo non sai *come* eseguire la milestone, solo *cosa*.
3. Le sezioni del `BASTIONE-BLUEPRINT-v2.md` rilevanti per il **prossimo step** indicato nel SESSION-STATE (i §N sono citati accanto a ogni build step).

Se uno di questi file non è nel contesto, o se il SESSION-STATE è incoerente con lo stato reale del codice, **fermati e segnalamelo** prima di procedere.

## 2. Ri-acquisisci i guardrail (ad alta voce — è una garanzia di sicurezza)
Bastione lancia controlli attivi: a ogni sessione fresca ri-conferma esplicitamente i vincoli di §4 del SESSION-STATE (= §7/§28 del blueprint). Scrivi nella risposta che li rispetterai:
- Produzione = blocco assoluto · Owned-only (host non dichiarato → fermati e chiedi) · Read-only di default · **Scritture canary = staging-only con cleanup garantito; fuori dal capstone live restano offline/monkeypatch** · Segreti redatti · Se manca un dato critico → fermati e chiedi.

Questo non è cerimoniale: un contesto fresco senza re-conferma può derivare. Ri-ancorati. **I guardrail valgono anche per gli agenti del workflow:** vanno iniettati in OGNI prompt builder/fixer.

## 3. Riportami lo stato (breve, prima di agire)
Dammi un orientamento in poche righe:
- **Milestone** attiva e **avanzamento**: task/step `done/totale`, **prossimo**.
- Eventuali **blocchi** o decisioni OPEN che toccano il prossimo passo.
- L'**ultima riga di log** della sessione precedente (dove avevamo lasciato).
- Lo **stato del repo** (se ci sono modifiche non committate, test rossi, ecc.).

## 4. Proponi il piano di workflow della milestone e ATTENDI il via
Lo sviluppo è **workflow-first**: sulla base del `next` nel SESSION-STATE, **non** proporre il prossimo singolo step da scrivere a mano, ma il **piano del dynamic workflow** che chiude la milestone attiva. Promemoria di processo (LOCKED): **non aprire un dynamic workflow per ogni step**, ma **UN dynamic workflow che copre l'intera milestone**, con gli agenti in parallelo **dove i file lo consentono** (builder che editano lo stesso file vanno sequenziati nel working tree condiviso; builder su file disgiunti + tutte le blind-review girano in parallelo).

Proponi, in quest'ordine:

**(a) TASK-GRAPH della milestone.** I task atomici, **decomposti per OWNERSHIP DI FILE** (per massimizzare il parallelismo sicuro), con per ciascuno: dipendenze, file/output prodotti, **GATE** (i test che lo verificano) e **modello builder** (Sonnet 4.6 o Opus 4.8 secondo complessità).

**(b) PIANO DEL SINGOLO DYNAMIC WORKFLOW.** Le **ondate**: cosa gira **in parallelo** (file disgiunti) e cosa va **sequenziato** perché tocca lo stesso file; dove stanno le **blind-review** (k dimensioni, Opus) e i **fixer** (Opus). Un solo workflow per la milestone, non uno per step.

**(c) COME VERIFICHERAI.** Ground-truth dell'orchestratore = rieseguire `python -m pytest -q` (l'oracolo sono i test, MAI il self-report dell'agente) + **blind-review adversariale per dimensione**; per i deliverable human-facing, generare l'artefatto reale e ispezionarlo.

**(d) CHECKPOINT PRE-DISPATCH (PLAN).** Mostra il piano **prima di lanciare**. Poi **fermati e aspetta il mio ok**: non avviare lo strumento Workflow finché non confermo o aggiusto la direzione. Se ho richieste diverse dal `next` previsto, le do qui.

Per la meccanica completa (ruoli, modelli, cap di concorrenza, enforcement git sugli agenti, scoping dei commit, gestione delle ondate) **rimanda a `BASTIONE-WORKFLOWS.md`**: qui basta il piano, là c'è il come.

> **Opt-in dello strumento Workflow:** in sessione **ultracode** lo strumento è opt-in **automatico**; altrimenti l'opt-in è **esplicito** (dichiaralo quando proponi il piano).
