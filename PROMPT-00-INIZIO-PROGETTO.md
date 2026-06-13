# PROMPT 00 — INIZIO PROGETTO (Bastione)

> **Come usare questo file:** incollalo in Claude Code **una sola volta**, al primissimo avvio del progetto (repo vuota). Bootstrappa Bastione e produce il primo incremento di M0. Da lì in poi userai `PROMPT-01-INIZIO-SESSIONE` e `PROMPT-02-FINE-SESSIONE` a ogni giro.

---

Sei l'agente che implementa **Bastione (BAS)**, un orchestratore di security testing **difensivo** per applicazioni web di mia proprietà. Questo è il primo avvio: la repo è vuota.

## 1. Documenti canonici (fonte di verità — leggili PRIMA di scrivere codice)
- `BASTIONE-BLUEPRINT-v2.md` — il **cosa**: architettura, contratti dati, macchina a stati, moduli, roadmap. Le sezioni sono numerate (§N). È **normativo**: non inventare struttura, segui §4.
- `BASTIONE-SESSION-STATE.md` — il **dove siamo**: milestone attiva, build order, Definition of Done, guardrail, log. È il file che terrai aggiornato a ogni sessione.

Se uno dei due non è nel contesto, **fermati e chiedimelo** prima di procedere.

## 2. Prime direttive di sicurezza (NON negoziabili — vincoli, non suggerimenti)
Bastione lancia controlli attivi contro infrastruttura: queste regole vengono prima di qualsiasi obiettivo di funzionalità. Sono in §7/§28 del blueprint e §4 del SESSION-STATE.
1. **Produzione = blocco assoluto.** Nessuna azione verso `environment="production"`.
2. **Owned-only.** Si tocca solo un target dichiarato `owned`/`authorized-written` nel TOML. Host non dichiarato → fermati e chiedi.
3. **Read-only di default.** In M0 è **tutto** read-only: nessuna scrittura, nessun ownership challenge necessario.
4. **Scritture (canary) = M2.** In M0 sono **stub** che sollevano `NotImplementedError("M2")`. Non anticiparle.
5. **Segreti redatti** in ogni output. Mai committare evidenze in chiaro; `.gitignore` su `runs/` e `targets/*.local.toml`. (Le `baselines/` invece **si committano**: il formato §16 non contiene evidenze, e servono al CI gate §22.)
6. **Se manca un dato critico** (`environment`, target che non risolve, o `ownership_token` quando la run chiede > read-only — in M0 read-only il token non serve, §7.1) → fermati e chiedi. Mai improvvisare.

Conferma di aver letto e accettato queste direttive nella tua prima risposta.

## 3. Convenzioni di codice (LOCKED)
- **Python 3.11+**, gestione dipendenze con **`uv`** (`pyproject.toml`), validazione con **pydantic v2** (vedi §2/§3 del blueprint).
- **Prosa e commenti in italiano; identificatori (classi, funzioni, variabili) in inglese.**
- Tool esterni invocati come subprocess, rilevati a runtime (`shutil.which`), skip graceful con warning se assenti — **mai crash** (§3, L06).
- Codice testabile: per ogni modulo non banale, un test minimo.

## 4. Protocollo di sessione (come manterremo il contesto)
Il contesto tra sessioni vive **solo** in `BASTIONE-SESSION-STATE.md`, non nella tua memoria. Quindi:
- A **inizio** sessione leggerai il SESSION-STATE e ti orienterai (lo farà `PROMPT-01`).
- A **fine** sessione aggiornerai il SESSION-STATE: spunti i build step fatti, aggiorni il JSON `bastione-devstate/1`, aggiungi una riga di log (lo farà `PROMPT-02`).
Senza questo rituale, la prossima sessione riparte cieca. Trattalo come parte del lavoro, non come extra.

## 5. Compito di QUESTO primo avvio
Esegui il **Build order M0** (§2 del SESSION-STATE) **in ordine**, dallo step 1 fino al **checkpoint dopo lo step 4 (il gate)**, poi **fermati e fammi rivedere**. Concretamente:
- **Step 1 — SCAFFOLD:** struttura repo esatta di §4 del blueprint + `pyproject.toml` (uv) + `.gitignore` (runs/, targets/*.local.toml — **non** baselines/, che si committa: §16/§22).
- **Step 2 — ENUMS+MODELS:** `enums.py` (§5.1) e `models.py` (§5: `Finding`, `PostureCheck`, `Fingerprint`, `RunContext`, …). Tutto il resto dipende da qui.
- **Step 3 — CONFIG:** `config.py` (load+validate TOML → `TargetConfig`) + `targets/_example.toml` (§29).
- **Step 4 — GATE 🔒:** `gate.py` con `assert_preconditions` + `authorize` + `verify_ownership` (§7, §7.1). Questo è il cuore di sicurezza: deve esistere **prima** di qualsiasi modulo.

Mi fermo qui apposta: il gate è il pezzo critico e voglio rivederlo prima che si costruisca sopra. Quando hai finito i 4 step:
1. Esegui i test che hai scritto e mostrami l'esito.
2. Aggiorna `BASTIONE-SESSION-STATE.md` (spunta gli step 1–4, aggiorna il JSON dev-state, aggiungi la riga di log — vedi `PROMPT-02`).
3. Dammi un riepilogo: cosa hai creato, cosa resta (step 5–16), eventuali dubbi.

Non procedere oltre lo step 4 in questa sessione. Iniziamo.
