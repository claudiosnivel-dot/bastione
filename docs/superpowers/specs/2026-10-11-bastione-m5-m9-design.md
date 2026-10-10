# Bastione M5–M9: aggiornamento 2026 (blueprint per milestone, M5 dettagliata)

> **Spec di design** · Codename BAS · Stato: APPROVATA in brainstorming (Claudio, 2026-10-11) · Prossimo: revisione della spec scritta, poi implementation plan **di M5** (writing-plans)
>
> **Fonti:**
> - gap analysis `docs/research/2026-10-10-gap-analysis-sicurezza-2026.md` (commit `f841546`);
> - spec M5 "debito blueprint" scritta con Fable (2026-10-10), **riverificata e corretta** (§3);
> - fact-check su fonti primarie del 2026-10-10/11.
>
> **Granularità:** **M5 è dettagliata** fino al livello che serve per il piano. **M6–M9 sono fissate a livello di milestone** (scope, livelli, prerequisiti): ognuna avrà la sua spec quando arriva il suo turno (una milestone per sessione, `BASTIONE-WORKFLOWS.md`).
>
> **Alla chiusura di ogni milestone:** aggiornare SESSION-STATE (nuova §3-x, §7 log, §6 `next_session_goal`) e il blueprint §27 (roadmap).

## Missione e clausola d'uso (vincolante, precede ogni altra sezione)

**Bastione non nasce per attaccare: nasce per proteggere.** Il nome lo dice. Un bastione è un'opera di fortificazione, e lo scopo dello strumento è rendere i progetti di Claudio **il più possibile invulnerabili**: trovare le debolezze delle *sue* app prima di chiunque altro, chiuderle, e accorgersi subito se si riaprono.

1. **Il token di ownership è la clausola principale di utilizzo.**
   - Bastione agisce solo su asset di cui Claudio ha **provato il possesso**: il token pubblicato sull'host o nel DNS oggi, e per asset (R2) da M5 in poi.
   - Senza prova verificata, Bastione si limita a leggere ciò che è già pubblico, come un normale visitatore.
   - Con la prova, verifica le difese **di quel solo asset**.
   - Un asset non provato non viene mai toccato oltre l'inventario di informazioni pubbliche.
   - È una regola di codice (gate §7), non una raccomandazione.
2. **Ogni controllo esiste per produrre una correzione o confermare una protezione.**
   - Il ciclo è sempre: verifica → finding → remediation (playbook, FIX-PLAN per l'agente) → `bastione verify` → baseline.
   - Una protezione che regredisce genera un alert.
   - Un controllo che non porta né a una correzione né alla conferma di una difesa non entra in Bastione.
3. **Dimostrazione minima.** Quando serve confermare che una difesa manca, Bastione si ferma al minimo indispensabile per dimostrarlo:
   - legge metadati, mai dati (P8);
   - scrive solo canary usa-e-getta su staging, con cleanup garantito;
   - non sfrutta mai una debolezza oltre la conferma.
4. **Cosa Bastione non fa mai.**
   - Toccare sistemi non posseduti (art. 615-ter c.p.).
   - Azioni attive in produzione.
   - Estrarre o conservare dati degli utenti.
   - Persistenza, evasione, negazione del servizio.
   - Distribuire payload o strumenti riutilizzabili contro terzi.
5. **Onestà difensiva.** Ciò che Bastione non riesce a verificare viene dichiarato (R6, §26). Una protezione non verificata non viene mai presentata come presente.

Tutte le milestone M5–M9 qui sotto sono descritte in termini di **proprietà da proteggere** e di **verifiche che le confermano**. I dettagli tecnici delle singole richieste stanno nei piani di implementazione, derivati dal codice e dalle fonti verificate in §3.

## 0 · Perché

**Lo stato attuale.** M0–M4 hanno chiuso il canone §27 e il filone autenticato. La gap analysis del 2026-10-10 e la verifica sul codice mostrano tre cose:

1. **Bastione sta diventando cieco proprio dove è più forte.**
   - I progetti Supabase nuovi nascono **senza chiavi legacy** (solo `sb_publishable_` / `sb_secret_`), e le legacy saranno rimosse "late 2026".
   - Il recon riconosce solo `eyJ…`, quindi il modulo `supabase` non gira e non lo dice.
   - Dal **30/10/2026** cambia anche la semantica dell'accesso: niente GRANT automatici sulle nuove tabelle, errore `42501`.
2. **Alcune corsie danno falsi negativi credibili.**
   - `zap_active` non usa la sessione, non popola il site tree e non attende la fine dello scan.
   - `idor` scarta i cookie.
   - nuclei esclude per severità proprio i rilevamenti delle CVE critiche.
3. **Il debito del blueprint** (catalogo segreti §10.2, §11.1.3–5, TLS e origin §12, WordPress §13) e le aree 2026 non coperte (DNS ed email, framework, supply chain, controlli dall'interno, sicurezza degli agenti) vanno chiusi con un ordine **per tema**. Così lo stesso file non viene toccato in due milestone diverse.

**L'obiettivo resta quello di Bastione:** trovare ciò che è bucabile **sulle app di Claudio**, per correggerlo. Owned-only, by code.

## 1 · Decisioni prese (brainstorming 2026-10-10/11)

| # | Decisione |
|---|---|
| D1 | **Struttura per tema** (non "Fable intatta", non "una M5 enorme"). M5 = urgenze + le parti di Fable sugli stessi file (segreti, Supabase). M6 = perimetro (TLS, origin, WordPress, DNS ed email, takeover). M7 = framework e supply chain. M8 = dall'interno con token. M9 = agent-safety, AI, rumore. |
| D2 | **Regole trasversali R1–R7** (§2) approvate e LOCKED per M5–M9. |
| D3 | **Signup in sola lettura.** Il signup-probe di Fable (creare un utente) viene **sostituito** dalla lettura di `GET /auth/v1/settings` confrontata con un'attesa dichiarata (R1, R7). |
| D4 | **`sk_test_` esposta = HIGH**, come nel blueprint §10.2: stesso difetto architetturale della live, fa fallire il CI gate e scatena l'alert. |
| D5 | **Le RPC si invocano in `GET`** (transazione READ ONLY lato PostgREST), con denylist di nomi a effetto esterno, timeout e lettura minima. La severità dipende da ciò che esce: le colonne personali portano a CRITICAL. Argomenti opzionali dal TOML (modo oracolo). |
| D6 | **Probing di `.env`/`.git` in `server_exposure`**, non in `secrets` (lì esiste già da M4.4, a livello PROBE); i contenuti passano ai detector. |
| D7 | Ordine: **M5 → validazione live di M4+M5 → M6 → M7 → M8 → M9**. Gli opzionali (host SSH, porte, mobile, Electron) partono solo su trigger. |
| D8 | Commit su `main`; ogni milestone in **un** dynamic workflow (builder → blind-review → fixer, sequenziati per ownership dei file). |

## 2 · Regole trasversali (LOCKED per M5–M9)

**R1. Classificazione dell'intrusione.** Completa il §7 del blueprint e corregge l'ambiguità del §12.

| Livello | Cosa rientra |
|---|---|
| **READ_ONLY** | Ciò che farebbe un visitatore normale: GET di pagine e asset linkati; query DNS pubbliche e log Certificate Transparency; un handshake TLS ordinario; endpoint pubblici e documentati (`/auth/v1/settings`, `/.well-known/*`, JWKS). |
| **PROBE** | Ciò che fa solo chi indaga, senza creare stato: path indovinati; handshake TLS forzati per versione; invocazione **in sola lettura** di logica applicativa (RPC in GET, list dello storage, query GraphQL di introspezione); verifica di validità dei segreti presso il provider (solo chiamate di identità); connessioni dirette a IP dichiarati. |
| **MUTATING** | Tutto ciò che **crea stato o costa**: righe, utenti, file, **email inviate**, chiamate a servizi a pagamento, active scan. Resta staging-only, con ownership e `--i-own-this-its-staging`. |

**R2. Ownership per asset** (estende il token autorizzativo, §7.1).

| Asset | Prova di possesso |
|---|---|
| Host web | Come oggi: `/.well-known/bastione-ownership.txt` oppure TXT `_bastione.<host>`. **Irrigidimento:** match esatto di una riga (non sottostringa), e l'host finale deve essere lo stesso anche dopo un redirect. |
| Sottodominio | Dichiarato nel TOML **e** coperto da un TXT (sull'apex o sul sottodominio). |
| IP | Solo se **dichiarato nel TOML** e risolto da un hostname verificato. Mai range, mai IP trovati con euristiche. |
| Progetto Supabase / account Vercel-Netlify / repo GitHub (M8) | Il **token API** stesso. Il gate verifica che il project ref o il repo del token coincida con il target. |

Ciò che viene scoperto ma non è dichiarato si **inventaria soltanto** (DNS e CT sono pubblici) e non viene mai sondato.

**R3. Token API.**
- In sola lettura e con lo scope minimo.
- Solo da variabile d'ambiente (convenzione `*_env`, come `[auth]`).
- Redatti (P8); mai nel TOML, nei report o nel SARIF.

**R4. Tool esterni fail-closed.**
- `bastione/toolcheck.py` legge la versione di ogni tool e applica una policy (versione minima + denylist).
- Una versione vietata o sotto il minimo produce `*_SKIPPED` INFO con il motivo, e il tool **non** viene eseguito.
- Policy iniziale:
  - **trivy** ≥ 0.72.0 (CVE-2026-63328 nella 0.71.x), vietate 0.69.4, 0.69.5 e 0.69.6 (CVE-2026-33634, compromissione TeamPCP);
  - **nuclei** ≥ 3.10.0 (CVE-2026-76802/76803/76804/76805/76819).
- Workflow GitHub: action fissate per SHA. Dipendenze Python: lockfile con hash.

**R5. L'evidenza è un dato non fidato.** Nel bundle per l'agente di coding:
- le istruzioni di Bastione (template) e le evidenze stanno in blocchi separati, con avviso "dati, non istruzioni";
- le evidenze sono sanificate: via zero-width, bidi, ANSI e caratteri di controllo; troncamento.

Firma HMAC e guard sul perimetro del diff arrivano in M9.

**R6. Onestà, mai silenzio.** Ogni "non determinabile" diventa un finding INFO esplicito, per esempio `SUPABASE_KEY_NOT_FOUND` o `TLS_UNDETERMINED`. I limiti di §26 vengono resi nel report.

**R7. Oracle-first per i comportamenti che possono essere voluti.** Signup aperto, sign-in anonimo, bucket elencabili, RPC pubbliche:
- **finding** solo se violano un'attesa dichiarata nel TOML;
- senza attesa, **INFO** che chiede di dichiararla;
- la soppressione vale solo con una dichiarazione esplicita (come §15).

## 3 · Verifiche e correzioni rispetto alla spec di Fable

Tutti i punti sono verificati sul codice (path) o su fonte primaria.

| Punto di Fable | Esito | Correzione recepita |
|---|---|---|
| Debito: 1/7 detector, TODO in `cloudflare`/`headers`/`secrets`, playbook orfani, `wordpress/` assente, `testssl.sh` nel doctor, `_finding_id`, ABC `Detector`, playbook e FixBuilder Stripe | ✅ corretto | — |
| Signup-probe con POST `/auth/v1/signup` (classificato READ_ONLY) | ❌ | Contraddice §11.1.5 ("read-only") e L11. Con lo SMTP di default fallisce ("Email address not authorized", la transazione fa rollback, limite di 2 email/ora). Con uno SMTP custom genera bounce. → **D3**: `GET /auth/v1/settings`. |
| Storage: `GET .../object/list/{b}`; bucket da `GET /storage/v1/bucket` | ❌ | Il list è una **POST** (`object/list` e `object/list-v2`). Con la chiave anon, `GET /bucket` risponde `200 []` anche se i bucket esistono → nomi dal **bundle** e dal **TOML**. Pubblico ≠ elencabile (lint 0025). |
| RPC: euristica sui nomi `get_/list_/search_` per decidere cosa invocare; nomi dall'OpenAPI | ⚠️ | PostgREST esegue **qualunque** funzione chiamata in GET in transazione READ ONLY (una scrittura dà 405 / SQLSTATE 25006). L'OpenAPI è chiusa all'anon sull'hosted moderno (S9) → nomi da `.rpc('…')` nel bundle e dal TOML. Rischio residuo: effetti fuori dal database → denylist di nomi (**D5**). |
| TLS: "check minimo sulla versione negoziata" | ❌ | Una singola negoziazione restituisce la versione più alta: TLS 1.0 abilitato resta invisibile e il risultato "moderno" è falso. Serve un handshake **per versione** (min = max, `@SECLEVEL=0` per 1.0/1.1). → M6. |
| Origin: `GET https://<ip>/` con header `Host`; candidati da `mail.`, `ftp.`, SPF | ❌/⚠️ | SNI sbagliato → usare l'estensione `sni_hostname` di httpx. I candidati euristici sono spesso **IP di terzi** (provider di posta) → violazione di owned-only. Si sondano solo gli IP dichiarati (R2). Cloudflare Pages: non applicabile. → M6. |
| Probing di `.env`/`.git/config`/`.git/HEAD` nel modulo `secrets`, a READ_ONLY | ⚠️ | Già presente in `server_exposure` (M4.4, PROBE: `/.env`, `/.git/config`). → **D6**: estendere lì e passare i body ai detector. |
| Catalogo segreti (§10.2 del 2024) | ⚠️ | Manca **`sb_secret_`** (CRITICAL), più OpenAI, Anthropic, npm e bot Telegram. Stripe: 401 = morta, 403 = viva ma limitata. Google `AIza`: dopo maggio-giugno 2026 Gemini rifiuta le chiavi standard non ristrette → LOW, alzata solo se la verifica risponde. |
| WordPress: versione da `readme.html`; `should_run` da header e cookie | ❌/⚠️ | WordPress è alla 7.x e `readme.html` **non** mostra più la versione → meta generator, `<generator>` dell'RSS, `?ver=` degli asset core. `Fingerprint` non conserva l'HTML → il riconoscimento va nel **recon**. Il cookie `wordpress_` è raro sulla home anonima. WPScan gratuito: 25 chiamate/giorno; alternativa Wordfence Intelligence v3 (gratuito con chiave). → M6. |
| SPF/DKIM/DMARC rimandati "perché richiedono auth o nuova superficie" | ⚠️ | Sono query DNS READ_ONLY: nessuna dipendenza da auth. → M6. |
| Urgenze (chiavi `sb_`, 42501, difetti M4, nuclei, supply chain del tool, remediation scollegata) | assenti | → M5. |

## 4 · M5: "Supabase 2026 + segreti + correttezza" (DETTAGLIATA)

### 4.0 Guardrail (iniettati in ogni prompt di builder e fixer)

1. Produzione = blocco assoluto. Owned-only. READ_ONLY di default.
2. **Livelli** (R1):
   - recon, chiavi, 42501, auth settings, JWKS: READ_ONLY;
   - storage list, RPC in GET, introspezione GraphQL, liveness dei segreti, nuovi path di `server_exposure`: PROBE;
   - `zap_active`: MUTATING (invariato).
3. **Nessuna scrittura nuova** in M5. Le uniche corsie MUTATING restano quelle esistenti (canary §11.2, `idor` WRITE, `zap_active`).
4. **P8:** mai segreti, token, valori di righe, nomi di oggetti dello storage o body sensibili in un campo del Finding. Solo metadati: endpoint, regola, conteggi, nomi di colonna, esito.
5. Segreti di configurazione via ENV, mai nel TOML (R3).
6. Resilienza §4.7: I/O che fallisce o tool assente → `*_SKIPPED` / INFO, **mai** un crash.
7. Gate-first: ogni azione PROBE fa self-gate (`max_intrusion ≥ PROBE ∧ ownership_verified`) più `authorize(PROBE)` come backstop.
8. I sub-agenti **non** eseguono mai `git commit/add/push/checkout/reset` e toccano **solo** i file del loro task.

### 4.1 Mappa delle corsie e dell'ownership dei file

| Corsia | File posseduti | Dipende da |
|---|---|---|
| **W0 contratti** | `bastione/models.py`, `bastione/config.py`, `targets/_example.toml`, **nuovo** `bastione/toolcheck.py` (+ test) | — |
| **L1a recon** | `bastione/recon/fingerprint.py` | W0 |
| **L1b supabase core** | `bastione/modules/supabase/module.py` | W0, L1a |
| **L1c supabase sottomoduli** | **nuovi** `modules/supabase/storage.py`, `rpc.py`, `auth_posture.py`, `graphql.py` | W0 (paralleli tra loro); il wiring in `module.py` lo fa L1b-wiring dopo |
| **L2 catalogo segreti** | **nuovi** `modules/secrets/detectors/*.py`; `detectors/__init__.py` in un passo finale unico | W0 |
| **L3 server_exposure** | `modules/server_exposure/module.py` | L2 (registry dei detector; i detector sono già nel REGISTRY a runtime) |
| **L4 fix M4** | `modules/zap_active/module.py`, `modules/idor/module.py` | W0 (`toolcheck`) |
| **L5 tool e supply chain** | `modules/nuclei/module.py`, `modules/trivy/module.py`, `modules/semgrep/module.py`, `modules/zap/module.py`, `bastione/cli.py` (solo `doctor`), `.github/workflows/bastione.yml`, lockfile, `pyproject.toml` | W0 (`toolcheck`) |
| **L6 remediation e report** | `bastione/remediation/agent_bundle.py`, `playbooks/*.md`, `bastione/report/markdown.py`, `bastione/report/html.py` | W0; conosce i rule_id dalla spec (§4.9) |
| **WF wiring finale** | `bastione/orchestrator.py` (chiamata a `build_fix_plan` con i PostureCheck), `README.md` | tutte |

Ordine d'esecuzione:
1. Onda 1: W0.
2. Onda 2, in parallelo: L1a, L1c, L2, L4, L5, L6.
3. Onda 3: L1b (core + wiring dei sottomoduli) ‖ L3 ‖ `detectors/__init__.py`.
4. Onda 4: WF.

Blind-review per corsia, con le dimensioni correctness · sicurezza/P8/gate · robustezza. I fixer vanno sequenziati per file.

### 4.2 W0: contratti

**`models.py`:**
- `Fingerprint.supabase_key_kind: Literal["legacy_jwt", "publishable"] | None = None`. Il campo `anon_key` resta, per retrocompatibilità, e contiene la chiave pubblica di **entrambi** i tipi.
- `Fingerprint.discovered_buckets: list[str] = []`
- `Fingerprint.discovered_rpcs: list[str] = []`

**`config.py` / TOML** (tutto opzionale, `_flatten` esteso):

```toml
[supabase]
url = "https://abcdef.supabase.co"   # esistente; utile anche per i custom domain
buckets = ["avatars"]                # nomi noti (lo storage non li elenca all'anon)
rpcs = ["get_listino"]               # nomi noti oltre a quelli del bundle

[expectations.auth]
signup_open = false                  # il signup pubblico è voluto?
anonymous_signin = false             # il sign-in anonimo è voluto?

[[expectations.bucket]]
name = "avatars"
anon_list = false                    # l'anon può elencare gli oggetti?

[[expectations.rpc]]
name = "get_listino"
anon_execute = true                  # l'anon può eseguirla?
sample_args = { categoria = "freni" }  # opzionale: argomenti per invocarla (query string)
```

**`toolcheck.py`** (nuovo, puro più un confine I/O):
- `TOOL_POLICY = {"trivy": {"min": "0.72.0", "deny": ["0.69.4", "0.69.5", "0.69.6"]}, "nuclei": {"min": "3.10.0", "deny": []}}`
- `check_tool(name) -> ToolStatus(ok: bool, version: str | None, reason: str)`.
- Il confine `_read_version(name) -> str | None` è monkeypatchabile: argv-lista `[name, "--version"]`, con timeout.
- Versione non leggibile per un tool con policy → `ok=False` (fail-closed). Tool senza policy → `ok=True`.

### 4.3 L1: recon e Supabase. Obiettivo: "la difesa dei dati Supabase resta verificabile nel 2026"

| Proprietà da proteggere | Cosa Bastione conferma | Esito se la protezione manca o non è verificabile |
|---|---|---|
| Le tabelle restano protette anche sui progetti con le chiavi nuove | Il recon riconosce la chiave pubblica in **entrambi** i formati (legacy e publishable): la verifica RLS continua a girare. | `SUPABASE_KEY_NOT_FOUND` / `SUPABASE_URL_NOT_FOUND` (INFO, R6): la verifica non è stata fatta, e il report lo dice. |
| Il motivo per cui un dato è protetto è solido | Distingue "protetto da policy RLS" da "protetto solo dall'assenza di GRANT" (default Supabase dal 30/10/2026). | Il secondo caso è **protetto ma fragile**: posture pass con nota e raccomandazione di abilitare la RLS esplicitamente; la verifica definitiva è in M8. |
| Il progetto è pronto alla rimozione delle chiavi legacy | Segnala chiavi legacy ancora in uso e firma JWT solo legacy. | `SUPABASE_LEGACY_KEYS_IN_USE`, `SUPABASE_JWT_LEGACY_HS256` (INFO, migrazione). |
| I file nello storage sono visibili solo a chi deve vederli | Per i bucket noti (bundle + TOML), conferma che l'anon non possa consultarne l'elenco, salvo attesa dichiarata (R7). | `STORAGE_PUBLIC_LISTABLE` (CRITICAL se i nomi suggeriscono dati personali, altrimenti HIGH). |
| Le funzioni del database non scavalcano la RLS | Per le RPC note (bundle + TOML), conferma che quelle non dichiarate pubbliche non siano eseguibili dall'anon e non restituiscano dati personali. L'invocazione avviene **solo in modalità di sola lettura garantita dal server**, con esclusione prudenziale delle funzioni a effetti esterni, timeout e lettura minima. | `RPC_DATA_EXPOSED` (CRITICAL), `RPC_ANON_WRITE_CAPABLE` (HIGH, TENTATIVE), `RPC_ANON_INVOCABLE` (MEDIUM, TENTATIVE); INFO per le funzioni non verificabili o escluse. |
| L'autenticazione è configurata come Claudio l'ha voluta | Confronta la configurazione pubblica dell'auth (signup, conferma email, sign-in anonimo) con le attese dichiarate. | `SIGNUP_OPEN`, `SIGNUP_NO_EMAIL_CONFIRM`, `ANON_SIGNIN_ENABLED` (MEDIUM); INFO "da dichiarare" se manca l'attesa. |
| La superficie GraphQL non è più ampia del necessario | Conferma che l'introspezione GraphQL non sia esposta all'anon. | `SUPABASE_GRAPHQL_INTROSPECTION` (LOW). |

**Coerenza con l'oracolo §15.** Una tabella dichiarata leggibile dall'anon (`anon_select=true`) ma negata produce `SUPABASE_EXPECTED_READ_DENIED` (INFO). Non è un problema di sicurezza, ma spiega perché la funzione dell'app potrebbe rompersi dopo il 30/10.

**Struttura.** `supabase/module.py` supera già le 1.400 righe. Le nuove verifiche vanno in sottofili isolati (`storage.py`, `rpc.py`, `auth_posture.py`, `graphql.py`), ognuno con un proprio confine I/O monkeypatchabile; `module.py` li orchestra.

**Livelli (R1).** Riconoscimento delle chiavi, semantica dell'accesso e configurazione pubblica dell'auth: READ_ONLY. Storage, RPC, GraphQL: PROBE, gate-first.

### 4.4 L2: catalogo segreti. Obiettivo: "nessuna chiave privata finisce nel browser"

Un file drop-in per detector (§10). `detectors/__init__.py` si aggiorna in un passo unico.

| `detector_id` | Riconosce | Severità | Verifica di validità (PROBE, solo identità) |
|---|---|---|---|
| `SECRET_SERVICE_ROLE` | JWT Supabase service_role (esistente) | CRITICAL | sì (esistente) |
| `SECRET_SUPABASE_SECRET_KEY` | chiave segreta Supabase nel formato nuovo | CRITICAL | sì |
| `SECRET_STRIPE` | chiavi segrete e ristrette Stripe; segreti dei webhook | live/ristretta CRITICAL · test **HIGH** (D4) · webhook HIGH | sì: distingue revocata / valida / valida con permessi limitati |
| `SECRET_AWS_AKIA` | access key AWS (permanenti e temporanee) | HIGH | no (solo flag, come §10.2) |
| `SECRET_GITHUB` | token GitHub (classici e fine-grained) | HIGH | sì |
| `SECRET_UPSTASH` | URL + token REST Upstash | HIGH | sì |
| `SECRET_PRIVATE_KEY` | blocchi di chiave privata | CRITICAL | no |
| `SECRET_HIGH_ENTROPY` | stringhe ad alta entropia fuori allowlist | LOW, sempre TENTATIVE | no |
| `SECRET_OPENAI` | chiavi API OpenAI | HIGH | sì |
| `SECRET_ANTHROPIC` | chiavi API Anthropic | HIGH | sì |
| `SECRET_NPM` | token npm | HIGH | sì |
| `SECRET_TELEGRAM_BOT` | token di bot Telegram (incluso quello di Bastione) | HIGH | sì |
| `SECRET_GOOGLE_API_KEY` | chiavi API Google | LOW; HIGH se la verifica conferma l'accesso alle API AI | sì |

**Regole LOCKED** (estendono §10.2):
- La verifica di validità usa solo chiamate di identità o di sola lettura: mai operazioni, anche se la chiave le permetterebbe.
- L'evidenza è sempre redatta.
- La remediation è sempre **rotazione** (passo umano, priorità 1, L13) e **spostamento lato server**.

### 4.5 L3: `server_exposure`. Obiettivo: "niente configurazioni né ambienti di sviluppo esposti"

- Estende l'elenco dei file di configurazione verificati: varianti di `.env`, metadati git, specifiche API pubblicate.
- Riconosce un **dev server** raggiungibile pubblicamente: `DEV_SERVER_EXPOSED` (HIGH).
- Specifica API pubblicata senza motivo: `API_SPEC_EXPOSED` (LOW).
- Il contenuto di un file di configurazione esposto passa ai detector di L2, così una chiave trapelata viene identificata e messa in rotazione.
- Solo same-host, livello PROBE (come M4.4).

### 4.6 L4: correzioni M4. Obiettivo: "le corsie autenticate dicono la verità"

- **`zap_active`:**
  - la sessione dell'account di test viene **davvero** applicata allo scan;
  - lo scan parte dagli endpoint dichiarati in `[auth]`;
  - i risultati si leggono solo a scan concluso (con timeout);
  - la configurazione di sessione viene rimossa a fine scan (`finally`);
  - la policy vincolata fail-closed resta invariata.
- **`idor`:** le sessioni basate su cookie vengono rispettate.
- Test di regressione per ogni difetto. Senza queste correzioni, la validazione live di M4 rischia di confermare come protetta un'app che non lo è.

### 4.7 L5: strumenti e supply chain. Obiettivo: "gli strumenti di Bastione non diventano un rischio"

- `toolcheck` (R4) applicato a tutti i wrapper e a `doctor`, che mostra versione e stato di ogni tool.
- nuclei: la copertura di **rilevamento** include anche le CVE gravi. Restano escluse per tag le categorie invasive o di disservizio.
- Workflow GitHub con action fissate per SHA; lockfile Python con hash.
- **Azione umana:** aggiornare trivy locale a ≥ 0.72.0.

### 4.8 L6: remediation e report. Obiettivo: "ogni problema trovato arriva a una correzione verificabile"

- Il fix plan consuma anche i **PostureCheck falliti** (oggi solo i Finding). Si allineano i rule_id (`MISSING_CSP` → `POSTURE_CSP`).
- Il template SQL per la RLS segue il pattern raccomandato da Supabase dopo il 30/10: abilitazione della RLS, policy e GRANT espliciti nella stessa migrazione.
- **Playbook per tutti i rule_id M4 e M5** (§4.9). I playbook orfani restano finché M6 non li emette.
- Bundle per l'agente conforme a R5 (blocchi separati, evidenze sanificate).
- Limiti onesti di §26 resi nel report MD e HTML.

### 4.9 Modello dati M5 (rule_id e check_id nuovi)

- **supabase:**
  - INFO: `SUPABASE_KEY_NOT_FOUND`, `SUPABASE_URL_NOT_FOUND`, `SUPABASE_LEGACY_KEYS_IN_USE`, `SUPABASE_JWT_LEGACY_HS256`, `SUPABASE_EXPECTED_READ_DENIED`;
  - storage e RPC: `STORAGE_PUBLIC_LISTABLE`, `RPC_DATA_EXPOSED`, `RPC_ANON_WRITE_CAPABLE`, `RPC_ANON_INVOCABLE`, `RPC_NOT_VERIFIABLE` (INFO);
  - auth e GraphQL: `SIGNUP_OPEN`, `SIGNUP_NO_EMAIL_CONFIRM`, `ANON_SIGNIN_ENABLED`, `AUTH_EXPECTATION_UNDECLARED` (INFO), `SUPABASE_GRAPHQL_INTROSPECTION`;
  - posture: `POSTURE_STORAGE_PRIVATE_<bucket>`, `POSTURE_RPC_GATED_<fn>`, `POSTURE_AUTH_AS_DECLARED`.
- **secrets:** i `detector_id` della tabella §4.4.
- **server_exposure:** `DEV_SERVER_EXPOSED`, `API_SPEC_EXPOSED`.
- **tool:** gli `*_SKIPPED` esistenti, con il nuovo motivo "versione non ammessa".

Tutti con `_finding_id` LOCKED (§16) e `check_id` stabili (§17). Pesi del posture score invariati.

### 4.10 Testabilità offline

- Per ogni corsia, **app sintetiche in due varianti**: protetta (ogni verifica deve confermare la difesa) e non protetta (ogni verifica deve accorgersi della mancanza).
- Confini I/O monkeypatchati; nessun target live nei test.
- **Gate-test:** a READ_ONLY o senza ownership, nessuna azione PROBE parte (zero richieste).
- **P8-test** con valori sentinella: segreti, righe, nomi di oggetti mai presenti in evidence, title e description.
- **`toolcheck`:** versioni vietate o sotto il minimo devono produrre SKIPPED senza esecuzione.
- **Ground truth:** `python -m pytest -q` rilanciato dall'orchestratore sull'albero stabile, più blind-review per dimensione (correctness · sicurezza/P8/gate · robustezza).

### 4.11 Validazione live (fuori dall'automazione)

Richiede target owned + staging + `ownership_token` pubblicato + ok esplicito di Claudio:
- un **progetto Supabase nuovo** (solo chiavi nel formato nuovo) collegato al sandbox Vercel, con configurazioni volutamente deboli (un bucket consultabile, una RPC non protetta, signup aperto non dichiarato) per confermare che Bastione le trova, e poi che `verify` le dà per chiuse dopo la correzione;
- i target owned già in uso;
- in coda, la validazione live delle corsie M4 (ora affidabili grazie a L4).

### 4.12 Fuori scope di M5

- Valori degli header e TLS → M6 (stesso file `headers`).
- Origin, WordPress, DNS ed email → M6.
- Edge Functions, mass assignment e verifica interna di GRANT e RLS → M8.

---

## 5 · M6: "Perimetro esterno e trasporto" (livello milestone)

**Obiettivo:** il perimetro pubblico delle app è solido e resta tale.

- **`headers`:**
  - valutazione dei **valori** (qualità della CSP, durata di HSTS, header deprecati come INFO);
  - **TLS**: versioni abilitate verificate una per una (non per negoziazione unica), con `testssl.sh` quando c'è;
  - **scadenza dei certificati** rispetto alle nuove durate (200, 100, 47 giorni);
  - nessuna penalità per l'assenza di OCSP.
- **`cloudflare`:** conferma che l'origin non sia raggiungibile aggirando Cloudflare, **solo sugli IP dichiarati** (R2). Non applicabile a Cloudflare Pages.
- **Nuovo modulo `dns_email`** (READ_ONLY): SPF, DKIM, DMARC (RFC 9989), CAA, DNSSEC, protezione anti-spoofing dei domini che non inviano posta.
- **Inventario dei sottodomini** da Certificate Transparency e controllo dei CNAME orfani (rischio takeover) sui sottodomini **dichiarati**. Gli altri si inventariano soltanto.
- **`surface`** collegato alla pipeline, con sottodomini, certificati e IP nel diff.
- **WordPress (§13):**
  - riconoscimento nel recon;
  - strato nativo READ_ONLY (esposizione della versione, xmlrpc, esposizione dell'elenco utenti, file di backup);
  - feed di vulnerabilità opzionale con chiave da ENV.
- **Live:** i siti WordPress e le app Cloudflare di Claudio.
- **Prerequisito:** R2 per sottodomini e IP.

## 6 · M7: "Framework e supply chain" (livello milestone)

**Obiettivo:** framework e dipendenze delle app non hanno vulnerabilità note sfruttate.

- **Fingerprint delle versioni** dello stack JS (Next.js, React, Vite), confrontate con OSV/GHSA e priorità a KEV ed EPSS. Niente soglie scritte a mano: le versioni sicure cambiano spesso (es. il rilascio Next.js del 14/10/2026).
- **Rilevamento non invasivo** delle CVE note dei framework: solo template di rilevamento, PROBE.
- **Librerie vulnerabili nel bundle** e **inventario degli script di terze parti**, con SRI e drift degli hash.
- **Corsia repo** (INT, token GitHub in sola lettura):
  - audit dei workflow (zizmor, actionlint);
  - OSV-Scanner, compresi i pacchetti malevoli noti;
  - configurazione di cooldown e script di install;
  - segreti nella storia git;
  - integrità dei file di configurazione degli agenti (`.claude/settings.json`, `.vscode/tasks.json`, `.mcp.json`).

## 7 · M8: "Dall'interno, con il token autorizzativo" (livello milestone)

**Obiettivo:** le configurazioni che dall'esterno non si vedono sono corrette.

- **W0:** estensione del gate a R2 e R3 (binding token ↔ target).
- **Supabase Management API** (sola lettura):
  - lint del Security Advisor come Finding;
  - GRANT e stato RLS reali (chiude il "protetto ma fragile" di M5);
  - impostazioni auth;
  - stato delle chiavi legacy;
  - policy dello storage;
  - verifica JWT delle Edge Functions.
  - Trasforma due limiti onesti di §26 in verifiche vere.
- **API Vercel e Netlify:** variabili d'ambiente non marcate *sensitive*, livello di protezione delle preview.
- **Impostazioni del repo GitHub:** secret scanning, push protection, permessi di default del token, policy di pin per SHA.
- **Corsie autenticate:** verifica della protezione contro il mass assignment, su canary di proprietà (MUTATING, staging).

## 8 · M9: "Agent-safety, AI e riduzione del rumore" (livello milestone)

**Obiettivo:** le correzioni automatiche sono sicure e l'attenzione di Claudio va solo dove serve.

- **Bundle di remediation:**
  - firma HMAC verificata da un hook di Claude Code;
  - guard sul perimetro del diff (un fix non tocca workflow, CLAUDE.md, dipendenze);
  - `bastione verify` obbligatorio prima di chiudere.
- **Prioritizzazione Act / Attend / Track** (KEV, EPSS, SSVC). Telegram solo per Act e regressioni, il resto in un digest settimanale. SARIF con `baselineState` e `security-severity`.
- **Inventario delle configurazioni MCP**, con hash delle descrizioni dei tool e drift.
- **Endpoint AI delle app:** autenticazione e limiti verificati contro le attese del TOML, **senza generare costi**.
- **Privacy:** tracker caricati prima del consenso e drift delle terze parti.

## 9 · Opzionali (partono solo su trigger)

- **Audit di un host via SSH:** solo se Claudio ha un VPS; chiave dedicata in sola lettura, comandi in allowlist.
- **Servizi esposti** sugli IP dichiarati.
- **App mobile ed Electron:** solo se entrano nel portfolio.

## 10 · Ordine, dipendenze, chiusura

**M5 → validazione live di M4 e M5 → M6 → M7 → M8 → M9.**

- Ogni milestone ha la propria spec (M6–M9) e il proprio piano, costruiti in **un** dynamic workflow.
- Alla chiusura: SESSION-STATE e blueprint §27 aggiornati, commit e push su `main`.
- M8 dipende dal W0 del gate esteso.
- M9 dipende dai rule_id stabili di M5–M8.

## 11 · Domande aperte (non bloccanti, da chiudere nei piani)

- Strumento per il lockfile Python: pip-tools (uv non è installato in locale) oppure uv.
- Timeout di default di `zap_active` (proposta: 30 minuti, configurabile via ENV).
- Elenco definitivo delle funzioni escluse per prudenza dalla verifica delle RPC.
- `SIGNUP_NO_EMAIL_CONFIRM`: finding sempre, o anche questo governato da un'attesa (R7)?
- M6: WPScan (25 chiamate al giorno gratuite) o Wordfence Intelligence (gratuito con chiave) come feed predefinito.
- R2: un TXT sull'apex può coprire tutti i sottodomini dichiarati, o serve un TXT per sottodominio?

## 12 · Fonti principali

- Gap analysis: `docs/research/2026-10-10-gap-analysis-sicurezza-2026.md`, con le fonti per area.
- Supabase:
  - grant: https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically
  - chiavi API: https://supabase.com/docs/guides/api/api-keys
  - migrazione chiavi: https://github.com/orgs/supabase/discussions/29260
  - Security Advisor: https://supabase.com/docs/guides/database/database-advisors
  - Auth: https://github.com/supabase/auth
  - Storage: https://github.com/supabase/storage
- PostgREST, modalità di accesso delle funzioni: https://docs.postgrest.org/en/v13/references/transactions.html
- Trivy, advisory: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- Nuclei, advisory: https://github.com/projectdiscovery/nuclei/security/advisories
- OpenSSL 3, migrazione (TLS 1.0/1.1): https://github.com/openssl/openssl/blob/openssl-3.0/doc/man7/migration_guide.pod
- DMARC: https://www.rfc-editor.org/rfc/rfc9989
- Let's Encrypt, durata dei certificati: https://letsencrypt.org/2025/12/02/from-90-to-45
- Next.js, rilascio di sicurezza di ottobre 2026: https://nextjs.org/blog/upcoming-nextjs-security-update-october-2026
- GitHub Actions, protezioni sull'esecuzione dei workflow: https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/

---

*Allineato a `BASTIONE-BLUEPRINT-v2.md` (§1, §5–§7, §9–§18-bis, §26–§27), `BASTIONE-WORKFLOWS.md`, ai moduli esistenti e alle spec M4 in `docs/superpowers/`.*
