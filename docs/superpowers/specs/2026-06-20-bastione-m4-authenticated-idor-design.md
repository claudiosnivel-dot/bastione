# Bastione M4 — Modalità autenticata + IDOR cross-tenant (M4.0 + M4.1)

> **Spec di design** · Codename BAS · Stato: APPROVATA (brainstorming, 2026-06-20) · Prossimo: implementation plan (writing-plans)
> Estende `BASTIONE-BLUEPRINT-v2.md` (v2.1). Alla chiusura della milestone, M4 va ripreso nel blueprint canonico + SESSION-STATE.

## 0 · Perché (motivazione)

Le app moderne stile **titanseo.vercel.app** mettono **Supabase lato server, dietro login, senza anon key nel bundle**. Questo toglie *una* classe d'attacco (bypass diretto dell'RLS via anon key), ma **non rende l'app sicura**: il peso della sicurezza si **sposta** sul livello di autorizzazione scritto a mano nel server, sul flusso di auth e sull'API della app. Con Supabase lato server si usa tipicamente la `service_role`, che **scavalca l'RLS** → l'autorizzazione la decide il codice applicativo, endpoint per endpoint. **Un controllo dimenticato = un altro utente legge/modifica i dati altrui** (Broken Access Control, OWASP #1).

Bastione oggi è **cieco su questa superficie**: il modulo Supabase (§11.1/§11.2) non parte se non c'è una superficie PostgREST raggiungibile dal client. "Il modulo non parte" ≠ "l'app è sicura": significa che Bastione non guarda il punto dove oggi nascono le falle di queste architetture.

**M4 = "Bastione autenticato"**: fa evolvere Bastione da auditor della superficie *anon* ad **attaccante autorizzato della superficie *autenticata*** (su app **owned**). Per le app future con questa architettura, M4 rende Bastione **più** prezioso, non obsoleto.

## 1 · Scope di QUESTA spec

- **M4.0 — Fondamenta "modalità autenticata"** (prerequisito di tutte le classi M4): acquisizione sessione, scoperta superficie API, estensione gate/config/modelli.
- **M4.1 — IDOR / accesso cross-tenant** (READ **e** WRITE), prima classe costruita sopra le fondamenta.

**Fuori scope (spec successive, stesso fondamento):** M4.2 robustezza login (rate-limit, enumerazione, sessione, reset) · M4.3 DAST web autenticato generico (ZAP active con sessione) · M4.4 segreti/config lato server. Fuori MVP anche: auto-crawl via **browser headless** (resta l'estrazione statica dal bundle + endpoint dichiarati); login via **Supabase Auth diretto** se l'anon key non è scopribile (si ricade su token pre-catturato / POST a login_url).

## 2 · Guardrail (LOCKED — ereditati da §7/§28, validi anche per gli agenti che costruiscono M4)

1. **Produzione = blocco assoluto.** `environment="production"` → abort.
2. **Owned-only.** Solo target dichiarati `owned`/`authorized-written`. Host non dichiarato → fermati e chiedi.
3. **Niente bypass dell'auth, niente brute-force.** Bastione fa login **solo** con le credenziali di test **fornite** dall'utente. Non indovina password, non forza il login. ("Attaccante" = utente di test legittimo che prova a violare la tenancy.)
4. **WRITE cross-tenant = MUTATING**, staging-only, gate-first, con **cleanup garantito** (canary §11.2). READ cross-tenant = PROBE.
5. **P8:** l'evidence non riporta mai i *valori* dei dati di A né i segreti di sessione (token/cookie redatti) — solo ID risorsa + fatto dell'esposizione.
6. **Resilienza non silenzio:** modulo che fallisce → `MODULE_ERROR`/`IDOR_SKIPPED` INFO, mai crash, mai skip silenzioso.
7. **Manca un dato critico** (account di test, login_url, ownership_token per >read-only) → fermati e chiedi.

## 3 · Architettura (componenti e confini)

Sottosistema **custom** (l'oracolo cross-tenant è il differenziatore che nessuno scanner pronto offre, perché non conosce la tenancy). Riusa il pattern moduli §9/§14, il gate §7, l'oracolo §15, il canary §11.2, i modelli §5, la testabilità offline (confini I/O monkeypatchati).

### 3.1 `bastione/auth/session.py` (M4.0)
- **Modello `AuthSession`** (§5): `account_label` (es. "A"/"B"), `scheme`, header/cookie di sessione (token redatto in repr/log, P8), `acquired_ok: bool`.
- **`acquire_session(account_cfg, *, _http=...) → AuthSession | None`**: confine I/O monkeypatchabile. Tre modi dichiarati nel TOML per-account:
  1. **`token`** (pre-catturato): bearer/cookie incollato nel config owned. *Universale* (copre titanseo che nasconde l'anon key). Nessuna chiamata di rete in acquisizione.
  2. **`login_post`**: `POST login_url` con `{email, password}` di test → estrae la sessione via `session_json_path` (es. `access_token`) o `session_cookie` (nome cookie). Funziona sia per Supabase Auth diretto sia per un `/api/auth/login` dell'app.
  3. *(esteso in futuro: Supabase Auth diretto con anon key scoperta.)*
- **Resilienza:** acquisizione fallita → `None` + finding onesto a valle (no crash).

### 3.2 `bastione/recon/api_surface.py` (M4.0)
- **`build_api_surface(fingerprint, cfg) → ApiSurface`**: dal bundle JS estrae `fetch('/api/...')`, riferimenti a server actions, manifest di route (estensione pura dell'estrazione bundle già esistente). **Ground truth = endpoint dichiarati nel TOML**; l'estrazione dal bundle è l'**assist** (e un finding INFO sulla copertura, come `SUPABASE_SCHEMA_VIA_BUNDLE`).
- **Modello `ApiSurface`** (§5): lista di `ApiEndpoint{method, path_template, kind: list|read|create|update|delete, public: bool}`.

### 3.3 `bastione/modules/idor/module.py` (M4.1)
- `IdorModule(Module)`, `name="idor"`, `max_intrusion=MUTATING` (il WRITE), ma il READ gira già a PROBE.
- `should_run`: vero se ci sono ≥2 account di test dichiarati **e** una superficie API (dichiarata o scoperta).
- `run(ctx)`: self-gate (sotto PROBE o senza ownership → `IDOR_SKIPPED` INFO) → acquisisce A, B, anon → **READ probe** (PROBE) → se `max_intrusion≥MUTATING` + flag staging → **WRITE probe canary** (§3.5) → parse → `Finding[]` + `PostureCheck[]`.

### 3.4 Estensioni trasversali (M4.0)
- **`config.py` / TargetConfig (§5.6, §29):** nuova sezione `[auth]` con `test_accounts` (lista: label + modo sessione), `api_endpoints` (lista dichiarata), `public_endpoints` (soppressione oracolo §15).
- **`gate.py` (§7):** `authorize(PROBE|MUTATING, ctx)` invariato come meccanica; il WRITE IDOR richiede MUTATING + ownership + staging + `--i-own-this-its-staging` (riuso del gate canary). Validazione che gli account siano dichiarati come **test** (non utenti reali) resta responsabilità dichiarativa dell'utente (owned-only).
- **`enums.py` (§5.1):** eventuali nuovi rule_id sono stringhe, nessun nuovo enum necessario oltre a quelli esistenti (Severity/Confidence/IntrusionLevel/Status).
- **Orchestratore (§6) + CLI (§25):** wiring `idor` in `_ensure_modules_loaded`, `doctor`, `list-modules`; il comando `scan` lo attiva quando `[auth]` è presente e l'intrusione lo consente.
- **SARIF/report (§23):** generici su `Finding[]`, nessuna modifica.

### 3.5 Algoritmo del probe (M4.1, il cuore)
1. **Acquisisci** sessioni A, B e (opzionale) anon.
2. **Enumera le risorse di A:** come A, chiama gli endpoint `list`/`read` dichiarati → raccogli gli **ID risorsa** e i corpi (dati legittimi di A = ground truth di "appartiene ad A").
3. **READ cross-tenant (PROBE):** per ogni risorsa di A, rigioca il `GET` **come B** e **come anon**.
   - **Oracolo:** B/anon ottengono i dati di A (2xx con corrispondenza) → **`IDOR_CROSS_TENANT_READ` CRITICAL**. 403/404/vuoto → isolamento OK → `PostureCheck POSTURE_TENANT_ISOLATION_<ep>` pass. Endpoint dichiarato `public` → finding **soppresso** + posture pass (§15).
4. **WRITE cross-tenant (MUTATING) — modello canary (§11.2):**
   - Come **A**: *crea* una **risorsa-canary usa-e-getta** via endpoint `create` dichiarato (body con marker) → registra ID + stato. (Mai sui dati reali di A.)
   - Come **B**: prova a *modificare* (PUT/PATCH) e *cancellare* (DELETE) la canary.
   - **Oracolo:** la modifica/cancellazione di B riesce e **persiste** (riletta come A) → **`IDOR_CROSS_TENANT_WRITE` CRITICAL**.
   - **Cleanup GARANTITO (`try/finally`):** A elimina la canary alla fine. Se B l'ha già cancellata (caso-finding) il cleanup è moot ma registrato. Cleanup fallito → **`IDOR_CLEANUP_FAILED` CRITICAL** (mai risorse orfane). Se non c'è endpoint `create` noto → **`IDOR_WRITE_SKIPPED_NO_CANARY` INFO** (onesto, niente write-test alla cieca).

## 4 · Modello dati (output)

Nuovi `rule_id` (modulo `idor`), `Finding`/`PostureCheck` esistenti (§5), `finding_id` formula LOCKED §16:
- `IDOR_CROSS_TENANT_READ` (CRITICAL, FIRM) — B/anon legge i dati di A.
- `IDOR_CROSS_TENANT_WRITE` (CRITICAL, FIRM) — B modifica/cancella la canary di A.
- `IDOR_CLEANUP_FAILED` (CRITICAL) — canary non ripulita (mai orfana silenziosa).
- `IDOR_SKIPPED` (INFO) — gated/senza account/senza superficie: skip **dichiarato** (§4.7/§26).
- `IDOR_WRITE_SKIPPED_NO_CANARY` (INFO) — nessun endpoint create → niente write-test.
- `POSTURE_TENANT_ISOLATION_<endpoint>` (PostureCheck) — isolamento che regge (pesa nello score §17).

**P8:** evidence = solo `{rule_id, method, path, ruolo-attaccante (B/anon), id-risorsa}`; **mai** i valori dei dati di A né i token di sessione (redatti).

## 5 · Config (TOML) — esempio

```toml
[auth]
# almeno 2 account di test OWNED su staging
[[auth.test_accounts]]
label = "A"
mode = "login_post"            # oppure "token"
login_url = "https://staging.example.com/api/auth/login"
email = "test-a@example.com"
password_env = "BASTIONE_IDOR_A_PW"   # mai password in chiaro nel TOML
session_json_path = "access_token"     # oppure session_cookie = "sb-..."

[[auth.test_accounts]]
label = "B"
mode = "token"
token_env = "BASTIONE_IDOR_B_TOKEN"

# superficie dichiarata (ground truth); l'estrazione dal bundle è assist
[[auth.api_endpoints]]
method = "GET"
path_template = "/api/orders"
kind = "list"

[[auth.api_endpoints]]
method = "GET"
path_template = "/api/orders/{id}"
kind = "read"

[[auth.api_endpoints]]
method = "POST"
path_template = "/api/notes"
kind = "create"

[[auth.api_endpoints]]
method = "DELETE"
path_template = "/api/notes/{id}"
kind = "delete"

# endpoint pubblici di proposito → oracolo soppresso (§15)
[auth.suppression]
public_endpoints = ["/api/health", "/api/public/*"]
```

I segreti (password, token) si passano via **env**, mai nel TOML committabile (P8 / §29).

## 6 · Testabilità offline (il metodo Bastione)

- **Confini I/O monkeypatchati:** `acquire_session` e un `_http_request(method, url, session) → Response` di modulo. Nessun target live nei test, nessuna rete.
- **App sintetiche in-memory:** i test costruiscono un finto backend (un dict di risorse per-tenant) in **due varianti** — (a) **isolata** (rifiuta cross-tenant → oracolo non emette finding, posture pass) e (b) **bucata** (serve i dati di A a B → oracolo emette `IDOR_CROSS_TENANT_READ/WRITE`). Si verifica l'oracolo su entrambe.
- **Cleanup canary provato offline:** test che la `try/finally` elimini la canary e che `IDOR_CLEANUP_FAILED` scatti se il delete fallisce (come i test §11.2).
- **P8:** test che asseriscono l'assenza dei valori-dato di A e dei token nell'evidence/title/description.
- **Gate:** test che sotto read-only/senza ownership → `IDOR_SKIPPED`, niente sessione, niente richieste; che il WRITE richiede MUTATING + staging.
- **Ground-truth orchestratore:** `python -m pytest -q` (mai il self-report degli agenti) + blind-review adversariale (correctness · sicurezza/P8/guardrail · robustezza/cleanup).

## 7 · Esecuzione live (outward-facing, FUORI dall'automazione)

Far girare M4.1 dal vivo su **titanseo** (o altra app owned) **non è un task da builder**: è gated su **target owned dichiarato + `ownership_token` pubblicato + `environment=staging` + due account di test forniti + `--i-own-this-its-staging` + ok esplicito di Claudio**. Senza, il gate aborta correttamente. Il codice e i test sono **offline**; il trigger gate solo l'esecuzione live.

## 8 · Decisioni prese (brainstorming 2026-06-20)

- Decomposizione in **M4** (oltre il canone §27); prima spec = **M4.0 + M4.1**.
- Auth: **mix** → token pre-catturato (pavimento) + POST a login_url (automazione).
- IDOR: **READ + WRITE** cross-tenant da subito.
- Architettura: **sottosistema custom** (Approccio 1), non ZAP (che non conosce la tenancy).
- Sicurezza WRITE: **risorsa-canary usa-e-getta creata da A** (mai dati reali), cleanup garantito §11.2.

## 9 · Domande aperte (da chiarire in fase di plan, non bloccanti)

- Forma esatta del confronto READ ("B vede i dati di A"): match per ID + presenza di campi non vuoti vs hash del corpo. (Proposta: risorsa identificata per ID; finding se B ottiene 2xx con un corpo non-vuoto/coerente per quell'ID di A.)
- Quanti ID risorsa di A campionare per endpoint (cap di sicurezza/rumore). (Proposta: cap piccolo configurabile, default basso.)
- Gestione dei path_template con più parametri.

---

*Allineato a `BASTIONE-BLUEPRINT-v2.md` §5/§6/§7/§8/§11.2/§14/§15/§16/§17/§23/§25/§29 e a `BASTIONE-WORKFLOWS.md`. Da foldare nel blueprint/SESSION-STATE all'avvio dell'implementazione.*
