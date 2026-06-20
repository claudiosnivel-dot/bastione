# Bastione M4 — Corsie autenticate: login-hardening + ZAP-active + server-exposure (M4.2 + M4.3 + M4.4)

> **Spec di design** · Codename BAS · Stato: APPROVATA (brainstorming, 2026-06-20) · Prossimo: implementation plan (writing-plans)
> Estende il fondamento **M4.0** (`auth/session`, `recon/api_surface`, `[auth]`) già in repo (commit `e51ab48`). Sorelle di M4.1 (IDOR, `51c2e8c`). Alla chiusura, M4 va aggiornata in SESSION-STATE §3-quinquies.

## 0 · Perché

Su architetture stile **titanseo** (Supabase lato server, login wall) il rischio si è spostato sulla superficie **autenticata**. M4.1 (IDOR) copre l'accesso cross-tenant. Queste tre corsie coprono il resto della superficie che il muro di login NON rende sicura:
- **M4.2 — robustezza del login**: il muro stesso (rate-limit, enumerazione account, sicurezza di sessione).
- **M4.3 — DAST autenticato**: vuln web generiche sull'API *dietro* il login (XSS/injection), via ZAP active con la sessione.
- **M4.4 — segreti/config lato server**: service_role/segreti trapelati in source-map/errori/endpoint di debug, CORS permissivo.

## 1 · Scope

Tre **moduli nuovi e indipendenti** (file disgiunti → builder paralleli), tutti sul fondamento M4.0 e sui pattern stabiliti (`@register` §9 · self-gate + `which`→`SKIPPED` INFO §14/§26 · confine I/O modulo-livello monkeypatchabile · `_finding_id` LOCKED §16 · P8 · offline-test). **Fuori scope:** estensioni future; auto-crawl headless; il modulo `zap` passive esistente NON viene toccato.

## 2 · Guardrail (LOCKED — §7/§28, anche per gli agenti)

1. Produzione = blocco assoluto. Owned-only. READ_ONLY di default.
2. **M4.2/M4.4 = PROBE** (azioni attive non-mutanti: login a password sbagliata, probe di endpoint, trigger di errori GET/POST innocui). **M4.3 = MUTATING** (active scan può mutare incidentalmente → staging-only + `ownership_token` + `--i-own-this-its-staging`, gate-first `authorize(MUTATING)`).
3. **Niente brute-force.** M4.2 rate-limit usa un **cap basso** (≤5) di tentativi a **password sbagliata** su un account di TEST per *rilevare* il rate-limiting, non per indovinare. Documentato.
4. **P8:** mai segreti/token/dati sensibili in un campo Finding — solo metadati (endpoint, regola, presenza). I segreti trovati (M4.4) si riportano **redatti** (riusa i detector §10 che già redigono).
5. Segreti di config (API key ZAP) via **ENV**, mai nel TOML.
6. Resilienza §4.7: confini I/O che falliscono / tool assente → `*_SKIPPED` INFO o nessun finding, mai crash.

## 3 · M4.2 — `bastione/modules/login_hardening/module.py` (PROBE)

**`LoginHardeningModule`** (`name="login_hardening"`, `max_intrusion=PROBE`). `should_run` = `cfg.auth` ha ≥1 `test_account` con `mode="login_post"` (serve un `login_url`). Confine I/O modulo-livello `_login_request(url, *, json, headers) -> response|None` (monkeypatchabile).

`run`: self-gate (`max_intrusion<PROBE` o `not ownership_verified` → `LOGIN_HARDENING_SKIPPED` INFO, nessuna richiesta) → `authorize(PROBE, ctx)` backstop → oracoli:

| oracolo | come | finding |
|---|---|---|
| **rate-limit** | ≤5 POST a `login_url` con password ERRATA (mai quella vera) per l'account di test; se nessuna risposta 429/blocco compare entro il cap → falla | `LOGIN_NO_RATE_LIMIT` (HIGH) |
| **enumerazione account** | confronta la risposta del login (o di un endpoint reset se dichiarato) per un'email **esistente** (quella del test account) vs una **inesistente** (derivata, es. `nonexistent-<rand>@<dominio>`); se status/messaggio rivelano l'esistenza → falla | `LOGIN_USER_ENUMERATION` (MEDIUM) |
| **sicurezza sessione** | dopo UN login riuscito (via `acquire_session` M4.0), ispeziona i flag del cookie di sessione (`HttpOnly`, `Secure`, `SameSite`); flag mancanti → falla | `SESSION_COOKIE_INSECURE` (MEDIUM) + PostureCheck `POSTURE_SESSION_COOKIE` |

**P8:** evidence = solo esito (es. "5 tentativi falliti senza 429", "status 200 per email nota vs 404 per ignota", "cookie senza HttpOnly") — mai la password né il token. **Skip onesto** se il login_url non risponde. Cap rate-limit configurabile (`[auth].login_attempts_cap`, default 5).

## 4 · M4.3 — `bastione/modules/zap_active/module.py` (MUTATING 🔴)

**`ZapActiveModule`** (`name="zap_active"`, `max_intrusion=MUTATING`). Colla sottile attorno a **ZAP active** (clone del pattern nuclei/trivy §14). `should_run` = `cfg.auth` presente (sessione) **e** `cfg.auth.api_endpoints` non vuoto. Confine I/O modulo-livello `_run_zap_active(base_url, session_headers, endpoints, out_path) -> alerts|None` (monkeypatchabile; nei test ritorna JSON di alert sintetici).

`run`: self-gate (`max_intrusion<MUTATING` → `ZAP_ACTIVE_SKIPPED` INFO; o `not ownership_verified` → SKIPPED) → **gate-first `authorize(MUTATING, ctx)`** (propaga `IntrusionDenied` → run aborta) → `which("zap"/"zap.sh")` assente → `ZAP_ACTIVE_SKIPPED` INFO onesto → acquisisce la sessione (M4.0) → invoca `_run_zap_active` con **policy VINCOLATA** (esclude le regole ascan distruttive/mutanti, cap di severità — sul modello del fix nuclei M1 `-exclude-tags`) sugli endpoint scoperti → parse alert → `Finding[]` (risk ZAP `High/Medium/Low/Informational`→`Severity`; `rule_id` = pluginId/alert name; `location.endpoint` = url; evidence **redatta** = nome alert + url, mai il payload/response body sensibile; `intrusion_used=MUTATING`; dedup §16).

`ZAP_ACTIVE_SKIPPED` INFO (gated / ZAP assente / sessione non acquisita). API key/host ZAP via ENV (`BASTIONE_ZAP_API_KEY`, `BASTIONE_ZAP_ADDR`). Raw JSON in `run_dir/raw/zap-active.json` (§4). **Wiring `doctor`:** `zap` aggiunto a `_EXTERNAL_TOOLS`.

> **Policy vincolata (LOCKED):** la scansione attiva esclude le categorie di attacco distruttive/state-changing dove ZAP lo consente; resta detection-oriented. Anche così è MUTATING (può submettere a form/endpoint) → gate alto. La validazione live è outward-facing/gated.

## 5 · M4.4 — `bastione/modules/server_exposure/module.py` (PROBE)

**`ServerExposureModule`** (`name="server_exposure"`, `max_intrusion=PROBE`). `should_run` = sempre True su un target http (riusa `base_url`/fingerprint). Confine I/O modulo-livello `_fetch(method, url, *, headers) -> response|None` (monkeypatchabile). Riusa i **detector §10** (REGISTRY `DETECTORS`) per i segreti.

`run`: self-gate (`max_intrusion<PROBE` o `not ownership_verified` → `SERVER_EXPOSURE_SKIPPED` INFO) → `authorize(PROBE, ctx)` → oracoli:

| oracolo | come | finding |
|---|---|---|
| **source map** | per ogni bundle JS noto (fingerprint), prova `<bundle>.map`; se 200, passa il contenuto ai detector §10 | `SOURCEMAP_EXPOSED` (CRITICAL se trova `SECRET_SERVICE_ROLE`, altrimenti MEDIUM: codice sorgente esposto) |
| **errori verbosi** | una richiesta malformata a un endpoint API (`POST` body non valido) → la risposta contiene stack trace / path / framework? | `VERBOSE_ERROR_LEAK` (MEDIUM) |
| **endpoint sensibili** | GET su una **allowlist** built-in (`/.env`, `/.git/config`, `/api/debug`, `/server-status`, `/actuator`, …); 200 + contenuto plausibile → falla | `SENSITIVE_ENDPOINT_EXPOSED` (HIGH) |
| **CORS** | `OPTIONS`/`GET` con `Origin: https://evil.example`; risposta con `Access-Control-Allow-Origin: *` **o** l'origin riflessa **insieme a** `Access-Control-Allow-Credentials: true` → falla | `CORS_MISCONFIG` (HIGH) |

**P8:** i segreti trovati nelle source-map sono **redatti dai detector §10** (mai in chiaro); l'evidence degli errori verbosi riporta solo il *tipo* di leak (es. "stack trace presente"), non il corpo. `SERVER_EXPOSURE_SKIPPED` INFO se gated. PostureCheck per gli oracoli che passano (es. `POSTURE_NO_SOURCEMAP`, `POSTURE_CORS_SAFE`).

## 6 · Modello dati (rule_id nuovi)

`login_hardening`: `LOGIN_NO_RATE_LIMIT` (HIGH), `LOGIN_USER_ENUMERATION` (MEDIUM), `SESSION_COOKIE_INSECURE` (MEDIUM), `LOGIN_HARDENING_SKIPPED` (INFO).
`zap_active`: `<zap-pluginId>` (severity mappata), `ZAP_ACTIVE_SKIPPED` (INFO).
`server_exposure`: `SOURCEMAP_EXPOSED` (CRITICAL/MEDIUM), `VERBOSE_ERROR_LEAK` (MEDIUM), `SENSITIVE_ENDPOINT_EXPOSED` (HIGH), `CORS_MISCONFIG` (HIGH), `SERVER_EXPOSURE_SKIPPED` (INFO).
PostureCheck: `POSTURE_SESSION_COOKIE`, `POSTURE_NO_SOURCEMAP`, `POSTURE_CORS_SAFE`, `POSTURE_NO_RATE_LIMIT`(passa se rate-limit presente). Tutti con `_finding_id`/`check_id` stabili (§16/§17).

## 7 · Config (TOML) — aggiunte minime

```toml
# riusa [auth] di M4.0; per M4.2 basta un test_account login_post
[auth]
login_attempts_cap = 5        # M4.2: cap basso del rate-limit probe (default 5)

[[auth.test_accounts]]
label = "A"
mode = "login_post"
login_url = "https://staging.example.com/api/auth/login"
email = "test-a@example.com"
password_env = "BASTIONE_IDOR_A_PW"
session_cookie = "session"     # per il check SESSION_COOKIE_INSECURE
```

Segreti via ENV: `BASTIONE_ZAP_API_KEY`, `BASTIONE_ZAP_ADDR` (M4.3); password (M4.2) via `password_env`. Allowlist endpoint sensibili (M4.4) = built-in nel modulo (estendibile in futuro). Nuovo campo opzionale `AuthConfig.login_attempts_cap: int = 5`.

## 8 · Testabilità offline (metodo Bastione)

Per ogni modulo: confini I/O monkeypatchati (`_login_request` / `_run_zap_active` / `_fetch`), **app sintetiche** in due varianti — **vulnerabile** (es. niente 429, cookie senza HttpOnly, `.map` esposta coi segreti, CORS `*`+credentials, alert ZAP presenti) e **hardened** (429 al 3° tentativo, cookie sicuro, `.map` 404, CORS safe, nessun alert) — e si verifica l'oracolo su entrambe. Gate-test (read-only/no-ownership → `*_SKIPPED`, nessuna richiesta; M4.3 MUTATING gate-denied → `IntrusionDenied` propaga). P8-test con valori-sentinella (segreto/password/token assenti da evidence/title/description). Ground-truth orchestratore = `python -m pytest -q` (mai self-report) + blind-review per dimensione (correctness · sicurezza/P8/guardrail · robustezza).

## 9 · Integrazione

`_ensure_modules_loaded` += `login_hardening`, `zap_active`, `server_exposure`. `doctor`: `zap` in `_EXTERNAL_TOOLS`. `list-modules` li mostra (login_hardening=probe, zap_active=mutating, server_exposure=probe) leggendo REGISTRY. SARIF/report/DefectDojo generici su `Finding[]` → nessuna modifica.

## 10 · Esecuzione live (outward-facing, FUORI dall'automazione)

Le tre corsie dal vivo su un'app reale sono **gated**: owned + `environment=staging` + `ownership_token` (per M4.3 anche `--i-own-this-its-staging`) + credenziali di test via ENV + ok esplicito di Claudio. Il codice e i test sono **offline**.

## 11 · Decisioni prese (brainstorming 2026-06-20)

- Tutte e 3 le corsie ora; tre moduli indipendenti.
- M4.2 + M4.4 = **PROBE**; **M4.3 = MUTATING** (active scan può mutare → gate alto staging-only + conferma esplicita).
- M4.3 = nuovo modulo `zap_active` (non si tocca il `zap` passive), policy vincolata, colla §14.
- M4.2 rate-limit: cap basso (≤5), password sbagliata, owned/staging, documentato (non brute-force).
- M4.4: riusa i detector §10 (segreti redatti); 4 oracoli (source-map, errori verbosi, endpoint sensibili, CORS).

## 12 · Domande aperte (non bloccanti, da rifinire in fase di plan)

- M4.2 enumerazione: criterio di "risposte distinguibili" (status code vs corpo vs timing). Proposta: status + presenza/assenza di un marker testuale; il timing è fragile offline → escluso.
- M4.3 policy vincolata: l'insieme esatto di regole ascan da escludere dipende dalla versione ZAP; in offline si testa il *parsing* e il *gate*, non la policy reale (che si valida live).
- M4.4 allowlist endpoint: set iniziale conservativo; evitare falsi positivi (un 200 generico di SPA su path ignoti → escludere via euristica content-type/markers).

---

*Allineato a `BASTIONE-BLUEPRINT-v2.md` (§5/§6/§7/§9/§10/§12/§14/§16/§17/§23/§25/§29), `BASTIONE-WORKFLOWS.md`, al fondamento M4.0 e alla spec IDOR (`2026-06-20-bastione-m4-authenticated-idor-design.md`).*
