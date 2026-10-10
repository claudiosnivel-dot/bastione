# Bastione e lo stato dell'arte della sicurezza a ottobre 2026: gap analysis e piano di aggiornamento

> **Data:** 2026-10-10 · **Base di confronto:** Bastione al commit `02447cd` (M0–M4 chiuse, 925 test verdi).
> **Metodo:**
> - quattro ricerche web parallele (web app/API · server e infrastruttura · cloud, supply chain e CI/CD · AI/LLM e temi emergenti);
> - un inventario del codice reale di Bastione;
> - una verifica diretta sulle fonti primarie dei punti più critici (Supabase changelog e docs, advisory Trivy) e sul codice dei difetti segnalati.
>
> **Affidabilità:**
> - Tutto ciò che riguarda **il codice di Bastione** è stato **verificato leggendo i file** (path citati).
> - Le affermazioni esterne hanno una fonte. **[NV]** = non verificato su fonte primaria (fonte unica secondaria o conoscenza pregressa).
>
> **Vincolo di lettura:** ogni proposta rispetta i principi LOCKED del blueprint (P1 owned-only by code, P2 read-only di default, P5 colla sottile, P8 segreti redatti). Le nuove corsie che richiedono accesso "dall'interno" passano dal **token autorizzativo** e dal gate (§7), come le corsie attuali.

---

## 0 · In sintesi

1. **La "gemma" Supabase sta per diventare cieca.**
   - Il recon riconosce solo le chiavi legacy `eyJ…` (JWT). Il modulo `supabase` gira solo se trova quella chiave.
   - Supabase sta migrando a `sb_publishable_…` / `sb_secret_…` e depreca le chiavi legacy **entro fine 2026**.
   - Su un'app che usa solo le chiavi nuove, Bastione **salta l'intera sonda RLS senza dirlo**. Il detector dei segreti non riconosce `sb_secret_…`, cioè la nuova chiave equivalente a service_role.
   - **È la priorità n.1.**
2. **Il 30 ottobre 2026 cambia il modello di esposizione di Supabase.**
   - Anche nei progetti esistenti le nuove tabelle non ricevono più grant automatici ad `anon` e `authenticated`.
   - I remediation SQL e la semantica dei finding vanno aggiornati: niente grant ≠ RLS che protegge.
3. **Le corsie M4 hanno tre difetti latenti** da correggere **prima** della validazione live già pianificata:
   - `zap_active` non usa la sessione autenticata.
   - `zap_active` legge gli alert senza attendere la fine dello scan.
   - `idor` scarta i cookie di sessione.
   - Una validazione live oggi darebbe **falsi negativi credibili**.
4. **La copertura è profonda su Supabase/RLS/IDOR ma stretta su tutto il resto.**
   - Mancano TLS, DNS/email, subdomain takeover, porte/servizi esposti, CVE dei framework (Next.js/React/Vite), qualità dei valori degli header (CSP), supply chain del repo, GitHub Actions, AI/LLM.
   - Il catalogo segreti ha **un solo detector** su sei previsti.
5. **La supply chain di Bastione stesso è un rischio reale.**
   - Trivy è stato compromesso a marzo 2026 (CVE-2026-33634, binari 0.69.4–0.69.6).
   - Bastione lancia qualunque `trivy` trovi sul PATH senza verificarlo.
   - Il workflow GitHub usa action fissate per tag, non per SHA.
6. **Il motore regge.** Gate, ownership, baseline/drift, SARIF, bundle per l'agente e portfolio sono allineati alle pratiche 2026 (CTEM, regression-as-a-check, VEX-like accept). Le novità si innestano come **moduli drop-in** senza toccare l'architettura.

---

## 1 · Cosa fa Bastione oggi (sintesi verificata)

| Area | Copertura attuale | Note |
|---|---|---|
| Recon | 1 GET di `base_url` + bundle `<script src>` same-host; whatweb/katana opzionali | Riconosce Supabase (solo `*.supabase.co` + anon JWT), Cloudflare (`cf-ray`), WordPress (solo via whatweb). Non riconosce nativamente Next.js, Vite, Vercel, Netlify, Firebase. |
| Supabase | RLS read anon, oracolo §15, canary write MUTATING, discovery tabelle dal bundle | Il punto più forte: validato live. |
| Segreti | **1 detector**: `SECRET_SERVICE_ROLE` (JWT `role=service_role`) + liveness | Il catalogo §10.2 (AWS, Stripe, GitHub, chiavi private, entropia) **non è stato costruito**. |
| Header | Solo **presenza** di HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy | Non valuta i valori (`unsafe-inline`, `max-age`, preload). |
| Cloudflare | Check "fronted" che passa sempre | L'origin-bypass è ancora TODO. |
| Black-box esterni | nuclei (cap `info,low,medium`), ZAP passive, ZAP active (MUTATING) | testssl.sh è elencato in `doctor` ma **mai invocato**. |
| White-box | trivy fs (vuln/secret/misconfig), semgrep `--config auto` | Serve `source_path`. |
| Autenticato (M4) | IDOR cross-tenant R/W, login hardening, server exposure (source map, 7 path, CORS) | Solo testato offline; la validazione live è il prossimo passo. |
| Difesa continua | baseline/drift, posture score, portfolio, CI gate, cron/GH Actions, Telegram, DefectDojo | Allineato alle pratiche moderne. |
| Remediation | FIX-PLAN.md + migrazioni SQL + `verify` | Di fatto si attivano solo `RLS_DISABLED` e `SECRET_SERVICE_ROLE` (vedi §2.6). |

---

## 2 · Urgenze (da fare prima di nuove funzionalità)

### 2.1 Nuove chiavi Supabase: Bastione non le vede 🔴

**Fatti verificati.**
- Docs ufficiali: le chiavi nuove sono `sb_publishable_…` (client, ruolo anon/authenticated) e `sb_secret_…` (backend, bypassa la RLS).
- *"Supabase is deprecating the anon and service_role keys by the end of 2026"*. Una data di rimozione definitiva non c'è.
- Le chiavi nuove vanno inviate nell'header `apikey`, *"not on Authorization: Bearer"*.
- Fonte: https://supabase.com/docs/guides/api/api-keys

**Nel codice.**
- `bastione/recon/fingerprint.py:51` estrae solo `eyJ…` (`_JWT_RE`).
- `bastione/modules/supabase/module.py:255`: `should_run` richiede `fp.anon_key is not None` → **con sole chiavi nuove il modulo non gira, e non viene emesso alcun finding SKIPPED**: è un silenzio, non un degrado dichiarato.
- `bastione/modules/secrets/detectors/service_role.py` cerca solo JWT: **`sb_secret_` esposto nel bundle = CRITICAL non rilevato**.
- `module.py:271` invia `Authorization: Bearer <chiave>`. Con una `sb_publishable_` questo comportamento va verificato su un progetto reale **[NV]**: potrebbe dare 401 e far sembrare la tabella "protetta" (falso negativo).

**Cosa fare.**
1. Riconoscere `sb_publishable_` come chiave pubblica e `sb_secret_` come segreto CRITICAL, con un detector dedicato e la liveness già esistente.
2. Inviare la publishable solo in `apikey`.
3. Se Supabase è rilevato ma nessuna chiave è estraibile, emettere un finding INFO esplicito `SUPABASE_KEY_NOT_FOUND`, non un silenzio (coerente con §26 "il report lo dichiara").
4. Riconoscere i custom domain Supabase, per esempio da `/auth/v1/` e `/rest/v1/` nel bundle.
5. Aggiungere un posture check informativo "chiavi legacy ancora in uso" (pianificare la migrazione).

### 2.2 30 ottobre 2026: fine dei grant automatici sulle nuove tabelle 🟠

**Fatti verificati.**
- Dal 30/05/2026 per i progetti nuovi, e **dal 30/10/2026 per tutti i progetti esistenti**, le nuove tabelle in `public` non ricevono più `GRANT` automatici ad `anon`, `authenticated` e `service_role`. Le tabelle esistenti mantengono i grant.
- La richiesta non autorizzata risponde con errore PostgREST `42501 permission denied`.
- `pg_graphql` non è più abilitato di default dal 18/05/2026.
- Fonte: https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically

**Impatto su Bastione.**
- Oggi 401/403 vengono letti come "RLS protegge" (`module.py:575-629`). Dopo il 30/10 una tabella può essere irraggiungibile per **mancanza di grant** anche con **RLS disabilitata**: il posture check direbbe "RLS ok" per il motivo sbagliato. Basta un `GRANT` futuro per esporla.
- Il remediation SQL di `RLS_DISABLED` non include i `GRANT` espliciti che ora servono.
- Con matrice oracolo `anon_select=true` su una tabella nuova senza grant, l'app si rompe e Bastione deve spiegare perché.

**Cosa fare.**
1. Distinguere nel finding e nel posture check il **motivo** del blocco: `42501` (grant assente) vs risultato vuoto o 401 da RLS.
2. Aggiornare i FixBuilder e i playbook RLS con il pattern `grant …` + `enable row level security` + policy nella stessa migrazione, come raccomanda Supabase.
3. Con il token autorizzativo (Management API, vedi §4.4), leggere grant e stato RLS reali invece di dedurli.

### 2.3 Difetti latenti nelle corsie M4 (prima della validazione live) 🔴

Tutti verificati sul codice:

| # | Difetto | Dove | Effetto |
|---|---|---|---|
| a | `zap_active` riceve `session_headers` ed `endpoints` ma **non li usa** | `bastione/modules/zap_active/module.py:101-150` | Lo scan "autenticato" è in realtà anonimo. |
| b | `zap_active` avvia `ascan/action/scan` e **legge subito** `core/view/alerts`, senza polling di `ascan/view/status` | stesso file, righe 138-142 | Risultati quasi vuoti: falso "tutto ok". |
| c | `idor` passa solo `sess.headers`, mai `sess.cookies` | `bastione/modules/idor/module.py:99-104` | Con sessioni a cookie (es. `@supabase/ssr` su Next.js) le richieste partono **non autenticate**, quindi l'IDOR non viene rilevato. |
| d | `server_exposure` controlla 7 path fissi e i `.map` solo degli script di `/` | `modules/server_exposure/` | Mancano `.git/HEAD`, `.env.local`/`.env.production`, backup, `/@vite/client`, Swagger/GraphiQL, endpoint Next.js. |

Senza questi fix la validazione live di M4 rischia di "passare" su un'app vulnerabile.

### 2.4 Il cap di severità di nuclei esclude proprio le CVE critiche 🟠

**Il problema.**
- `bastione/modules/nuclei/module.py:93-94` combina due filtri: `-exclude-tags intrusive,dos,fuzz,…`, che è giusto e protegge il target, e `-severity info,low,medium`.
- Il secondo **esclude tutti i template di rilevamento high/critical**, compresi quelli puramente passivi o di version-check: CVE-2025-29927 (bypass del middleware Next.js), React2Shell (CVE-2025-55182, CVSS 10, in KEV), esposizione del dev server Vite, takeover.
- La pericolosità di un template sta nei suoi **tag**, non nella **severità** del bug che rileva.

**Cosa fare.**
1. Togliere il cap di severità e affidarsi all'esclusione per tag.
2. Aggiungere una allowlist di template curati per lo stack (Next/React/Vite/Supabase/takeovers).
3. Fissare la versione minima di nuclei ≥ v3.10.0 (CVE-2026-76802/76805 sulla modalità DAST di nuclei stesso **[NV]**).

### 2.5 Supply chain di Bastione stesso 🟠

**Trivy compromesso (19–23/03/2026, TeamPCP, CVE-2026-33634, in KEV dal 26/03).**
- Binario malevolo v0.69.4; immagini Docker 0.69.5 e 0.69.6.
- 75–76 tag su 76–77 di `trivy-action` riscritti, più `setup-trivy`.
- Ultime versioni pulite: v0.69.3, trivy-action 0.35.0, setup-trivy 0.2.6.
- A valle è stato compromesso anche LiteLLM su PyPI (1.82.7/1.82.8).
- Fonti: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 · https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack · https://phoenix.security/trivy-supply-chain-attack-team-pcp/

**Esposizione di Bastione.**
- `modules/trivy` e gli altri wrapper fanno solo `shutil.which()`: nessun controllo di versione o firma.
- Nella S11 è stato usato `trivy.exe` v0.71.2, una release successiva all'incidente: **verificarne la provenienza** (checksum o firma cosign della release ufficiale).

**Workflow GitHub `.github/workflows/bastione.yml`.**
- `actions/checkout@v4`, `setup-python@v5`, `codeql-action/upload-sarif@v3` e `upload-artifact@v4` sono fissati per **tag**. Dopo tj-actions (2025) e trivy-action (2026) la pratica corrente è il pin per **SHA completo**. GitHub permette di imporlo con una policy (agosto 2025).
- Nota: dal 2026 `actions/checkout` ha nuove protezioni su `pull_request_target`, rese retroattive sui tag major. Chi fissa lo SHA deve aggiornarlo per ottenerle.
- `pip install -e .` senza lockfile né hash: le dipendenze hanno solo il limite inferiore `>=`.

**Cosa fare.**
1. `doctor` deve riportare la versione di ogni tool esterno e confrontarla con una **denylist di versioni compromesse** e una versione minima.
2. Opzionalmente, verificare checksum o firma.
3. Pin per SHA nel workflow.
4. Lockfile con hash (`uv lock` / `pip-compile --generate-hashes`).

### 2.6 Remediation scollegata dai controlli 🟡

- `build_fix_plan` riceve solo i `Finding`, ma gli header emettono solo `PostureCheck`. Così i FixBuilder `POSTURE_HSTS` e `MISSING_CSP` **non scattano mai**; inoltre il check reale si chiama `POSTURE_CSP`, non `MISSING_CSP`.
- 4 playbook su 9 riguardano rule_id che nessun codice emette: Stripe, storage, origin, signup.
- Nessuna regola M4 ha un playbook o un FixBuilder.
- I limiti onesti di §26 non compaiono nei report.

**Cosa fare.**
1. Il fix plan deve consumare anche i PostureCheck falliti.
2. Allineare i rule_id.
3. Scrivere i playbook per le regole M4 e per quelle nuove.
4. Rendere §26 nel report.

### 2.7 Next.js: rilascio di sicurezza straordinario annunciato per il 14/10/2026 🟡

- Annunciati 2 fix critici e 1 high, in dipendenze upstream.
- Le soglie di versione sicura di Next.js e React sono cambiate **più volte** tra dicembre 2025 e agosto 2026: React2Shell più i follow-up, poi i rilasci di maggio, luglio e agosto 2026. Le fonti raccolte riportano soglie diverse.
- Conclusione: **non hardcodare soglie**, interrogare OSV/GHSA (vedi M7).
- Fonte: https://nextjs.org/blog/upcoming-nextjs-security-update-october-2026 **[NV, da fonte unica]**

---

## 3 · Gap analysis per area

Legenda priorità: **P1** = alto impatto, basso costo, coerente con lo stack (JS/TS + Supabase + PaaS) · **P2** = importante · **P3** = situazionale o opzionale.
Livello di intrusione: RO = READ_ONLY · PR = PROBE · MU = MUTATING · **INT** = richiede il token autorizzativo o un accesso interno (API, repo, host).

### 3.1 Applicazione web: header e hardening lato browser

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **CSP strict** (nonce/hash + `strict-dynamic`, `object-src 'none'`, `base-uri`, `frame-ancestors`) | solo presenza | Parser CSP: flag su `unsafe-inline` senza nonce, `unsafe-eval`, `*`/`https:`/`data:` in `script-src`, direttive mancanti. **Nonce statico** (due GET, nonce uguale = bypass, frequente sugli SPA statici). | RO | P1 |
| **Trusted Types**: Baseline da febbraio 2026 (anche Firefox e Safari) | — | Check `require-trusted-types-for 'script'`. Con supabase-js la sessione sta in localStorage o in cookie leggibili da JS, quindi un XSS equivale al furto di sessione: TT e CSP diventano centrali. | RO | P2 |
| **HSTS** con `max-age` ≥ 1 anno, `includeSubDomains`, preload opzionale | solo presenza | Validare i valori; redirect HTTP→HTTPS sullo stesso host. | RO | P1 |
| **Integrity-Policy** (nuovo, disponibilità limitata) + **SRI** sugli script di terze parti | — | Inventario degli script third-party, SRI presente, **hash baseline + drift** (stile PCI DSS 4.0 6.4.3/11.6.1), domini script in NXDOMAIN o scaduti (lezione polyfill.io). | RO | P2 |
| COOP / CORP / Fetch Metadata (`Sec-Fetch-*`) | — | Presenza COOP/CORP; con sessione, replay di una POST con `Sec-Fetch-Site: cross-site` (un 403 indica la policy attiva). | RO/PR | P3 |
| Header deprecati: `X-XSS-Protection: 1` (dannoso), `Expect-CT`, `Feature-Policy`, HPKP | — | Segnalarli come INFO, **mai penalizzare** la loro assenza. | RO | P2 |
| `security.txt` (RFC 9116) con `Contact` ed `Expires` futuro | — | Check banale, utile anche come superficie di disclosure. | RO | P3 |
| `Clear-Site-Data` al logout | — | Con sessione: verificarlo sulla risposta di logout. | PR | P3 |

### 3.2 Autenticazione e sessione

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| Rate limit su login, **OTP, reset, signup** (429 + `Retry-After`) | solo login | Estendere `login_hardening` a reset, signup e magic-link/OTP con lo stesso cap prudente. | PR | P1 |
| Enumerazione account (status, **body**, **timing**) su login, signup e reset | solo status sul login | Confronto del body e dei tempi; endpoint di reset e signup. | PR | P2 |
| Cookie `__Host-`, HttpOnly, Secure, SameSite | flag base | Aggiungere il prefisso `__Host-` e la rotazione della sessione al login (fixation). | PR | P2 |
| **JWT**: `alg:none`, firma alterata, `exp` scaduto, `aud` errato devono dare 401; segreti HS256 deboli | — | Test di manomissione con il token di test (le legacy Supabase usano HS256 condiviso); crack offline con wordlist del token **proprio**. | PR | P2 |
| Logout invalida il refresh token | — | Replay del refresh token dopo il logout. | PR | P3 |
| **Redirect allow-list** OAuth/Supabase senza wildcard; open redirect su `?next=`/`redirect_to=`; Host header poisoning del link di reset | — | Probe sugli endpoint auth Supabase (`/auth/v1/authorize?redirect_to=`) e sui parametri di redirect. | PR | P2 |
| Signup aperto non voluto, sign-in anonimo abilitato | playbook `SIGNUP_OPEN` orfano | Check via `/auth/v1/settings` (pubblico) e, con il token, via Management API. | RO/INT | P1 |
| Passkey/WebAuthn, DBSC (Chrome) | — | Solo INFO o raccomandazione (non verificabile in modo utile). | — | P3 |

### 3.3 Controllo accessi e API (OWASP A01 2025, che include SSRF)

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| BOLA/IDOR cross-tenant | ✅ `idor` (difetto cookie, §2.3c) | Fix cookie; usare i path estratti dal bundle (oggi ignorati); kind `update`. | PR/MU | P1 |
| **Mass assignment / BOPLA**: PATCH con `role`, `is_admin`, `tenant_id` | — | Su canary di A: PATCH con colonne privilegiate; verificare che il campo non cambi. | MU | P1 |
| **RPC Supabase** (`/rest/v1/rpc/*`) e funzioni `SECURITY DEFINER` eseguibili da anon | le RPC sono solo contate | Invocare in sola lettura le RPC senza argomenti o idempotenti dichiarate nella matrice oracolo; con il token, lint Advisor 0028/0029. | PR/INT | P1 |
| **GraphQL** (`/graphql/v1`): introspection, batching, alias brute-force | — | Query `__schema` con chiave publishable (lint 0026). | RO | P2 |
| **CORS** con `Origin: null` e varianti prefix/suffix | solo origin "evil" su `/` | Più varianti, anche sugli endpoint API e non solo su `/`. | RO | P2 |
| **Autorizzazione solo nel middleware** (Next.js) | — | Chiamare direttamente API routes e Server Actions senza sessione; header CVE-2025-29927 `x-middleware-subrequest`. | PR | P1 |
| **SSRF** (`/_next/image?url=`, webhook, link preview) | — | Solo verso un listener OOB **di proprietà**, staging. | MU | P3 |
| **Web cache deception**: `/account/x.css`, delimitatori `;` `%23`, `CF-Cache-Status` / `X-Vercel-Cache` | — | Con sessione: GET autenticata con suffisso statico, poi GET anonima; un HIT con dati privati è CRITICAL. | PR | P2 |
| Request smuggling ("HTTP/1.1 must die", 2025) | — | **Non** attivo su PaaS (impatta altri utenti); solo per origin self-hosted, in modalità discrepancy-only. | — | P3 |
| Errori verbosi / fail-open (nuova **A10:2025**) | `VERBOSE_ERROR_LEAK` escluso dall'MVP | Reintrodurlo: input malformati → stack trace, 500, dettagli di Postgres o PostgREST. | PR | P2 |

### 3.4 CVE dei framework rilevabili dall'esterno

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **Fingerprint di versione**: Next.js (`window.next.version`, chunk, `x-powered-by`), React, Vite | assente (solo whatweb) | Recon nativo dello stack JS e delle versioni, poi **matching OSV/GHSA**, con priorità a KEV ed EPSS. | RO | P1 |
| **React2Shell** CVE-2025-55182 (CVSS 10, KEV): **safe-check** non esecutivo (pattern `$1:a:a` → 500 `E{"digest"` `text/x-component`) | — | Implementare il safe-check di Assetnote (detection-only). | PR | P1 |
| Next.js 2026: advisory di maggio, luglio, agosto (RCE critiche) + rilascio del 14/10 | — | Coperto dal matching OSV, non da soglie hardcoded. | RO | P1 |
| **Dev server Vite esposto** (`/@vite/client`; `/.env?raw` CVE-2026-39364) | — | Probe `/@vite/client`: se risponde su un host pubblico è HIGH. | PR | P1 |
| **Librerie JS vulnerabili nel bundle** (stile retire.js) | — | Estrarre i pacchetti dai `sourcesContent` delle source map e dai banner, poi OSV. | RO | P2 |

### 3.5 Segreti

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| Formati da coprire: `sb_secret_`, `sk_live_`/`rk_live_`/`whsec_`, OpenAI `sk-proj-`/`sk-svcacct-`/`sk-admin-`, Anthropic `sk-ant-api03-`, Google `AIza`, `ghp_`/`github_pat_`, `npm_`, AWS `AKIA`, chiavi private, token bot Telegram/Discord | **solo** service_role JWT | Completare il catalogo §10.2 (un file per detector, drop-in) **con match per prefisso** (le lunghezze cambiano). | RO | P1 |
| **Google `AIza`**: chiavi "pubbliche" per Maps/Firebase che ottengono accesso a **Gemini** se nel progetto è abilitata la Generative Language API (Truffle Security, febbraio 2026) | — | Liveness read-only: `GET generativelanguage.googleapis.com/v1beta/models?key=…` → 200 = CRITICAL. | PR | P1 |
| **Variabili `NEXT_PUBLIC_`/`VITE_` con nomi da segreto** | — | Euristica sul bundle e, con il token, via API Vercel/Netlify. | RO/INT | P2 |
| Segreti in `sourcesContent` delle source map | parziale (solo detector service_role) | Si estende automaticamente con il catalogo. | RO | P1 |
| **Storia git** (Betterleaks, successore di gitleaks da marzo 2026; TruffleHog per la verifica) | trivy fs (INFO) | Corsia white-box: scan della history + file di config MCP e agent. | INT | P2 |
| GitHub secret scanning + push protection (gratis sui repo pubblici) | — | Con un token GitHub read-only: verificare che siano attivi e leggere gli alert aperti. | INT | P2 |

### 3.6 Supabase in profondità (oltre la RLS su tabelle)

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **Storage**: bucket pubblici e listing anonimo (lint 0025) | playbook orfano | `object/list` anonimo sui bucket trovati nel bundle. | RO | P1 |
| **Edge Functions** con `verify_jwt=false` o che usano `supabaseAdmin` senza filtro sul chiamante; verifica firma dei webhook Stripe | — | Invocazione anonima di `/functions/v1/<nome>` (nomi dal bundle); con il repo, grep di `config.toml`. | PR/INT | P1 |
| **Security Advisor** (lint 0002, 0010, 0011, 0013, 0015, 0023, 0024 `USING(true)`, 0028/0029) | non verificabile (§26) | **Con il token Management API**: importare i lint come Finding. Supera il limite onesto "SECURITY DEFINER non verificabile". | INT | P1 |
| **Firma JWT asimmetrica** (JWKS ES256) e revoca del segreto HS256 legacy | — | `GET /auth/v1/.well-known/jwks.json` (o `/auth/v1/jwks`): vuoto o solo HS256 → INFO "non migrato". | RO | P2 |
| **Realtime**: canali `private: true` + policy su `realtime.messages` | — | Con il token: elenco delle policy; esterno: join anonimo ai topic trovati nel bundle. | PR/INT | P3 |
| Grant automatici disattivati dal 30/10 (vedi §2.2) | — | Semantica 42501 + SQL aggiornati. | RO | P1 |

### 3.7 Piattaforme PaaS e cloud

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **Vercel**: incidente di aprile 2026 (env var **non marcate Sensitive** decifrate dall'attaccante); Deployment Protection su preview e deployment URL | — | Esterno: URL `*.vercel.app` di preview o deployment raggiungibili senza auth wall. Con il token API Vercel: env var non-sensitive con nomi da segreto, livello di protezione. | RO/INT | P1 |
| **Netlify** Secrets Controller | — | Con il token: env var senza `is_secret`. | INT | P3 |
| **Cloudflare origin bypass** (`curl --resolve` sull'IP di origine); Authenticated Origin Pulls | TODO | Implementare il check annunciato (playbook `ORIGIN_BYPASSABLE` già pronto): IP di origine dalla config, dalla storia DNS o da CT. | PR | P2 |
| **Firebase** rules aperte (`/.json`, Firestore list) | — | Se il recon trova una config Firebase: probe anonimo in sola lettura. | RO | P3 |
| Bucket S3/GCS nominati nel bundle | — | Tentativo di listing anonimo. | RO | P3 |

### 3.8 TLS / PKI

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| TLS 1.2/1.3 solo AEAD+PFS (Mozilla v5.8/v6) | **niente** (testssl mai invocato) | Wrapper testssl.sh (già previsto in `doctor`) oppure check nativo minimo con `ssl` stdlib. | RO | P1 |
| **Durata dei certificati in calo**: 200 giorni dal 15/03/2026, 100 dal 2027, 47 dal 2029; Let's Encrypt a 45 giorni (profilo tlsserver) e 64 giorni di default dal 2027 | — | **Scadenza del certificato** con alert sotto 1/3 della durata residua (posture plus drift). Un cron fisso a 60 giorni smetterà di funzionare. | RO | P1 |
| OCSP finito (Let's Encrypt ha spento i responder ad agosto 2025) | — | **Non** penalizzare l'assenza di OCSP stapling; Must-Staple va segnalato come legacy. | RO | P2 |
| Scambio chiavi post-quantum ibrido X25519MLKEM768 (Chrome, Firefox e Cloudflare di default) | — | Solo INFO o bonus (via testssl o OpenSSL ≥ 3.5). | RO | P3 |
| **CAA** (anche `accounturi`) e **DNSSEC**, ora validato dalle CA (SC-085, dal 15/03/2026: un DNSSEC rotto blocca l'emissione dei certificati) | — | Vedi §3.9. | RO | P2 |

### 3.9 DNS, email e perimetro (EASM-lite)

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **Subdomain takeover / dangling DNS** (CNAME verso Vercel, Netlify, Heroku o S3 deprovisionati) | — | Sottodomini da **Certificate Transparency** (crt.sh) + DNS; per ogni CNAME controllare NXDOMAIN e il fingerprint "not found" del provider; template nuclei `takeovers`. | RO | P1 |
| **Inventario della superficie nel tempo** | `surface` esiste ma **non è cablato nella pipeline** e non traccia i sottodomini | Cablarlo nella scan; sottodomini, certificati e IP nel diff (CTEM "discovery"). | RO | P1 |
| **SPF/DKIM/DMARC**: requisiti Gmail, Yahoo e Microsoft; DMARC diventato standard (RFC 9989-9991, maggio 2026), `pct` rimosso, `np` | — | Check DNS: DMARC `p=quarantine/reject` + `np=reject`, SPF senza `+all` e con ≤10 lookup, selettori DKIM comuni. Per i domini che **non inviano** email: `v=spf1 -all`, `p=reject`, null MX (anti-spoofing a costo zero). | RO | P1 |
| MTA-STS / TLS-RPT | — | Solo se il dominio riceve email. | RO | P3 |
| CT monitoring: certificati non richiesti | — | Diff degli issuer CT contro CAA (drift). | RO | P2 |

### 3.10 Server e host (se l'utente ha un VPS o self-hosting)

Oggi Bastione **non ha alcuna corsia host**. Lo stato dell'arte si divide in esterno (EXT) e interno (INT):

| Controllo | Tipo | Proposta | Prio |
|---|---|---|---|
| **Porte esposte** (TCP completo, UDP top, **IPv6**) contro allowlist dichiarata | EXT | Wrapper naabu/nmap **solo sugli IP risolti da hostname verificati** (ownership) e dichiarati nel TOML; diff contro baseline. | P1 (se c'è un VPS) |
| Servizi critici esposti: Docker API 2375, kubelet 10250, Redis, MongoDB (MongoBleed CVE-2025-14847), Postgres, Elasticsearch, **Ollama 11434**, Prometheus, Portainer/Grafana/Traefik/Supabase Studio | EXT | Probe banner/endpoint read-only (`/version`, `/api/tags`…). | P1 |
| **Docker che aggira UFW** con porte pubblicate su `0.0.0.0` | EXT+INT | Il port scan esterno lo rivela; con accesso: `docker inspect` (privileged, `docker.sock`, CapAdd). | P2 |
| **SSH**: solo chiavi, niente root via password, KEX post-quantum (OpenSSH 10.x) | EXT | Wrapper `ssh-audit` (banner, algoritmi, metodi di autenticazione offerti). | P2 |
| Patch KEV: kernel "Copy Fail" CVE-2026-31431, sudo CVE-2025-32463, runc 1.3.3, nginx 1.30.2 **[NV]** | INT | Corsia "host-audit" via SSH con chiave dedicata read-only: Lynis, `systemd-analyze security`, `sshd -T`, versioni dei pacchetti contro OSV/KEV. | P3 |
| Backup immutabili e test di restore (3-2-1-1-0) | INT | Solo checklist o playbook (per Supabase: `pg_dump` fuori piattaforma). | P3 |
| Windows Server (baseline Microsoft, LAPS, SMB signing, deprecazione NTLM) | INT | Fuori fuoco per progetti personali: solo playbook. | P3 |

### 3.11 Supply chain, repository e CI/CD (con token GitHub read-only)

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **Ondate npm 2025-26**: Shai-Hulud 1 e 2, axios (marzo 2026), TanStack (maggio 2026, **con provenance SLSA valida**), "ChainDrop" (agosto 2026, persistenza in `.vscode/tasks.json` e negli **hook SessionStart di `.claude/settings.json`**) | trivy vuln (CVE, non malware) | **Sweep IOC** del lockfile contro OSV `MAL-`; ricerca di hook sospetti in `.claude/settings.json`, `.vscode/tasks.json`, `.mcp.json`. Rilevante perché l'utente lavora con Claude Code. | INT | P1 |
| **Cooldown sulle release**: npm `min-release-age` (≥11.10), pnpm 11 `minimumReleaseAge` di default, Bun; script di install in allowlist (pnpm 11 `allowBuilds`) | — | Check di config: `.npmrc`, `pnpm-workspace.yaml`, `bunfig.toml`, Dependabot `cooldown`. | INT | P1 |
| **GitHub Actions**: pin per SHA, `permissions:` minimi, `pull_request_target`/`workflow_run` (regola di default **dal 2/11/2026** sui repo pubblici), template injection `${{ github.event.* }}`, cache poisoning, `id-token: write` | — | Wrapper **zizmor** + actionlint (un output vuoto di zizmor = errore del tool, non "pulito"). | INT | P1 |
| Impostazioni del repo via API: secret scanning, push protection, Dependabot, token di default read-only, policy di pin per SHA, immutable releases | — | Check via API GitHub con token fine-grained read-only. | INT | P2 |
| SCA del sorgente: OSV-Scanner v2, trivy **pinnato e verificato**, Opengrep (fork LGPL di Semgrep dopo il cambio di licenza) | trivy + semgrep | Aggiungere OSV-Scanner come secondo motore (indipendente da trivy); valutare Opengrep come alternativa a semgrep. | INT | P2 |
| npm publishing (se pubblichi pacchetti): trusted publishing OIDC, token granulari, 2FA WebAuthn | — | Solo se pertinente. | INT | P3 |

### 3.12 AI / LLM / MCP / agenti

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Liv. | Prio |
|---|---|---|---|---|
| **OWASP LLM Top 10 2026** (agosto 2026; Excessive Agency #3, Unbounded Consumption #6 come "cost asymmetry", nuova LLM08 Hidden Context Exposure) + **Agentic Top 10** (dicembre 2025) | — | Tassonomia per i finding AI (doppio tag 2025/2026). | — | P3 |
| **Chiavi AI nel frontend** (circa 3.000 siti con chiavi OpenAI nel JS, febbraio 2026) e LLMjacking | — | Coperto dal catalogo segreti (§3.5). | RO | P1 |
| **Denial of wallet** su endpoint AI ed Edge Functions: invocabili senza auth, senza 429, senza cap su `max_tokens` | — | Probe con **budget di spesa rigido**, classificato PR/MU, solo staging. | PR/MU | P2 |
| Output LLM renderizzato senza sanitizzazione (markdown-image exfiltration; `dangerouslySetInnerHTML`, `rehype-raw`) | — | Regole semgrep/opengrep custom + CSP `img-src`/`connect-src` restrittive. | INT/RO | P2 |
| **MCP**: server esposti con `tools/list` senza auth; CVE mcp-remote (≤0.1.15) e Inspector (<0.14.1); tool poisoning e rug pull | — | Inventario delle config MCP del repo, **hash delle descrizioni dei tool e drift** (si sposa con baseline §16), version gate; probe di auth sui server MCP self-hosted. | INT/PR | P2 |
| Red-teaming LLM in CI (promptfoo, MIT, acquisito da OpenAI a marzo 2026; garak) | — | Corsia opzionale promptfoo → SARIF, con un canary nel system prompt. | PR | P3 |
| **Sicurezza del bundle di remediation dato a Claude Code** (vedi §5) | bundle P8-redatto | Evidenze **non fidate** delimitate, strip di Unicode, bidi e ANSI, firma HMAC del bundle, guard sul perimetro del diff. | — | **P1** |

### 3.13 Gestione delle vulnerabilità e rumore

| Stato dell'arte 2026 | Bastione oggi | Gap / proposta | Prio |
|---|---|---|---|
| Prioritizzazione **KEV → EPSS v4 → SSVC (Vulnrichment) → CVSS 4.0**; esposizione su internet come moltiplicatore | severità statica | Arricchire i finding con CVE (trivy, nuclei, OSV) con `kev`, `epss`, `ssvc` → classi **Act / Attend / Track**. | P2 |
| Telegram solo per "Act" o per le regressioni; il resto in un **digest settimanale** | alert su NEW ≥ soglia o DRIFT | Aggiungere il digest e la classe Act. | P2 |
| **OpenVEX** per i rischi accettati, **riaperti automaticamente** se la CVE entra in KEV o l'EPSS sale | `--accept` / baseline | Accept con motivazione e scadenza; riapertura su KEV/EPSS. | P3 |
| **SARIF hygiene**: una `category` per modulo (da luglio 2025 GitHub rifiuta run multiple con lo stesso tool e categoria), `baselineState`, `security-severity` | SARIF 2.1.0 con fingerprint | Aggiungere `baselineState` (mappa NEW/KNOWN/FIXED) e `security-severity`; verificare le category. | P2 |

### 3.14 Privacy e compliance (UE/Italia)

| Stato dell'arte 2026 | Proposta | Prio |
|---|---|---|
| Tracker caricati **prima del consenso** (strumenti EDPS Website Evidence Collector ed EDPB Website Auditing Tool) | Visita headless senza interazione: cookie, storage e richieste a terze parti contro EasyPrivacy; percorso "rifiuta"; link a privacy e cookie policy; **drift delle terze parti**. | P2 (se le app hanno utenti UE) |
| **CRA**: obbligo di segnalazione delle vulnerabilità sfruttate dall'11/09/2026 per i "manufacturer"; i progetti personali non commerciali sono in genere fuori ambito | Solo per prodotti monetizzati: SBOM, security.txt, playbook 24h/72h. | P3 |
| NIS2 | Un solo sviluppatore è fuori ambito. | — |

### 3.15 Altri "sistemi" possibili nel portfolio

| Sistema | Stato dell'arte | Proposta | Prio |
|---|---|---|---|
| **WordPress** | Patchstack: 11.334 vulnerabilità nel 2025 (+42%), 91% nei plugin, sfruttamento di massa in ore | Modulo §13 già previsto: enumerazione dei plugin (HTML e `readme.txt`), `xmlrpc.php`, `/wp-json/wp/v2/users`, `?author=1`, `debug.log`, backup + feed delle vulnerabilità. | P3 (solo se esiste un sito WP) |
| **Mobile** (APK/IPA) | MASVS 2.1, MASTG v2 (2026), segreti hardcoded diffusi | Unpack, riuso del catalogo segreti, flag del manifest Android (`debuggable`, `allowBackup`, `usesCleartextTraffic`). | P3 |
| **Electron** | fuse, `contextIsolation`/`sandbox` | `@electron/fuses read` + grep di `webPreferences`. | P3 |
| **Bot Telegram/Discord** (incluso il bot di Bastione) | token raccolti dal codice | Detector dei token; webhook con `secret_token` **[NV]**. | P2 |
| **Estensioni browser** | furto dell'account sviluppatore, poi update malevolo | Lint del manifest MV3; versione nello store ≠ tag del repo. | P3 |

---

## 4 · Piano di aggiornamento proposto (milestone)

Coerente con il metodo del repo: una milestone per sessione, un dynamic workflow, builder → blind-review → fixer, test offline come ground truth, live gated. Ordine pensato per **valore/rischio**: prima ciò che rende Bastione cieco o fuorviante, poi l'ampliamento.

### M5: riallineamento 2026 (correttezza prima dell'ampiezza)

*Obiettivo: niente falsi negativi silenziosi. È prerequisito della validazione live di M4.*

1. **Chiavi nuove Supabase**:
   - estrazione di `sb_publishable_`;
   - detector `SECRET_SUPABASE_SECRET_KEY` (`sb_secret_`);
   - header `apikey`-only;
   - `SUPABASE_KEY_NOT_FOUND` esplicito;
   - custom domain (§2.1).
2. **Semantica 42501 e grant espliciti** nei finding, nei FixBuilder e nei playbook RLS (§2.2).
3. **Fix M4**:
   - `zap_active` con sessione (header e cookie via replacer o HTTP Sender di ZAP) e polling di `ascan/view/status`;
   - `idor` che invia i cookie;
   - path dal bundle (§2.3).
4. **Nuclei**: via il cap di severità, allowlist di template curati per lo stack, versione minima (§2.4).
5. **Catalogo segreti §10.2** completato con i prefissi 2026 (Stripe, OpenAI, Anthropic, Google AIza + liveness Gemini, GitHub, npm, AWS, chiavi private, bot token).
6. **Header: validazione dei valori** (parser CSP con nonce statico, HSTS `max-age`/`includeSubDomains`, header deprecati come INFO).
7. **Remediation ricollegata**: il fix plan consuma i PostureCheck, rule_id allineati, playbook per le regole M4, §26 nel report.
8. **Igiene della supply chain di Bastione**:
   - `doctor` con versioni e denylist (trivy 0.69.4–0.69.6);
   - action pinnate per SHA;
   - lockfile con hash.

### M6: perimetro esterno (EASM-lite), tutto READ_ONLY

1. **TLS**: wrapper testssl.sh (già in `doctor`) o check nativo; **scadenza dei certificati** contro il calendario 200/100/47 giorni; niente penalità per l'assenza di OCSP.
2. **DNS ed email**: SPF/DKIM/DMARC (RFC 9989), CAA, DNSSEC, null-sender per i domini che non inviano email.
3. **Sottodomini da CT + dangling CNAME/takeover**; deployment di preview Vercel/Netlify raggiungibili.
4. **`surface` cablato nella scan**, con sottodomini, certificati e IP nel diff.
5. **Cloudflare origin bypass** (TODO esistente + playbook già scritto).
6. **Ownership estesa** (vedi §6): una prova per ogni asset nuovo (sottodominio, IP).

### M7: framework e supply chain

1. **Fingerprint dello stack JS** (Next.js, React, Vite, versioni) e **matching OSV/GHSA + KEV/EPSS**, niente soglie hardcoded.
2. **Safe-check** non esecutivi: React2Shell, CVE-2025-29927, `/@vite/client`, endpoint dev e debug, Swagger/GraphiQL.
3. **Librerie vulnerabili nel bundle** (dalle source map) + **inventario degli script di terze parti** con SRI e drift degli hash.
4. **Corsia repo (INT, token GitHub read-only)**:
   - zizmor + actionlint;
   - OSV-Scanner con `MAL-`;
   - check di cooldown e script di install;
   - scan della history con Betterleaks/TruffleHog;
   - **sweep IOC** di `.claude/settings.json`, `.vscode/tasks.json`, `.mcp.json`;
   - impostazioni del repo via API.

### M8: Supabase e piattaforme dall'interno (corsia "autorizzata")

1. **Supabase Management API** (token personale read-only, via ENV, P8):
   - lint del Security Advisor importati come Finding;
   - grant e stato RLS reali;
   - impostazioni auth (signup aperto, sign-in anonimo, redirect allow-list, scadenza dei JWT);
   - stato delle chiavi legacy e della firma JWT;
   - bucket e policy di storage;
   - `verify_jwt` delle Edge Functions.
   - Trasforma due "limiti onesti" di §26 in controlli veri.
2. **Esterno**: storage listing, Edge Functions anonime, `/graphql/v1` introspection, JWKS.
3. **Vercel/Netlify API**: env var non-sensitive con nomi da segreto, livello di Deployment Protection.
4. **Mass assignment** e **RPC** nelle corsie autenticate.

### M9: AI, agenti e riduzione del rumore

1. **Bundle di remediation "agent-safe"** (§5): da anticipare in M5 se si usa già il bundle con Claude Code in autonomia.
2. **Prioritizzazione Act/Attend/Track** (KEV, EPSS, SSVC) + digest settimanale su Telegram; SARIF `baselineState` e `security-severity`.
3. **Inventario MCP con hash dei tool e drift**; version gate.
4. **Probe denial-of-wallet** con budget, solo staging; corsia promptfoo opzionale.
5. **Privacy**: tracker prima del consenso + drift delle terze parti.

### Opzionali (trigger-based, come M3)

- Modulo WordPress §13: solo se esiste un sito WP.
- Corsia host-audit via SSH (Lynis, ssh-audit, docker inspect): solo se c'è un VPS.
- Port scan naabu/nmap: solo su IP verificati.
- APK, Electron ed estensioni: solo se esistono nel portfolio.

---

## 5 · Il bundle di remediation è una superficie d'attacco

Bastione consegna a Claude Code dei documenti costruiti **anche da contenuto controllato dal target**: body, header, titoli, nomi di file, metadati dei pacchetti. Nel 2025-26 sono stati documentati diversi casi:

- prompt injection contro agenti di pentest attraverso le risposte HTTP (arXiv 2508.21669);
- issue avvelenate contro le GitHub Action di agenti, con il token npm esfiltrato (febbraio 2026);
- malware che invoca le CLI AI locali per cercare segreti (s1ngularity/Nx, agosto 2025);
- persistenza negli hook di `.claude/settings.json` (ChainDrop, agosto 2026).

Oggi il bundle è P8-redatto (bene per i segreti), ma **non tratta l'evidenza come input ostile**. Proposte:

1. Separare in modo netto le **istruzioni di Bastione** (template fissi) dalle **evidenze non fidate**, in blocchi delimitati con avviso esplicito "dati, non istruzioni".
2. Strip di zero-width, bidi e ANSI; troncamento; dove basta, hash o estratti al posto del body grezzo.
3. **Firma HMAC** di `fix-plan.json`, verificata da un hook di Claude Code prima dell'uso.
4. Profilo d'esecuzione dell'agente: sandbox, niente segreti di produzione, rete in allowlist, lettura negata di `.env` e `~/.ssh` ("Rule of Two": mai insieme dati privati, contenuto non fidato e comunicazione esterna).
5. **Guard sul perimetro del diff**: un fix RLS non deve toccare workflow, `.mcp.json`, `CLAUDE.md`, `.claude/settings.json` o dipendenze.
6. **`bastione verify` obbligatorio**: nessuna chiusura senza l'oracolo deterministico. Lo stesso principio vale per un eventuale triage via LLM, che resta **consultivo**: in letteratura la riduzione dei falsi positivi su codice reale è solo del 34% circa, con il rischio di sopprimere veri positivi.

---

## 6 · Il modello di autorizzazione (token) va esteso agli asset nuovi

Oggi l'ownership challenge (`bastione/gate.py`) prova il controllo di **un host web**: `/.well-known/bastione-ownership.txt` oppure TXT `_bastione.<host>`. Le corsie proposte toccano asset diversi, e P1 ("owned-only by code") richiede che la prova li copra:

| Asset nuovo | Prova di possesso proposta |
|---|---|
| Sottodomini scoperti da CT | Scansione **solo** se il sottodominio è dichiarato nel TOML **e** coperto da un TXT sull'apex o sul sottodominio stesso; i sottodomini scoperti ma non dichiarati vengono **solo inventariati** (DNS/CT sono pubblici), mai sondati. |
| IP per il port scan | Solo IP **risolti da hostname verificati** e dichiarati nel TOML; mai range. |
| Progetto Supabase, account Vercel/Netlify, repo GitHub | Il **token API stesso** è la prova: un token valido per quel progetto o repo dimostra l'accesso. Token **read-only e a scope minimo**, solo da ENV, redatti P8, mai nel TOML. Il gate verifica che il project ref o il repo del token coincida con quello del target. |
| Host via SSH (host-audit) | Chiave dedicata, utente non privilegiato, comandi in allowlist. |

Due rifiniture minori del challenge attuale:

- `verify_ownership` segue i redirect e accetta il token come **sottostringa** del body. Meglio un **match esatto della riga** e la **verifica che l'host finale sia lo stesso**, così un redirect verso un altro dominio non soddisfa la prova.
- Valutare un token con scadenza o rotazione.

---

## 7 · Cosa **non** fare (per restare Bastione)

- Non diventare una suite di pentest generalista: per XSS e SQLi generici restano ZAP e nuclei (P5, "colla sottile").
- Niente test attivi di request smuggling o cache poisoning su infrastrutture PaaS condivise: impattano altri tenant.
- Niente agenti AI di pentest autonomi (Shannon, Strix, ecc.) fuori da staging e senza un proxy di scope. Se mai, una corsia opzionale MUTATING con budget e scope enforced.
- Niente triage LLM che **chiude** finding: solo ranking o spiegazione; il verdetto resta all'oracolo deterministico.
- Niente penalità per i controlli superati dalla storia: OCSP stapling, `X-XSS-Protection`, Expect-CT.

---

## 8 · Fonti principali

**Verificate direttamente in questa analisi**
- Supabase, fine dei grant automatici: https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically
- Supabase API keys: https://supabase.com/docs/guides/api/api-keys
- Trivy/TeamPCP: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 · https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack · https://phoenix.security/trivy-supply-chain-attack-team-pcp/ · https://ncsc.gov.ie/pdfs/TeamPCP_Supply-Chain_Attack.pdf

**Standard**
- OWASP Top 10:2025: https://top10.owasp.org/2025
- ASVS 5.0: https://owasp.org/www-project-application-security-verification-standard/
- API Security Top 10 (2023, ancora corrente): https://api-security.owasp.org/
- RFC 9700 (OAuth Security BCP): https://www.rfc-editor.org/rfc/rfc9700

**Browser**
- Strict CSP: https://web.dev/articles/strict-csp
- Trusted Types Baseline: https://web.dev/blog/baseline-digest-feb-2026
- Integrity-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
- Fetch Metadata: https://web.dev/articles/fetch-metadata

**Framework**
- React2Shell: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- Safe-check di Assetnote: https://github.com/assetnote/react2shell-scanner
- CVE-2025-29927: https://www.offsec.com/blog/cve-2025-29927
- Next.js, luglio 2026: https://nextjs.org/blog/july-2026-security-release
- Vite CVE-2026-39364: https://advisories.gitlab.com/npm/vite/CVE-2026-39364/

**PortSwigger**
- Top 10 tecniche 2025: https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- HTTP/1.1 must die: https://portswigger.net/research/http1-must-die

**TLS e DNS**
- Let's Encrypt, da 90 a 45 giorni: https://letsencrypt.org/2025/12/02/from-90-to-45
- Let's Encrypt, fine di OCSP: https://letsencrypt.org/2024/12/05/ending-ocsp
- DMARC RFC 9989: https://www.rfc-editor.org/rfc/rfc9989.html
- HSTS preload: https://hstspreload.org/

**Infrastruttura**
- Release notes OpenSSH: https://www.openssh.org/releasenotes.html
- Ritiro di ingress-nginx: https://kubernetes.dev/blog/2025/11/12/ingress-nginx-retirement
- MongoBleed: https://unit42.paloaltonetworks.com/mongobleed-cve-2025-14847/
- Ollama esposti: https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama

**Supply chain e CI**
- Shai-Hulud: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- axios: https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager
- ChainDrop: https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/
- pnpm 11: https://pnpm.io/blog/releases/11.0
- Token npm: https://github.blog/changelog/2025-09-29-strengthening-npm-security-important-changes-to-authentication-and-token-management/
- Policy di pin per SHA: https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/
- Protezioni sull'esecuzione dei workflow: https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/
- zizmor: https://blog.trailofbits.com/2026/05/22/we-hardened-zizmors-github-actions-static-analyzer/

**Piattaforme**
- Incidente Vercel di aprile 2026: https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
- Chiavi Google e Gemini: https://thehackernews.com/2026/02/thousands-of-public-google-cloud-api.html
- Security Advisor di Supabase: https://supabase.com/docs/guides/database/database-advisors

**AI e agenti**
- OWASP LLM 2026: https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new
- Lethal trifecta: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- Injection contro agenti di pentest: https://arxiv.org/abs/2508.21669
- Affidabilità del triage via LLM: https://arxiv.org/abs/2601.22952v1
- MCP 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/changelog

**Gestione delle vulnerabilità**
- EPSS v4: https://research.empiricalsecurity.com/research/introducing-epss-version-4
- Vulnrichment (SSVC): https://github.com/cisagov/vulnrichment
- SARIF, una category per run: https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/

**Non verificati o con fonti discordanti** (da ricontrollare prima di implementare):
- le soglie esatte di versione sicura Next.js/React (le fonti divergono, quindi meglio usare OSV);
- CVE-2026-75604 e il contenuto del rilascio Next.js del 14/10;
- le CVE nginx 2026;
- le CVE kernel di agosto e settembre 2026;
- i benchmark di Shannon;
- l'output SARIF nativo di promptfoo;
- il comportamento di `Authorization: Bearer sb_publishable_…` su PostgREST;
- lo stato GA di Realtime Authorization.
