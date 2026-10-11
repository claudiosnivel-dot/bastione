# Runbook: validazione live M4+M5 (spec M5–M9 §4.11)

> **Stato:** pronto, **non eseguito**. Serve l'ok esplicito di Claudio e un target owned in staging.
> **Preparato in:** Sessione 16 (2026-10-11), insieme alla prova generale offline `tests/test_rehearsal_live_m5.py`.
> **Guardrail:** owned-only, staging, `ownership_token` pubblicato, nessun dato reale. Produzione bloccata dal gate.

## 0. Cosa ha già dimostrato la prova generale offline

`tests/test_rehearsal_live_m5.py` esegue la stessa sceneggiatura contro un sito e un progetto Supabase **simulati in-process**. Passano davvero CLI, gate, recon, moduli, baseline, report e `verify`. Il server simulato si comporta come il gateway Supabase documentato (chiave nell'header `apikey`, root OpenAPI chiusa all'anon).

La prova ha trovato tre difetti, corretti in S16 prima di andare live:

1. **Chiave `sb_publishable_` troncata.** La regex del recon si fermava al primo `-` o `_`. Le chiavi reali ne contengono (formato: 22 caratteri base64url + `_` + 8 di checksum). Con la chiave troncata ogni richiesta riceveva 401 e Bastione dichiarava "protetti" bucket, RPC e tabelle. Stesso problema nel detector `sb_secret_`.
2. **`verify` dava FIXED a finding mai ricontrollati.** `verify` girava solo a READ_ONLY. I finding trovati a PROBE (storage, RPC, server_exposure…) sparivano dalla ri-scansione e risultavano FIXED. Ora un finding è FIXED solo se la run poteva ri-osservarlo:
   - il livello della run raggiunge quello con cui era stato trovato;
   - il suo modulo ha girato senza errori né `*_SKIPPED` / `*_NOT_FOUND`;
   - la run non ha dichiarato un limite (`*_NOT_VERIFIABLE`, `*_NOT_READABLE`, `*_NOT_ENUMERABLE`, test di scrittura saltato) su quello stesso controllo;
   - per i finding Supabase su tabelle, bucket, RPC e GraphQL serve una **prova positiva**: il posture check corrispondente (`POSTURE_RLS_<t>`, `POSTURE_RLS_WRITE_<t>`, `POSTURE_STORAGE_PRIVATE_<b>`, `POSTURE_RPC_GATED_<f>`, `POSTURE_GRAPHQL_INTROSPECTION`) deve essere passato nella stessa run. Un asset non più testato, o con esito non conclusivo, non si chiude.

   Altrimenti resta aperto come `not_reverified` (report, `verify`, sommario di `scan`, `scan-all`). `verify` accetta `--max-intrusion probe`. La baseline salva il livello e una chiave dell'endpoint (famiglia + hash: nessun nome di tabella o bucket in chiaro).
3. **RLS "attiva" su esiti non conclusivi.** Rete giù, 404, 429 o 5xx sulla GET anonima producevano la posture "RLS attiva". Ora producono l'INFO `RLS_NOT_VERIFIABLE`.

Cosa la prova **non** può dimostrare: che il Supabase reale risponda come quello simulato. Questo è lo scopo della validazione live.

## 1. Prerequisiti (azioni di Claudio)

- [ ] Ok esplicito alla validazione live su questo target.
- [ ] **Progetto Supabase nuovo**, usa-e-getta, creato dopo l'introduzione delle chiavi 2026. Nessun dato reale. Solo chiavi `sb_publishable_` / `sb_secret_` (chiavi legacy disattivate, se il pannello lo consente).
- [ ] **Sito sandbox** (es. Vercel, statico) collegato al progetto. Riutilizzabile `bozza/` (gitignored) aggiornando `app.js`.
- [ ] Token di ownership pubblicato su `https://<sito>/.well-known/bastione-ownership.txt` (una riga, solo il token).
- [ ] `targets/sandbox2026.local.toml` (gitignored) con `environment = "staging"` e `ownership = "owned"`.

## 2. Configurazione del sandbox (debolezze volute)

Tutte reversibili e confinate al progetto usa-e-getta.

**Tabelle** (Table editor o SQL):

- `ordini`: RLS attiva, nessuna policy per `anon` → atteso "protetta".
- `fatture`: creata **senza** GRANT ad `anon` (default dal 30/10/2026) → atteso "protetto ma fragile".

**Bucket `documenti`** (privato), con una policy che consente all'anon di elencare gli oggetti, e 1 file finto (es. `contratto_test.pdf` vuoto):

```sql
create policy "sandbox: anon puo elencare documenti"
  on storage.objects for select to anon
  using (bucket_id = 'documenti');
```

**RPC `lista_clienti`** che restituisce una riga finta con una colonna `email`, eseguibile da `anon`:

```sql
create table public.clienti_finti (id int primary key, email text, nome text);
insert into public.clienti_finti values (1, 'finto@example.invalid', 'Test');
create function public.lista_clienti() returns setof public.clienti_finti
  language sql stable security definer set search_path = public
  as $$ select * from public.clienti_finti $$;
grant execute on function public.lista_clienti() to anon;
```

**Auth:** signup pubblico **attivo** (default), sign-in anonimo **disattivo**.

**Bundle del sito** (`app.js`): URL del progetto + chiave publishable + riferimenti che il recon deve scoprire:

```js
const sb = supabase.createClient("https://<ref>.supabase.co", "sb_publishable_…");
sb.from('ordini').select('*');
sb.from('fatture').select('*');
sb.storage.from('documenti').list();
sb.rpc('lista_clienti');
```

## 3. Config del target

```toml
# targets/sandbox2026.local.toml (gitignored)
name = "sandbox2026"
base_url = "https://<sito-sandbox>"
environment = "staging"
ownership = "owned"
ownership_token = "<token pubblicato>"

[notify]
channel = "none"

# signup_open NON dichiarato apposta (§4.11: "signup aperto non dichiarato")
[expectations.auth]
anonymous_signin = false

[[expectations.bucket]]
name = "documenti"
anon_list = false
```

## 4. Esecuzione

| # | Comando | Esito atteso |
|---|---|---|
| 1 | `bastione scan --target sandbox2026` | READ_ONLY. `SUPABASE_SCHEMA_VIA_BUNDLE` INFO, `AUTH_EXPECTATION_UNDECLARED` (signup). Nessuna richiesta a storage/RPC/GraphQL. |
| 2 | `bastione scan --target sandbox2026 --max-intrusion probe --accept-baseline` | Ownership verificata. `STORAGE_PUBLIC_LISTABLE` (CRITICAL: nome che suggerisce un contratto), `RPC_DATA_EXPOSED` CRITICAL, signup non dichiarato INFO. Posture: `ordini` protetta, `fatture` protetto ma fragile. **Nessuna** `SUPABASE_LEGACY_KEYS_IN_USE`. Baseline salvata. |
| 3 | Correzioni (§5) | — |
| 4 | `bastione verify --target sandbox2026` | Storage e RPC compaiono come `not_reverified` (READ_ONLY non può ricontrollarli). Il signup chiuso risulta FIXED. |
| 5 | `bastione verify --target sandbox2026 --max-intrusion probe` | `STORAGE_PUBLIC_LISTABLE` e `RPC_DATA_EXPOSED` → **FIXED**. Nessun `not_reverified`. |

**Segnali d'allarme (fermarsi e analizzare):**

- `SUPABASE_KEY_NOT_FOUND`, oppure bucket e RPC "protetti" al passo 2 → la chiave non è stata estratta o viene rifiutata. Controllare `runs/<target>/<ts>/fingerprint.json`: `anon_key` deve essere la chiave **intera**.
- 401 su tutte le chiamate al progetto → verificare l'header. Bastione invia `apikey` e `Authorization: Bearer` con lo **stesso** valore. Supabase lo ammette per compatibilità; la guida ufficiale indica il solo `apikey`. Se il gateway lo rifiuta, è un difetto da correggere in `modules/supabase/module.py`.
- `RLS_NOT_VERIFIABLE` su `ordini`/`fatture` → il nome dal bundle non corrisponde o la Data API non espone lo schema.
- `SECRET_HIGH_ENTROPY` sulla chiave publishable → non dovrebbe più comparire (S16).

## 5. Correzioni da applicare al passo 3

```sql
drop policy "sandbox: anon puo elencare documenti" on storage.objects;
revoke execute on function public.lista_clienti() from anon, public;
```

Auth: disattivare il signup pubblico (oppure dichiararlo con `signup_open = true` nel TOML).

## 6. Corsie M4 (in coda, stessa sessione o successiva)

Richiedono un'app owned con login e **2 account di TEST** con credenziali via ENV (`[auth]` nel TOML, vedi `targets/_example.toml` e spec M4).

- `login_hardening` e `server_exposure`: PROBE.
- `idor` (scrittura su canary usa-e-getta) e `zap_active`: MUTATING, con `--i-own-this-its-staging`. Per ZAP serve il daemon locale (`BASTIONE_ZAP_*`).
- Per chiudere i loro finding: `verify --max-intrusion probe` (o `mutating` con la conferma). A un livello più basso restano `not_reverified`.

## 7. Chiusura

- [ ] Eliminare (o mettere in pausa) progetto Supabase e sito sandbox.
- [ ] Togliere il token dal well-known.
- [ ] Self-audit guardrail di PROMPT-02 §3.
- [ ] Riportare gli esiti in `BASTIONE-SESSION-STATE.md` (log §7, `build_steps_m5`, `next_session_goal`).

## Limiti noti (residui, non bloccanti)

- **Asset non più referenziato.** Per i finding Supabase con prova positiva resta `not_reverified` finché l'asset non torna a essere testato: dichiarare nel TOML (`[supabase] buckets/rpcs`, `[[expectations.*]]`) gli asset da tenere sotto controllo.
- **Corsie M4 senza prova positiva.** `IDOR_CROSS_TENANT_WRITE`, `login_hardening`, `server_exposure` e `zap_active` si chiudono ancora per assenza (con i vincoli di livello, modulo e limiti). Se la scrittura IDOR non risponde, il finding può risultare FIXED. Da estendere quando quelle corsie avranno un posture check per asset.

- **Canary e RLS_WRITE_OPEN.** Il canary scrive solo su tabelle lette dall'anon o dichiarate `anon_insert=true`. Se si chiude la lettura ma non la scrittura, la tabella esce dalla superficie del canary: il finding resta `not_reverified` (nessuna prova), ma la scrittura aperta non viene più ri-testata. La verifica definitiva è in M8 (GRANT e RLS dall'interno).
- **Tabella vuota.** Una tabella leggibile ma vuota risulta "protetta": la verifica black-box non distingue (limite §26 già noto).
- **Alta entropia sulla anon key legacy.** Il JWT legacy può produrre un `SECRET_HIGH_ENTROPY` LOW. Riduzione del rumore prevista in M9.
