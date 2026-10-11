### Playbook — {{ title }}

**Cosa significa.** L'endpoint GraphQL di Supabase (`{{ location.endpoint or "/graphql/v1" }}`, estensione `pg_graphql`) risponde a una query di **introspezione** inviata con la sola chiave pubblica: chiunque può scaricare lo schema GraphQL esposto (tabelle, colonne, relazioni, funzioni) senza autenticarsi.

**Perché è pericoloso.** L'introspezione non legge righe, ma consegna una mappa completa della superficie dati: nomi di tabelle e colonne, relazioni, mutazioni. Facilita la ricerca di tabelle dimenticate senza RLS e di funzioni esposte, e azzera il lavoro di ricognizione. La gravità reale dipende da ciò che c'è sotto: con la RLS corretta la mappa non apre alcun accesso. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Verifica se l'app usa GraphQL (cerca `graphql` nel codice del client). Se **non** lo usa, disabilita l'estensione: Dashboard Supabase → **Database → Extensions** → `pg_graphql` → disattiva (oppure, da SQL editor, `DROP EXTENSION IF EXISTS pg_graphql;`). L'endpoint smette di rispondere.
2. Se lo usa **solo da utenti loggati**, togli l'accesso all'anon alla funzione d'ingresso GraphQL e lascialo agli altri ruoli:
   ```sql
   REVOKE EXECUTE ON FUNCTION graphql_public.graphql FROM PUBLIC, anon;
   GRANT EXECUTE ON FUNCTION graphql_public.graphql TO authenticated, service_role;
   ```
   Se il comando segnala che il nome non è univoco, indica la firma completa dei parametri.
3. Se deve restare pubblico, **riduci ciò che l'anon vede**: lo schema GraphQL segue i privilegi Postgres del ruolo, quindi togli i `GRANT` dell'anon su tabelle e funzioni non necessarie (`REVOKE ALL ON TABLE public.<tabella> FROM anon;`) e tieni la **RLS attiva** su ogni tabella esposta: a proteggere i dati, anche a schema noto, è la RLS.
4. Applica su **staging**, verifica che l'app continui a funzionare, poi promuovi in produzione.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SUPABASE_GRAPHQL_INTROSPECTION` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
