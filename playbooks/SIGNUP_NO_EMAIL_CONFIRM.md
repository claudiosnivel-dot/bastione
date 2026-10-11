### Playbook — {{ title }}

**Cosa significa.** Supabase Auth di `{{ target }}` conferma automaticamente le registrazioni (`mailer_autoconfirm` attivo): chi si registra ottiene subito un account attivo, **senza dimostrare di possedere l'indirizzo email** indicato.

**Perché è pericoloso.** Chiunque può creare account con email altrui (o inesistenti): spoofing dell'identità, account squatting sull'indirizzo di una vittima, spam e consumo di quote, aggiramento di regole basate sul dominio email (es. "solo @azienda.it"). Le policy RLS e la logica che si fidano di `auth.jwt() ->> 'email'` diventano aggirabili. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Dashboard Supabase → **Authentication → Sign In / Providers → Email** → attiva **Confirm email** (cioè spegni l'autoconfirm). Self-hosted: `GOTRUE_MAILER_AUTOCONFIRM=false`; Supabase CLI in locale: `enable_confirmations = true` nella sezione `[auth.email]` di `supabase/config.toml`.
2. Configura un **SMTP personalizzato** nelle impostazioni Auth: il servizio email integrato è pensato per i test (limiti di invio molto bassi e destinatari ristretti), quindi la conferma non regge in produzione.
3. Gli account creati finora con l'autoconfirm risultano comunque "confermati" pur senza verifica della casella: se l'app si fida dell'email (policy RLS su `auth.jwt() ->> 'email'`, dominio aziendale, ownership), rivedi quelle regole e valuta una riverifica degli utenti sensibili.
4. Se alcuni flussi devono creare utenti già confermati (import, inviti), fallo **lato server** con l'Admin API (`email_confirm: true`), mai riattivando l'autoconfirm per tutti.
5. Applica su **staging** e prova registrazione e conferma end-to-end prima della produzione.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SIGNUP_NO_EMAIL_CONFIRM` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
