### Playbook — {{ title }}

**Cosa significa.** I **sign-in anonimi** sono abilitati su `{{ target }}` (Supabase Auth: `external_anonymous_users_enabled`), ma la matrice delle attese di Bastione dichiara `anonymous_signin = false`: chiunque può ottenere una sessione, senza email né password, con una sola chiamata.

**Perché è pericoloso.** Un utente anonimo NON usa il ruolo `anon`: riceve un vero token con ruolo **`authenticated`** (e il claim `is_anonymous` = true). Ogni policy RLS scritta "per gli utenti loggati" (`TO authenticated`) vale quindi anche per i visitatori anonimi, che possono crearsi sessioni a volontà, aggirando i controlli pensati per gli utenti registrati e consumando quote. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Se **non** ti servono: Dashboard Supabase → **Authentication → Sign In / Providers** → disattiva **Allow anonymous sign-ins**. Self-hosted: `GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED=false`; Supabase CLI in locale: `enable_anonymous_sign_ins = false` nella sezione `[auth]` di `supabase/config.toml`.
2. Se invece ti servono (carrello ospite, prova senza registrazione), **dichiaralo** in Bastione, così il finding si chiude con una scelta esplicita:
   ```toml
   [expectations.auth]
   anonymous_signin = true
   ```
   e proteggi le tabelle dove gli anonimi non devono entrare con una policy **restrictive** sul claim `is_anonymous`:
   ```sql
   CREATE POLICY no_anonymous_users ON public.<tabella>
     AS RESTRICTIVE FOR ALL TO authenticated
     USING ((SELECT (auth.jwt() ->> 'is_anonymous')::boolean) IS FALSE);
   ```
3. Se li tieni, limita l'abuso: attiva il **CAPTCHA** (Turnstile o hCaptcha) in Authentication → Attack Protection e controlla i rate limit dei sign-in anonimi.
4. Applica su **staging**, verifica che l'app autenticata continui a funzionare, poi promuovi in produzione.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `ANON_SIGNIN_ENABLED` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
