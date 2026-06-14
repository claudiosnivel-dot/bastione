### Playbook — {{ title }}

**Cosa significa.** La **registrazione self-service** è aperta su `{{ target }}`: chiunque può creare un account tramite l'endpoint di sign-up di Supabase Auth (`/auth/v1/signup`) senza invito né restrizioni.

**Perché è pericoloso.** Se l'app non è pensata per registrazioni pubbliche, un sign-up aperto consente abuso: creazione massiva di account, spam, accesso ad aree autenticate, consumo di quote. Combinato con RLS deboli, un account auto-creato può vedere dati altrui. Severità: **{{ severity }}**.

**Come ripararlo (Supabase Auth), passo-passo:**
1. Dashboard Supabase → **Authentication → Providers / Sign In / Up** → **disabilita "Allow new users to sign up"** se la piattaforma è a inviti/chiusa.
2. Se servono nuovi utenti solo su invito: usa il flusso **Invite** (Authentication → Users → *Invite*) o crea gli account via Admin API server-side.
3. Se la registrazione deve restare aperta, mitiga l'abuso: **conferma email obbligatoria**, CAPTCHA (hCaptcha/Turnstile in Auth settings), rate-limit, e domini email consentiti.
4. Ricontrolla le policy RLS: un utente registrato non deve poter leggere dati di altri (vedi playbook `RLS_DISABLED`).

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SIGNUP_OPEN` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
