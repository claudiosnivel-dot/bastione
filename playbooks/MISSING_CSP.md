### Playbook — {{ title }}

**Cosa significa.** Manca una **Content-Security-Policy** (`Content-Security-Policy`) sulle risposte di `{{ target }}`: il browser non ha una whitelist di sorgenti per script, stili e connessioni.

**Perché è pericoloso.** Senza CSP, una XSS (o uno script di terze parti compromesso) può eseguire codice arbitrario, esfiltrare token e dati. La CSP è la rete di sicurezza che limita il danno anche quando una XSS passa. Severità (se fallito): **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Parti da una policy restrittiva e allargala solo quanto serve:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
   ```
2. Aggiungi gli host di terze parti che usi davvero (es. Supabase, Stripe) a `connect-src`/`script-src`; evita `'unsafe-inline'` (preferisci nonce/hash).
3. Imposta l'header:
   - **Cloudflare:** Rules → **Transform Rules → Modify Response Header** → aggiungi `Content-Security-Policy`.
   - **`_headers`/middleware:** aggiungi la riga sopra alle risposte HTML.
4. Distribuisci prima in modalità report (`Content-Security-Policy-Report-Only`) per scoprire cosa romperesti, poi passa a enforcing.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il check `MISSING_CSP` deve tornare **passed** (finding/drift correlato a **FIXED**).

<sub>Dettaglio rilevato: `{{ evidence }}`</sub>
