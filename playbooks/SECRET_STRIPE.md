### Playbook — {{ title }}

**Cosa significa.** È stata individuata una **chiave segreta Stripe**{% if location.file %} in `{{ location.file }}`{% endif %} (tipicamente una `sk_live_…`/`sk_test_…` o un webhook secret). Le chiavi `sk_…` sono **segrete** e non devono mai stare nel client: solo le pubblicabili `pk_…` possono.

**Perché è pericoloso.** Con una secret key Stripe un attaccante può creare addebiti, emettere rimborsi, leggere dati di pagamento dei clienti e operare sull'account. È denaro reale e dati finanziari. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. **Ruota subito (azione umana):** Dashboard Stripe → **Developers → API keys** → **Roll** la secret key esposta (la vecchia viene revocata). Per i webhook, rigenera il signing secret.
2. Conserva la nuova `sk_…` **solo lato server** (env del backend); il client usa esclusivamente la `pk_…` pubblicabile.
3. Sposta server-side ogni chiamata che richiede la secret key (creazione PaymentIntent, ecc.).
4. Rimuovi la chiave dal sorgente e dalla history se era committata.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_STRIPE` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
