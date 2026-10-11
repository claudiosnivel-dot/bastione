### Playbook — {{ title }}

**Cosa significa.** È stata trovata una **secret key Supabase** (formato `sb_secret_…`){% if location.file %} in `{{ location.file }}`{% endif %}: l'equivalente moderno della `service_role`, una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** La secret key **bypassa completamente la RLS** e dà accesso amministrativo al progetto: chi la possiede legge e scrive qualunque tabella ignorando ogni policy, accede a Storage e gestisce gli utenti di Auth tramite l'Admin API. La chiave è **compromessa** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** Dashboard Supabase → **Project Settings → API Keys** → crea una nuova secret key, aggiorna il backend e poi **elimina/revoca** quella esposta. Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la revochi.
2. Conserva la nuova chiave **solo lato server** (env del backend o delle Edge Functions); nel client va soltanto la chiave pubblicabile (`sb_publishable_…`).
3. Rimuovi ogni riferimento dal frontend; le operazioni privilegiate passano da un endpoint server-side che custodisce la chiave.
4. Se era committata, ripulisci anche la history.
5. Controlla i log del progetto (Dashboard → Logs) per accessi anomali nel periodo di esposizione.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_SUPABASE_SECRET_KEY` deve passare a **FIXED**: si chiude quando la chiave non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
