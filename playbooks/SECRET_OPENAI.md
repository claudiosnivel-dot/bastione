### Playbook — {{ title }}

**Cosa significa.** È stata trovata una chiave segreta OpenAI{% if location.file %} in `{{ location.file }}`{% endif %}: una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con la chiave un attaccante consuma la tua quota, accede ai tuoi dati del provider e opera a tuo nome/spesa. La chiave è **compromessa** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** OpenAI dashboard → API keys → **revoca** la chiave esposta e **rigenerane** una nuova. Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la revochi.
2. Conserva la nuova chiave **solo lato server** (env del backend); il client non la usa mai.
3. Rimuovi ogni riferimento dal frontend; le chiamate passano da un endpoint server-side.
4. Se era committata, ripulisci anche la history.
5. Controlla Usage e Costs nel dashboard per consumi anomali nel periodo di esposizione e imposta un limite di spesa.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_OPENAI` deve passare a **FIXED**: si chiude quando la chiave non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
