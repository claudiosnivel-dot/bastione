### Playbook — {{ title }}

**Cosa significa.** È stata trovata una chiave segreta Anthropic{% if location.file %} in `{{ location.file }}`{% endif %}: una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con la chiave un attaccante consuma il tuo credito e la tua quota e opera sull'API a nome del tuo workspace, a tue spese. La chiave è **compromessa** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** Console Anthropic → API Keys → **disattiva/elimina** la chiave esposta e **creane** una nuova (idealmente in un workspace con un limite di spesa dedicato). Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la revochi.
2. Conserva la nuova chiave **solo lato server** (env del backend); il client non la usa mai.
3. Rimuovi ogni riferimento dal frontend; le chiamate passano da un endpoint server-side.
4. Se era committata, ripulisci anche la history.
5. Controlla Usage e Cost nella Console per consumi anomali nel periodo di esposizione.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_ANTHROPIC` deve passare a **FIXED**: si chiude quando la chiave non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
