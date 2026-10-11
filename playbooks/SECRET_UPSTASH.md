### Playbook — {{ title }}

**Cosa significa.** È stato trovato l'**URL REST di un database Upstash** (`https://<id>.upstash.io`){% if location.file %} in `{{ location.file }}`{% endif %}: quasi sempre accanto all'URL c'è anche il **token REST**, una credenziale che non deve mai stare nel client. Bastione riconosce l'URL e non verifica il token: trattalo come esposto.

**Perché è pericoloso.** Con URL e token REST un attaccante legge, scrive e cancella tutti i dati del database (cache, sessioni, code, contatori di rate-limit), senza altra autenticazione. Il token è **compromesso** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** Upstash Console → seleziona il database → **Details** → rigenera il REST token. Rimuoverlo dal codice NON basta: il token esposto resta valido finché non lo rigeneri.
2. Conserva il nuovo token **solo lato server** (env del backend); il client non lo usa mai. Se un client deve solo leggere, esiste un token **read-only** dedicato.
3. Rimuovi ogni riferimento dal frontend; le chiamate al database passano da un endpoint server-side.
4. Se era committato, ripulisci anche la history.
5. Il database può essere stato letto o modificato: valuta di invalidare le sessioni e le cache che conteneva.

**Come verificare il fix.** Ruotato e ripulito, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_UPSTASH` deve passare a **FIXED**: si chiude quando il token non compare più nel codice servito, quindi rifai il deploy dopo averlo rimosso.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
