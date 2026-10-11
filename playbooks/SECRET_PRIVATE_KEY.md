### Playbook — {{ title }}

**Cosa significa.** È stato trovato un **blocco di chiave privata** (intestazione PEM `BEGIN … PRIVATE KEY`){% if location.file %} in `{{ location.file }}`{% endif %}: una credenziale che non deve mai stare nel client né in un repository pubblico.

**Perché è pericoloso.** Con la chiave privata un attaccante può impersonare il tuo server (TLS), firmare token (per esempio JWT), decifrare dati o accedere a server e repository (SSH), a seconda dell'uso. La chiave è **compromessa** nel momento in cui è nel bundle: non si "ripulisce", va sostituita. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Identifica a cosa serve** (certificato TLS, chiave SSH, firma di token, service account cloud, PGP): lo dicono il tipo nell'intestazione e il file in cui è comparsa.
2. **Ruota subito (azione umana):** revoca la chiave presso chi la usa o l'ha emessa e rigenera la coppia.
   - TLS: revoca il certificato presso la CA e riemettilo con una coppia nuova.
   - SSH: rimuovi la chiave pubblica da `authorized_keys`, dalle deploy key e dagli account, poi genera una coppia nuova (`ssh-keygen -t ed25519`).
   - Firma di token (JWT): genera una nuova coppia, pubblica la nuova chiave pubblica e invalida i token firmati con la vecchia.
   - Service account cloud (file JSON): elimina la chiave dal service account e creane una nuova.
   - PGP: emetti il certificato di revoca e rigenera la coppia.

   Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la revochi.
3. Conserva la nuova chiave **solo lato server** (secret manager o env del backend); il client non la usa mai.
4. Rimuovi ogni riferimento dal frontend e dal repository; se era committata, ripulisci anche la history.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_PRIVATE_KEY` deve passare a **FIXED**: si chiude quando il blocco non compare più nel codice servito, quindi rifai il deploy dopo averlo rimosso.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
