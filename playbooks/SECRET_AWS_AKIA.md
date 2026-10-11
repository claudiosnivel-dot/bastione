### Playbook — {{ title }}

**Cosa significa.** È stata trovata una **access key AWS**{% if location.file %} in `{{ location.file }}`{% endif %} (ID che inizia con `AKIA` se permanente, con `ASIA` se temporanea): una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con una access key un attaccante opera con i permessi IAM dell'utente o del ruolo a cui appartiene: può leggere o cancellare bucket S3 e database, avviare risorse a pagamento (per esempio per il mining di criptovalute) e raggiungere altri segreti. I bot scansionano di continuo bundle e repository pubblici in cerca di chiavi AWS. Bastione non verifica se la chiave sia ancora attiva (nessuna chiamata verso AWS): trattala come attiva e **compromessa**. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** AWS Console → **IAM → Users → (utente) → Security credentials → Access keys** → *Make inactive* e poi *Delete*; creane una nuova con permessi minimi (least privilege). Per le credenziali temporanee (`ASIA`) usa *Revoke active sessions* sul ruolo. Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la disattivi.
2. Conserva la nuova chiave **solo lato server**, in un secret manager o nell'env del backend; meglio ancora usa ruoli IAM o OIDC al posto di chiavi di lunga durata. Il client non la usa mai.
3. Rimuovi ogni riferimento dal frontend; le chiamate ad AWS passano da un endpoint server-side.
4. Se era committata, ripulisci anche la history.
5. Controlla **CloudTrail** per l'uso della chiave esposta (filtra per l'access key ID) e verifica risorse o costi inattesi.

**Come verificare il fix.** Ruotata e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_AWS_AKIA` deve passare a **FIXED**: si chiude quando la chiave non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
