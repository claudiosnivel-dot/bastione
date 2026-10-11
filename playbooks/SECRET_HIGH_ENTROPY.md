### Playbook — {{ title }}

**Cosa significa.** Bastione ha trovato una **stringa ad alta entropia**{% if location.file %} in `{{ location.file }}`{% endif %} che potrebbe essere un segreto (token, password, chiave di firma) ma non corrisponde a nessun formato noto. Il finding è di severità bassa e va sempre trattato come un **sospetto, non una certezza** (nel titolo: «possibile segreto»): serve un controllo umano.

**Perché è pericoloso.** Se è un vero segreto valgono le conseguenze di qualunque credenziale esposta: chi la legge dal bundle ottiene l'accesso che essa concede. Molte stringhe così sono però innocue (identificatori pubblici, hash di integrità, ID di build, chiavi pubbliche). Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. **Ritrova la stringa:** apri il file indicato e cerca il prefisso e il suffisso mostrati nell'evidence in fondo (il valore completo è redatto di proposito).
2. **Decidi cos'è:** serve ad autenticarsi o a firmare qualcosa (token API, password, segreto HMAC, chiave di servizio)? Oppure è un valore pubblico (ID di tracciamento, hash SRI, chiave pubblica, UUID, nonce)?
3. **Se è un segreto:** ruotalo presso l'emittente (azione umana) e spostalo **lato server**. Rimuoverlo dal codice NON basta: il valore esposto resta valido finché non lo revochi. Conservalo in un secret manager o nell'env del backend e, se era committato, ripulisci la history.
4. **Se è un falso positivo** (valore pubblico): non c'è nulla da ruotare. Accettalo come rumore noto nella baseline, così non ricompare come nuovo: `bastione baseline --target {{ target }} --accept <finding_id>` (il finding deve essere già in baseline; gli id si vedono con `bastione baseline --target {{ target }} --show`).

**Come verificare il fix.** Ruotato e ripulito, ri-esegui:
```
bastione verify --target {{ target }}
```
Per un segreto vero il finding `SECRET_HIGH_ENTROPY` deve passare a **FIXED**: si chiude quando la stringa non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa. Un falso positivo accettato resta in baseline come rumore noto.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
