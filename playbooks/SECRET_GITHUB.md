### Playbook — {{ title }}

**Cosa significa.** È stato trovato un **token GitHub**{% if location.file %} in `{{ location.file }}`{% endif %} (personal access token classico `ghp_…`, fine-grained `github_pat_…` o token OAuth): una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con il token un attaccante accede ai repository (anche privati) nei limiti degli scope: può leggere il codice e i segreti che contiene, spingere commit o modificare i workflow di CI/CD (attacco alla supply-chain). Il token è **compromesso** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** GitHub → **Settings → Developer settings → Personal access tokens** → **elimina** il token esposto e creane uno nuovo *fine-grained* con scope minimo, repository specifici e scadenza breve. Se è un token OAuth o di una GitHub App, revocalo dalle impostazioni dell'app. Rimuoverlo dal codice NON basta: il token esposto resta valido finché non lo revochi.
2. Conserva il nuovo token **solo lato server** (env del backend o secret della CI); il client non lo usa mai.
3. Rimuovi ogni riferimento dal frontend; le chiamate all'API di GitHub passano da un endpoint server-side.
4. Se era committato, ripulisci anche la history.
5. Controlla il **Security log** (Settings → Security log) e i commit, i workflow e le deploy key recenti dei repository raggiungibili dal token.

**Come verificare il fix.** Ruotato e ripulito, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_GITHUB` deve passare a **FIXED**: si chiude quando il token non compare più nel codice servito, quindi rifai il deploy dopo averlo rimosso.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
