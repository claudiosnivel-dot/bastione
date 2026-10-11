### Playbook — {{ title }}

**Cosa significa.** È stato trovato un **token npm**{% if location.file %} in `{{ location.file }}`{% endif %} (formato `npm_…`): una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con il token un attaccante può pubblicare versioni malevole dei tuoi pacchetti (attacco alla supply-chain, che colpisce chi li installa) e scaricare i pacchetti privati dell'account. Il token è **compromesso** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** npmjs.com → icona del profilo → **Access Tokens** → **elimina** il token esposto e creane uno nuovo *granular* con permessi minimi (sola lettura se basta), scadenza breve e, se possibile, restrizione per IP. Per la CI preferisci il *trusted publishing* (OIDC) ai token di lunga durata. Rimuoverlo dal codice NON basta: il token esposto resta valido finché non lo revochi.
2. Conserva il nuovo token **solo lato server** (env del backend o secret della CI); il client non lo usa mai.
3. Rimuovi ogni riferimento dal frontend e dai file inclusi nel deploy: il token finisce spesso in `.npmrc` o nelle variabili di build.
4. Se era committato, ripulisci anche la history.
5. Controlla le versioni pubblicate di recente dei tuoi pacchetti (`npm view <pacchetto> time`) e l'elenco dei token ancora attivi.

**Come verificare il fix.** Ruotato e ripulito, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_NPM` deve passare a **FIXED**: si chiude quando il token non compare più nel codice servito, quindi rifai il deploy dopo averlo rimosso.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
