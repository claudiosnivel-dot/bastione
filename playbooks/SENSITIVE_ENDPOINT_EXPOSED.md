### Playbook — {{ title }}

**Cosa significa.** Il path `{{ location.endpoint or "<path>" }}` di `{{ target }}` risponde **200** con un contenuto non-HTML: un file di configurazione o un endpoint di debug/gestione (come `.env`, `.git/config`, `/api/debug`, `/server-status`, `/actuator`, `.aws/credentials`, `config.json`) è raggiungibile da chiunque, senza autenticazione. Bastione non conserva il contenuto: i segreti che riconosce al suo interno compaiono come finding `SECRET_*` a parte, con il valore redatto.

**Perché è pericoloso.** Questi file contengono tipicamente credenziali (chiavi API, password del database, token), la mappa interna dell'infrastruttura o dati di debug: basta una GET anonima per leggerli e ricavarne accesso diretto. Se è esposta la cartella `.git`, l'intero repository (storia compresa) è ricostruibile. Va trattato come se il contenuto fosse **già stato letto da terzi**. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo (l'ordine conta):**
1. **Ruota subito i segreti che il file conteneva (azione umana):** rimuovere il file non revoca nulla. Per ogni finding `SECRET_*` collegato a questo path segui il suo playbook di rotazione; con `.git` esposto, ruota ogni segreto che sia mai stato committato.
2. **Togli il file dalla pubblicazione.** I `.env*`, la cartella `.git`, i file di config e le chiavi cloud non devono finire nella directory servita (`public/`, `dist/`, `build/`, webroot): escludili con `.gitignore`/`.vercelignore`/`.dockerignore`, rifai la build e il deploy. Un file statico già pubblicato non si nasconde con una rewrite: va rimosso.
3. **Blocca il path anche a livello di server/edge** (difesa in profondità):
   - nginx: `location ~ /\.(?!well-known/) { deny all; }`
   - Apache: `RedirectMatch 404 /\.(?!well-known/)`
   - Cloudflare: Security → WAF → Custom rules → azione *Block* con l'espressione:
     ```
     (starts_with(http.request.uri.path, "/.env") or starts_with(http.request.uri.path, "/.git"))
     ```
4. **Endpoint applicativi** (`/api/debug`, `/server-status`, `/actuator`): disattivali in produzione oppure proteggili con autenticazione e allow-list IP. Esempi: Spring Boot Actuator espone solo `health` (`management.endpoints.web.exposure.include=health`); Apache `server-status` solo da localhost (`Require local`); le route di debug restano fuori dal build di produzione.
5. Se hai i log di accesso, controlla se il path è stato letto da altri prima del fix: in quel caso considera compromessi **tutti** i segreti che conteneva.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SENSITIVE_ENDPOINT_EXPOSED` deve passare a **FIXED** (il path non risponde più 200).

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
