### Playbook — {{ title }}

**Cosa significa.** Su `{{ target }}` risponde un **dev server** (`{{ location.endpoint or "/@vite/client" }}` è un endpoint tipico di Vite): l'app è servita con `npm run dev` invece che dalla build di produzione, oppure un ambiente di sviluppo è raggiungibile da Internet (porta aperta, tunnel, preview pubblica).

**Perché è pericoloso.** Un dev server serve il sorgente **non minificato** e con source map, il canale HMR (WebSocket) e, a seconda di versione e configurazione, endpoint che leggono file dal disco: sono noti casi di lettura di file arbitrari. Non è progettato per stare esposto e amplia molto la superficie d'attacco rispetto ai file statici della build. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Servi **solo la build di produzione**: `npm run build` e pubblica la cartella statica (`dist/`) con un hosting o una CDN (Vercel, Netlify, Cloudflare Pages) o con un web server. Mai `vite`, `npm run dev` o `next dev` in produzione.
2. Se è un ambiente di sviluppo raggiungibile da fuori (tunnel tipo ngrok o cloudflared, porta aperta, container avviato con `--host 0.0.0.0`), **chiudilo**, oppure proteggilo con autenticazione e allow-list IP; non lasciare `server.host` aperto su interfacce pubbliche.
3. Controlla che il deploy non lanci lo script `dev`: verifica il comando di avvio (`start`, `CMD` del Dockerfile, Procfile, *Start Command* della piattaforma).
4. Se è rimasto esposto a lungo, considera i sorgenti e i file che il server poteva servire (`.env`, configurazioni) come letti da terzi: **ruota le chiavi** che contenevano.
5. Aggiorna il dev server (Vite e simili) all'ultima versione: le vulnerabilità note di lettura file sono corrette nelle release recenti.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `DEV_SERVER_EXPOSED` deve passare a **FIXED** (l'endpoint del dev server non risponde più 200).

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
