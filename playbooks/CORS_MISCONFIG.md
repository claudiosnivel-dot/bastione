### Playbook — {{ title }}

**Cosa significa.** `{{ target }}` risponde a una richiesta cross-origin con una `Origin` arbitraria (Bastione ne invia una fittizia) **riflettendola** in `Access-Control-Allow-Origin` — oppure usando `*` — **insieme a** `Access-Control-Allow-Credentials: true`. Qualunque sito web, anche malevolo, può quindi leggere le risposte che la tua app dà a un utente loggato.

**Perché è pericoloso.** Un sito malevolo visitato da un utente autenticato può inviare richieste alla tua app con i cookie di quell'utente e **leggere le risposte** (dati personali, token, contenuto delle API): è come rubare la sessione dei dati. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Sostituisci la riflessione con una **allowlist esatta** di origini note: confronta l'`Origin` con un elenco di valori interi (`https://app.example.com`), mai con `startswith`/`endswith`/`contains` o regex permissive (`https://app.example.com.evil.com` le supererebbe). Esempio (Express + `cors`):
   ```js
   const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
   app.use(cors({
     origin: (origin, cb) => cb(null, !origin || ALLOWED.has(origin)),
     credentials: true,
   }));
   ```
2. Non combinare mai `Access-Control-Allow-Origin: *` con le credenziali. Se l'API è davvero pubblica e **senza cookie**, usa `*` e non inviare `Access-Control-Allow-Credentials`.
3. Se la risposta dipende dall'`Origin`, aggiungi `Vary: Origin` (niente cache avvelenata) e non accettare `Origin: null`.
4. Limita metodi e header consentiti (`Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`) al minimo necessario e tieni `credentials` solo sugli endpoint che ne hanno bisogno.
5. Controlla anche CDN, proxy e regole di edge: una policy CORS può essere aggiunta lì oltre che nell'app.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `CORS_MISCONFIG` deve passare a **FIXED** e il check `POSTURE_CORS_SAFE` deve tornare **passed**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
