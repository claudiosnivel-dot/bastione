### Playbook — {{ title }}

**Cosa significa.** Una **source map** (`{{ location.url or "<bundle>.js.map" }}`) è pubblicamente accessibile su `{{ target }}`: chiunque può ricostruire il **codice sorgente originale** del frontend (file, commenti, logica, rotte, endpoint interni e, a volte, segreti scritti nel codice).

**Perché è pericoloso.** Le source map annullano l'offuscamento della build: mostrano come funziona l'app, quali API chiama e dove cercare le falle, e rendono immediato trovare chiavi o endpoint dimenticati. Se nel sorgente compaiono segreti, Bastione li segnala a parte come `SECRET_*` (valore redatto): vanno considerati compromessi. Severità: **{{ severity }}** (CRITICAL quando la map contiene una `service_role`).

**Come ripararlo, passo-passo:**
1. **Non generare source map pubbliche in produzione:**
   - Vite: `build.sourcemap: false` in `vite.config` (è il default).
   - Next.js: `productionBrowserSourceMaps: false` in `next.config.js` (è il default).
   - webpack: `devtool: false` (oppure `"hidden-source-map"` se le carichi su un error tracker e non le pubblichi).
   - Create React App: `GENERATE_SOURCEMAP=false`.
2. Se ti servono per il debug (Sentry e simili), **caricale sul servizio durante la build e non pubblicarle**: cancella i `.map` dalla cartella di deploy prima del rilascio, ad esempio `find dist -name "*.map" -delete`.
3. **Rimuovi i `.map` già pubblicati**: rifai il deploy con la build pulita e, se c'è una CDN o una cache, svuotala (purge) così le vecchie map non restano servite.
4. **Difesa in profondità:** blocca i `.map` anche all'edge. Cloudflare: Security → WAF → Custom rules → azione *Block* con l'espressione `(http.request.uri.path.extension eq "map")`.
5. Se il sorgente conteneva segreti, **ruotali** (azione umana): ripulire le map non revoca nulla. Segui i playbook `SECRET_*` dei finding collegati.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SOURCEMAP_EXPOSED` deve passare a **FIXED** (la `.map` non risponde più 200) e il check `POSTURE_NO_SOURCEMAP` deve tornare **passed**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
