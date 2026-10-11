### Playbook — {{ title }}

**Cosa significa.** La specifica della tua API (`{{ location.endpoint or "/openapi.json" }}`: OpenAPI/Swagger) è scaricabile da chiunque su `{{ target }}`: elenca endpoint, parametri, schemi dei dati e talvolta esempi.

**Perché è pericoloso.** Non è una falla in sé, ma una **mappa** pronta per un attaccante: endpoint interni o amministrativi, parametri sensibili, versioni deprecate. Riduce il lavoro di ricognizione e rende più facile trovare IDOR, mass assignment e autenticazioni mancanti. Severità: **{{ severity }}** (bassa: conta ciò che la specifica elenca). Se l'API è pubblica per scelta (partner, SDK), è normale che lo sia anche la sua documentazione.

**Come ripararlo, passo-passo:**
1. Decidi se la specifica deve essere pubblica. Se **sì** (API per terzi), nessuna correzione: assicurati che descriva solo endpoint pubblici e nulla di interno o amministrativo (usa una specifica separata per la parte pubblica).
2. Se **no**, non pubblicarla in produzione:
   - FastAPI: `FastAPI(openapi_url=None)` (spegne anche `/docs` e `/redoc`).
   - Spring (springdoc): `springdoc.api-docs.enabled=false` e `springdoc.swagger-ui.enabled=false`.
   - Express o NestJS: monta Swagger UI e la route JSON solo fuori produzione (`NODE_ENV` diverso da `production`).
3. Oppure proteggi il path con autenticazione o allow-list IP all'edge (per esempio Cloudflare Access, o basic auth sul path).
4. Rivedi anche gli endpoint che la specifica elencava: devono richiedere autenticazione e controllare i permessi come qualunque altro.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `API_SPEC_EXPOSED` deve passare a **FIXED** (la specifica non risponde più 200).

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
