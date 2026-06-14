### Playbook — {{ title }}

**Cosa significa.** Manca l'header **HSTS** (`Strict-Transport-Security`): il browser non riceve l'istruzione di usare **solo HTTPS** per le visite future verso `{{ target }}`.

**Perché è pericoloso.** Senza HSTS un attaccante in posizione di rete può tentare un downgrade a HTTP (SSL-strip) sulla prima richiesta o su link `http://`, intercettando cookie e credenziali. HSTS chiude questa finestra. Severità (se fallito): **{{ severity }}**.

**Come ripararlo, passo-passo:**
- **Cloudflare:** Dashboard → **SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS)** → abilita con `max-age` ≥ 6 mesi, `includeSubDomains` e (quando sei certo) `preload`.
- **Header/origin** (`_headers` di Pages/Netlify o middleware):
  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```
- Verifica prima che **tutti** i sottodomini siano già su HTTPS prima di attivare `includeSubDomains`/`preload`, altrimenti li rendi irraggiungibili.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il check `POSTURE_HSTS` deve tornare **passed** (e il finding/drift correlato a **FIXED**).

<sub>Dettaglio rilevato: `{{ evidence }}`</sub>
