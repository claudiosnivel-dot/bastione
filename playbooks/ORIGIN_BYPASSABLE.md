### Playbook — {{ title }}

**Cosa significa.** L'origine reale dell'app{% if location.url %} (`{{ location.url }}`){% endif %} è **raggiungibile direttamente**, scavalcando Cloudflare: il WAF, il rate-limiting e le regole di edge proteggono solo il traffico che passa dal proxy, ma l'IP/host di origine risponde anche senza.

**Perché è pericoloso.** Un attaccante che conosce l'origine bypassa ogni protezione edge: niente WAF, niente bot-mitigation, niente caching protettivo. Gli attacchi colpiscono il server nudo. Severità: **{{ severity }}**.

**Come ripararlo (Cloudflare + origin), passo-passo:**
1. **Blocca tutto il traffico non-Cloudflare all'origine.** Sul server/firewall consenti in ingresso **solo** i [range IP di Cloudflare](https://www.cloudflare.com/ips/) sulle porte 80/443; rifiuta il resto.
2. Abilita **Authenticated Origin Pulls** (mTLS): l'origine accetta solo connessioni che presentano il certificato client di Cloudflare.
3. Assicurati che i record DNS dell'host pubblico siano **proxied** (nuvola arancione), non "DNS only".
4. Se l'IP di origine è già trapelato, valuta di **cambiarlo** dopo aver applicato i filtri.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `ORIGIN_BYPASSABLE` deve passare a **FIXED** (l'origine non risponde più al di fuori di Cloudflare).

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
