### Playbook — {{ title }}

**Cosa significa.** L'endpoint `{{ location.endpoint or "<endpoint>" }}` restituisce a un **altro utente** (B), oppure a un visitatore **non autenticato**, i dati di una risorsa che appartiene a un altro tenant (A): l'isolamento tra tenant non è applicato lato server (Broken Access Control, OWASP A01). Bastione ha confrontato le risposte con due account di test **senza leggere né riportare i dati**: il finding contiene solo metodo, path e ruolo.

**Perché è pericoloso.** Chi conosce o indovina l'identificativo di una risorsa (spesso sequenziale, come `/ordini/1042`) legge i dati di altri clienti. È il difetto più comune e più sfruttato nelle API, con impatto diretto su riservatezza e GDPR (dati personali di terzi). Severità: **{{ severity }}**.

**Come ripararlo, passo-passo (lato server):**
1. Applica il controllo di appartenenza su **ogni** query: filtra per l'utente o il tenant **ricavato dalla sessione verificata** (`auth.uid()`, `user.id`, il `tenant_id` del token), mai da un parametro inviato dal client. L'`id` nell'URL identifica la risorsa, non autorizza l'accesso.
2. Se i dati stanno in Supabase/Postgres, porta il controllo nel database con la **RLS** per-utente: vale anche quando un endpoint dimentica il filtro.
   ```sql
   ALTER TABLE public.<tabella> ENABLE ROW LEVEL SECURITY;
   CREATE POLICY sel_own ON public.<tabella>
     FOR SELECT TO authenticated
     USING ((SELECT auth.uid()) = user_id);
   ```
   (`user_id` è la colonna proprietario; nei sistemi multi-tenant usa `tenant_id` e una tabella di appartenenza.)
3. Un endpoint che non è pubblico non deve rispondere 200 senza una sessione valida: 401 se non autenticato, 403 o 404 per le risorse altrui. Nessuna policy né `GRANT` per `anon` sulle tabelle sottostanti.
4. Usa identificativi non sequenziali (UUID) come difesa **aggiuntiva**, mai come unico controllo.
5. Se l'endpoint è davvero pubblico per scelta, dichiaralo nel TOML così Bastione non lo segnala più:
   ```toml
   [auth.suppression]
   public_endpoints = ["/api/<risorsa>*"]   # prefisso con * finale
   ```
6. Aggiungi un test automatico di isolamento: A crea una risorsa, B prova a leggerla e deve ottenere 403 o 404.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `IDOR_CROSS_TENANT_READ` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
