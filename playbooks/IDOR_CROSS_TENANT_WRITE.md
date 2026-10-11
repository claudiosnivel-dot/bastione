### Playbook — {{ title }}

{# Questo playbook serve DUE rule_id (remediation_ref condiviso): IDOR_CROSS_TENANT_WRITE e IDOR_CLEANUP_FAILED. `rule_id` del context dice quale. #}
{% if rule_id == "IDOR_CLEANUP_FAILED" %}
**Cosa significa.** Il probe di scrittura cross-tenant ha creato su `{{ location.endpoint or "<endpoint>" }}` una risorsa **canary** usa-e-getta (marker `bastione-idor-canary`, mai dati reali), ma la pulizia automatica **non è confermata**: ne resta una da cancellare **a mano**. L'evidence in fondo riporta path e id da rimuovere.

**Perché conta.** Il cleanup non confermato può dipendere da un errore transitorio, da un endpoint `DELETE` che non risponde come dichiarato in `[auth]`, oppure dalla stessa falla di autorizzazione: controlla l'esito prima di rilanciare il probe. Severità: **{{ severity }}**.

**Prima di tutto: rimuovi la canary.** Cancella la risorsa indicata nell'evidence (stessa operazione `DELETE` sul path e sull'id riportati) con un account che ne ha il diritto. Non contiene dati reali, ma non deve restare nel tuo sistema.
{% else %}
**Cosa significa.** Su `{{ location.endpoint or "<endpoint>" }}` un **altro utente** (B) ha potuto cancellare o modificare una risorsa creata da A: l'autorizzazione di scrittura non isola i tenant (Broken Access Control, OWASP A01). Bastione l'ha provato solo su una risorsa **canary** usa-e-getta creata dall'account di test (mai dati reali): la canary è stata cancellata proprio da B.

**Perché è pericoloso.** È il caso peggiore di IDOR: chiunque abbia un account può **distruggere o manomettere i dati di altri clienti** (cancellazioni, modifiche di prezzi, stati, proprietà), con danni diretti all'integrità dei dati e alla continuità del servizio. Severità: **{{ severity }}**.
{% endif %}

**Come ripararlo, passo-passo (lato server):**
1. Applica il controllo di proprietà in scrittura: ogni `UPDATE`/`DELETE` deve includere la proprietà nella condizione (`WHERE id = $1 AND owner_id = $2`, con `$2` = utente della sessione verificata), mai l'`owner_id` o lo `user_id` ricevuto nel body.
2. Se i dati stanno in Supabase/Postgres, porta il controllo nel database con la **RLS** di scrittura: vale anche quando un endpoint dimentica il controllo.
   ```sql
   CREATE POLICY ins_own ON public.<tabella>
     FOR INSERT TO authenticated
     WITH CHECK ((SELECT auth.uid()) = user_id);
   CREATE POLICY upd_own ON public.<tabella>
     FOR UPDATE TO authenticated
     USING ((SELECT auth.uid()) = user_id)
     WITH CHECK ((SELECT auth.uid()) = user_id);
   CREATE POLICY del_own ON public.<tabella>
     FOR DELETE TO authenticated
     USING ((SELECT auth.uid()) = user_id);
   ```
   (Il `WITH CHECK` sull'`UPDATE` impedisce di "regalare" una riga a un altro utente.)
3. Usa una whitelist dei campi aggiornabili: il client non deve poter impostare `user_id`, `tenant_id`, `role` o altri campi di proprietà (mass assignment).
4. Verifica **tutti** i verbi dello stesso endpoint (PUT, PATCH, POST, DELETE), non solo quello segnalato: 401 senza sessione, 403 o 404 per le risorse altrui.
5. Aggiungi un test automatico: A crea una risorsa, B prova a modificarla o cancellarla e deve fallire.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
{% if rule_id == "IDOR_CLEANUP_FAILED" %}
Il finding `IDOR_CLEANUP_FAILED` sparisce quando la pulizia automatica della canary torna a riuscire; il finding `IDOR_CROSS_TENANT_WRITE`, se presente, deve passare a **FIXED**.
{% else %}
Il finding `IDOR_CROSS_TENANT_WRITE` deve passare a **FIXED**.
{% endif %}

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
