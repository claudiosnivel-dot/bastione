{# Questo playbook serve TRE rule_id (remediation_ref condiviso): RPC_ANON_INVOCABLE, RPC_ANON_WRITE_CAPABLE, RPC_NOT_VERIFIABLE. `rule_id` del context dice quale. `table` = ultimo segmento dell'endpoint: per /rest/v1/rpc/<fn> è il NOME DELLA FUNZIONE; viene dal bundle del target, quindi entra nello SQL solo se è un identificatore (altrimenti resta il segnaposto <fn>) e va quotato se ha maiuscole. #}
{% set fn = table if table and table.isidentifier() else "<fn>" %}
{% set fnq = fn if fn == fn.lower() else '"' ~ fn ~ '"' %}
### Playbook — {{ title }}

{% if rule_id == "RPC_ANON_WRITE_CAPABLE" %}
**Cosa significa.** La funzione RPC (`{{ location.endpoint or "/rest/v1/rpc/<fn>" }}`) è eseguibile con la chiave pubblica (anon) e, invocata in GET, ha **tentato una scrittura**: PostgREST l'ha bloccata perché le chiamate GET girano in una transazione `READ ONLY` (HTTP 405 / SQLSTATE 25006). Bastione non ha scritto nulla, ma una chiamata POST con la stessa chiave potrebbe modificare davvero i dati. L'esito è **TENTATIVE**: dedotto dal blocco, non da una scrittura riuscita.
{% elif rule_id == "RPC_NOT_VERIFIABLE" %}
**Cosa significa.** Bastione **non ha potuto verificare** la funzione RPC (`{{ location.endpoint or "/rest/v1/rpc/<fn>" }}`): il nome rientra tra quelli a possibile effetto esterno (invio di email, pagamenti, webhook, scritture: queste funzioni **non vengono mai invocate**, nemmeno in GET) oppure la chiamata non ha avuto risposta. È un limite di verifica dichiarato, **non** un'assoluzione: non sappiamo se l'anon possa eseguirla.
{% else %}
**Cosa significa.** La funzione RPC (`{{ location.endpoint or "/rest/v1/rpc/<fn>" }}`) è **eseguibile con la chiave pubblica (anon)**: una chiamata in GET con la sola chiave del bundle risponde 200, ma la funzione non è dichiarata pubblica nella matrice delle attese di Bastione. Può essere voluto (es. un listino pubblico) o una dimenticanza: l'esito è **TENTATIVE** finché non lo dichiari.
{% endif %}

**Perché è pericoloso.** Una funzione eseguibile dall'anon è una porta sul database che non passa dalle policy delle tabelle: se è `SECURITY DEFINER` gira con i permessi del proprietario e **scavalca la RLS**; se scrive, o ha effetti esterni (email, pagamenti, webhook), può essere chiamata da chiunque abbia la chiave pubblica, anche in massa. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. Decidi se la funzione deve essere pubblica. Senza invocarla, controlla chi può eseguirla (`<args>` = i tipi degli argomenti, es. `text, integer`):
   ```sql
   SELECT has_function_privilege('anon', 'public.{{ fnq }}(<args>)', 'EXECUTE');
   ```
   Per ricavare la firma esatta:
   ```sql
   SELECT oid::regprocedure FROM pg_proc
    WHERE proname = '{{ fn }}' AND pronamespace = 'public'::regnamespace;
   ```
2. Se **non** deve essere pubblica, revoca l'esecuzione. Postgres concede `EXECUTE` a `PUBLIC` di default e `anon` lo eredita: va revocato da `PUBLIC` **e** da `anon`:
   ```sql
   REVOKE EXECUTE ON FUNCTION public.{{ fnq }}(<args>) FROM PUBLIC, anon;
   -- se serve agli utenti loggati, riconcedila in modo esplicito:
   GRANT EXECUTE ON FUNCTION public.{{ fnq }}(<args>) TO authenticated;
   ```
3. Se **deve** restare pubblica, dichiaralo: l'attesa esplicita chiude il finding e fa emergere una violazione futura. Assicurati che sia `SECURITY INVOKER` e non restituisca dati personali.
   ```toml
   [[expectations.rpc]]
   name = "{{ fn }}"
   anon_execute = true
   ```
4. Applica su **staging** e verifica di nuovo.

{% if rule_id == "RPC_ANON_WRITE_CAPABLE" %}
**Funzione che scrive.** Concedila solo a `authenticated`, controlla `auth.uid()` **dentro** la funzione (mai fidarti di un `user_id` passato come argomento) e, se è `SECURITY DEFINER`, imposta `SET search_path = ''` e usa nomi qualificati.

{% elif rule_id == "RPC_NOT_VERIFIABLE" %}
**Funzione non verificabile.** Bastione non la invocherà mai: la prova è la query del passo 1 (`false` per l'anon = non eseguibile). Il finding INFO resta come promemoria finché il nome rientra tra quelli esclusi.

{% endif %}
**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
{% if rule_id == "RPC_NOT_VERIFIABLE" %}
Il finding INFO scompare solo se la funzione diventa verificabile; per le funzioni escluse per nome vale la prova manuale del passo 1.
{% else %}
Il finding deve passare a **FIXED** e il check `POSTURE_RPC_GATED_{{ fn }}` deve tornare **passed**.
{% endif %}

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
