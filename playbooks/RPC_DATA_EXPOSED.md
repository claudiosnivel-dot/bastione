{# `table` = ultimo segmento dell'endpoint: per /rest/v1/rpc/<fn> è il NOME DELLA FUNZIONE. Il nome viene dal bundle del target: entra nello SQL solo se è un identificatore (altrimenti resta il segnaposto <fn>) e va quotato se ha maiuscole. #}
{% set fn = table if table and table.isidentifier() else "<fn>" %}
{% set fnq = fn if fn == fn.lower() else '"' ~ fn ~ '"' %}
### Playbook — {{ title }}

**Cosa significa.** Una funzione RPC (`{{ location.endpoint or "/rest/v1/rpc/<fn>" }}`) invocata in GET con la chiave pubblica restituisce dati riconducibili a **dati personali**: l'anon legge, tramite la funzione, ciò che la RLS dovrebbe proteggere.

**Perché è pericoloso.** La funzione scavalca di fatto la RLS delle tabelle sottostanti ed espone dati degli utenti a chiunque abbia la chiave pubblica (dump, GDPR). Severità: **{{ severity }}**.

**Come ripararlo, passo-passo:**
1. In Supabase, rivedi la funzione: se non deve essere pubblica, **revoca l'esecuzione all'anon**. Attenzione: Postgres concede `EXECUTE` a `PUBLIC` di default e `anon` lo eredita, quindi va revocato da `PUBLIC` **e** da `anon` (revocarlo solo da `anon` non chiude nulla):
   ```sql
   REVOKE EXECUTE ON FUNCTION public.{{ fnq }}(<args>) FROM PUBLIC, anon;
   -- se serve agli utenti loggati, riconcedila in modo esplicito:
   GRANT EXECUTE ON FUNCTION public.{{ fnq }}(<args>) TO authenticated;
   ```
   Per ricavare i tipi degli argomenti (`<args>`):
   ```sql
   SELECT oid::regprocedure FROM pg_proc
    WHERE proname = '{{ fn }}' AND pronamespace = 'public'::regnamespace;
   ```
2. Se deve restare pubblica, assicurati che interroghi **solo** dati non personali e che rispetti la RLS (funzione `SECURITY INVOKER`, non `SECURITY DEFINER`, salvo necessità; una `SECURITY DEFINER` non va esposta nello schema `public`).
3. Dichiara l'attesa in Bastione:
   ```toml
   [[expectations.rpc]]
   name = "{{ fn }}"
   anon_execute = false   # true solo se la funzione è davvero pubblica
   ```
4. Applica su **staging** e verifica che l'anon non riceva più dati personali.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RPC_DATA_EXPOSED` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
