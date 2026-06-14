### Playbook — {{ title }}{% if table %} su `{{ table }}`{% endif %}

**Cosa significa.** La tabella{% if table %} `{{ table }}`{% endif %} (`{{ location.endpoint or "/rest/v1/<tabella>" }}`) accetta **scritture** (INSERT/UPDATE/DELETE) con la sola `anon` key: non esiste una policy che limiti chi può modificare i dati.

**Perché è pericoloso.** Un attaccante può inserire, alterare o cancellare record arbitrari (defacement, frode, distruzione dati) senza autenticarsi. È più grave della sola lettura aperta. Severità: **{{ severity }}**.

**Prima di tutto: `{{ table or "<tabella>" }}` è una TABELLA o una VISTA?** Una scrittura aperta su una **vista** ha una causa diversa da una su tabella base. Verificalo con:
```sql
SELECT relkind FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relname = '{{ table or "<tabella>" }}';
-- 'r' = tabella · 'v' = vista · 'm' = vista materializzata
```

**Caso A — è una TABELLA (`relkind = 'r'`), passo-passo:**
1. Dashboard Supabase → **Authentication → Policies** → tabella `{{ table or "<tabella>" }}`.
2. Verifica che RLS sia abilitata:
   ```sql
   ALTER TABLE public.{{ table or "<tabella>" }} ENABLE ROW LEVEL SECURITY;
   ```
3. Rimuovi qualsiasi policy permissiva `FOR ALL`/`FOR INSERT` con `WITH CHECK (true)` e sostituiscila con policy di scrittura legate all'utente:
   ```sql
   CREATE POLICY ins_own ON public.{{ table or "<tabella>" }}
     FOR INSERT WITH CHECK (auth.uid() = user_id);
   CREATE POLICY upd_own ON public.{{ table or "<tabella>" }}
     FOR UPDATE USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
   ```

**Caso B — è una VISTA (`relkind = 'v'`/`'m'`):** non si abilita RLS né si creano policy sulla view stessa (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` e `CREATE POLICY` non si applicano a una vista). Una vista *aggiornabile* propaga le scritture alle tabelle sottostanti col privilegio del suo *owner*, **bypassando** la loro RLS. Il fix corretto è forzare `security_invoker`, così la scrittura passa per i permessi e la RLS del **chiamante**:
   ```sql
   ALTER VIEW public.{{ table or "<tabella>" }} SET (security_invoker = on);
   ```
   Poi metti in sicurezza le **tabelle sorgente** della vista come nel Caso A (RLS + policy di scrittura per-utente): `security_invoker` fa applicare quelle policy alla scrittura, ma se le tabelle sotto restano aperte la vista resta scrivibile.

4. Applica su **staging**, prova un INSERT con la sola `anon` key (deve essere **rifiutato**), poi promuovi.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RLS_WRITE_OPEN`{% if table %} su `{{ table }}`{% endif %} deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
