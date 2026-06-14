### Playbook — {{ title }}{% if table %} su `{{ table }}`{% endif %}

**Cosa significa.** La tabella{% if table %} `{{ table }}`{% endif %} (`{{ location.endpoint or "/rest/v1/<tabella>" }}`) è esposta da PostgREST con Row Level Security **disattivata**: chiunque possieda la `anon` key (pubblica per design, presente nel bundle JS) può leggerne i record.

**Perché è pericoloso.** Senza RLS la `anon` key dà accesso diretto ai dati: dump completo della tabella, enumerazione di clienti/ordini/utenti, esposizione di dati personali (GDPR). Severità: **{{ severity }}**.

**Prima di tutto: `{{ table or "<tabella>" }}` è una TABELLA o una VISTA?** Su Supabase i finding RLS spesso colpiscono **viste** (view), non tabelle base, e il fix è diverso. Verificalo con:
```sql
SELECT relkind FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relname = '{{ table or "<tabella>" }}';
-- 'r' = tabella · 'v' = vista · 'm' = vista materializzata
```

**Caso A — è una TABELLA (`relkind = 'r'`), passo-passo:**
1. Dashboard Supabase → **Authentication → Policies** → seleziona la tabella `{{ table or "<tabella>" }}`.
2. Abilita RLS sulla tabella:
   ```sql
   ALTER TABLE public.{{ table or "<tabella>" }} ENABLE ROW LEVEL SECURITY;
   ```
3. Aggiungi una policy SELECT **restrittiva** (esempio per dati per-utente):
   ```sql
   CREATE POLICY sel_own ON public.{{ table or "<tabella>" }}
     FOR SELECT USING (auth.uid() = user_id);
   ```
   Se la tabella deve restare pubblica in lettura, rendilo esplicito con una policy che lo dica — non lasciarlo implicito a RLS spenta.

**Caso B — è una VISTA (`relkind = 'v'`/`'m'`):** sulle viste **non si abilita RLS** (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` non si applica a una view). Una vista, di default, gira con i permessi del suo *owner* e **bypassa** la RLS delle tabelle sottostanti. Il fix corretto è forzare `security_invoker`, così la vista esegue con i permessi del **chiamante** e quindi rispetta la RLS delle tabelle sorgente:
   ```sql
   ALTER VIEW public.{{ table or "<tabella>" }} SET (security_invoker = on);
   ```
   Assicurati poi che le **tabelle sorgente** della vista abbiano a loro volta RLS + policy corrette (vedi Caso A): `security_invoker` fa rispettare quelle policy, ma se le tabelle sotto non ne hanno, la vista resta aperta.

5. Applica prima su **staging**, verifica che l'app autenticata continui a funzionare, poi promuovi in produzione.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RLS_DISABLED`{% if table %} su `{{ table }}`{% endif %} deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
