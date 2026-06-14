### Playbook — {{ title }}{% if table %} su `{{ table }}`{% endif %}

**Cosa significa.** La tabella{% if table %} `{{ table }}`{% endif %} (`{{ location.endpoint or "/rest/v1/<tabella>" }}`) è esposta da PostgREST con Row Level Security **disattivata**: chiunque possieda la `anon` key (pubblica per design, presente nel bundle JS) può leggerne i record.

**Perché è pericoloso.** Senza RLS la `anon` key dà accesso diretto ai dati: dump completo della tabella, enumerazione di clienti/ordini/utenti, esposizione di dati personali (GDPR). Severità: **{{ severity }}**.

**Come ripararlo (Supabase), passo-passo:**
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
4. Applica prima su **staging**, verifica che l'app autenticata continui a funzionare, poi promuovi in produzione.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RLS_DISABLED`{% if table %} su `{{ table }}`{% endif %} deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
