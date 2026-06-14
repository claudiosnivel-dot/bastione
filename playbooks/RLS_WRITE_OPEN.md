### Playbook — {{ title }}{% if table %} su `{{ table }}`{% endif %}

**Cosa significa.** La tabella{% if table %} `{{ table }}`{% endif %} (`{{ location.endpoint or "/rest/v1/<tabella>" }}`) accetta **scritture** (INSERT/UPDATE/DELETE) con la sola `anon` key: non esiste una policy che limiti chi può modificare i dati.

**Perché è pericoloso.** Un attaccante può inserire, alterare o cancellare record arbitrari (defacement, frode, distruzione dati) senza autenticarsi. È più grave della sola lettura aperta. Severità: **{{ severity }}**.

**Come ripararlo (Supabase), passo-passo:**
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
4. Applica su **staging**, prova un INSERT con la sola `anon` key (deve essere **rifiutato**), poi promuovi.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `RLS_WRITE_OPEN`{% if table %} su `{{ table }}`{% endif %} deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
