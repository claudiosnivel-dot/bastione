### Playbook — {{ title }}

**Cosa significa.** La **`service_role` key** di Supabase è stata trovata{% if location.file %} in `{{ location.file }}`{% endif %}: una chiave che **bypassa completamente RLS** e dà accesso amministrativo al database. A differenza della `anon` key, non deve **mai** raggiungere il client/bundle.

**Perché è pericoloso.** Chi la possiede legge e scrive **qualunque** tabella ignorando ogni policy: è il controllo totale del backend. Va trattata come **compromessa** nel momento in cui è finita nel bundle. Severità: **{{ severity }}**.

**Come ripararlo, passo-passo (l'ordine conta):**
1. **Ruota subito (azione umana, non rinviabile):** Supabase → **Project Settings → API** → rigenera la `service_role` key e **revoca** quella attuale. Rimuoverla dal codice **non basta**: la chiave esposta resta valida finché non la ruoti.
2. Sposta la nuova chiave **lato server** (variabile d'ambiente del backend/edge function), **mai** nel frontend né in un file servito al client.
3. Rimuovi ogni riferimento alla `service_role` dal codice client; le chiamate privilegiate passano da un endpoint server-side che custodisce la chiave.
4. Verifica che il bundle pubblico contenga **solo** la `anon` key.

**Come verificare il fix.** Ruotata la chiave e ripulito il client, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_SERVICE_ROLE` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
