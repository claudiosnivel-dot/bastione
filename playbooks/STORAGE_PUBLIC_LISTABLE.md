### Playbook — {{ title }}

**Cosa significa.** Un **bucket Supabase Storage** (`{{ location.endpoint or "<bucket>" }}`) è pubblico **e listabile**: non solo i file noti sono scaricabili, ma se ne può **elencare il contenuto** e scoprire tutti gli oggetti presenti.

**Perché è pericoloso.** L'enumerazione espone file che dovevano restare riservati (documenti, allegati, backup, immagini private di altri utenti). Anche se i nomi sembrano "non indovinabili", la listabilità li rende tutti raggiungibili. Severità: **{{ severity }}**.

**Come ripararlo (Supabase), passo-passo:**
1. Dashboard Supabase → **Storage** → seleziona il bucket → **Configuration**.
2. Se il bucket non deve essere pubblico, impostalo su **Private**: l'accesso passerà da URL firmati a tempo (`createSignedUrl`).
3. Se deve restare pubblico per i singoli file ma **non** elencabile, aggiungi policy su `storage.objects` che neghino il `list`:
   ```sql
   CREATE POLICY no_list ON storage.objects
     FOR SELECT USING (false);
   ```
   e servi i file tramite URL firmati o un path noto, non via listing.
4. Applica su **staging**, verifica che il listing pubblico fallisca e che gli URL legittimi funzionino.

**Come verificare il fix.** Ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `STORAGE_PUBLIC_LISTABLE` deve passare a **FIXED**.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
