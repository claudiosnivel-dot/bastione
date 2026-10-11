### Playbook — {{ title }}

**Cosa significa.** È stato trovato il **token di un bot Telegram**{% if location.file %} in `{{ location.file }}`{% endif %}: una credenziale che non deve mai stare nel client.

**Perché è pericoloso.** Con il token un attaccante prende il controllo del bot: legge i messaggi che il bot riceve (compresi dati e chat id degli utenti), scrive a nome del bot (phishing da un mittente fidato) e può cambiarne il webhook. Il token è **compromesso** nel momento in cui è nel bundle. Severità: **{{ severity }}**.

**Come ripararlo (l'ordine conta):**
1. **Ruota subito (azione umana):** su Telegram apri **@BotFather** → `/revoke` → scegli il bot: viene generato un nuovo token e il vecchio smette subito di funzionare. Rimuoverlo dal codice NON basta: il token esposto resta valido finché non lo revochi.
2. Conserva il nuovo token **solo lato server** (env del backend); il client non lo usa mai. Se è il bot che Bastione usa per le notifiche, aggiorna la variabile d'ambiente `BASTIONE_TELEGRAM_BOT_TOKEN` con il nuovo valore.
3. Rimuovi ogni riferimento dal frontend; le chiamate all'API Bot passano da un endpoint server-side.
4. Se era committato, ripulisci anche la history.
5. Verifica con `getWebhookInfo` che il webhook del bot punti ancora al tuo endpoint e non a un URL altrui.

**Come verificare il fix.** Ruotato e ripulito, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_TELEGRAM_BOT` deve passare a **FIXED**: si chiude quando il token non compare più nel codice servito, quindi rifai il deploy dopo averlo rimosso.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
