### Playbook — {{ title }}

**Cosa significa.** È stata trovata una **chiave API Google** (formato `AIza…`){% if location.file %} in `{{ location.file }}`{% endif %}. Alcune chiavi Google nascono per stare nel client (Maps JavaScript, Firebase) **a patto di essere ristrette**; quelle che accedono ad API di intelligenza artificiale (Gemini) o a servizi a pagamento no.

**Perché è pericoloso.** Una chiave non ristretta, o abilitata su API a pagamento, permette a chiunque di consumare la tua quota e di fatturare a te: le chiavi che arrivano alle API di IA sono tra le più abusate. Se invece è ristretta a referrer e API specifici, la presenza nel bundle è prevista e il rischio è limitato. Severità: **{{ severity }}**: da fuori non si può sapere se la chiave sia ristretta, quindi il finding resta a questa severità anche quando la verifica read-only (solo con `--max-intrusion probe`) conferma l'accesso alle API di IA. L'esito compare nella descrizione del finding; il rischio reale lo stabilisci tu al punto 1.

**Come ripararlo (l'ordine conta):**
1. **Capisci a cosa serve:** Google Cloud Console → **APIs & Services → Credentials** → apri la chiave e leggi *Application restrictions* e *API restrictions* (e le API abilitate sul progetto).
2. **Se è una chiave server-side, non ristretta o abilitata su API di IA o a pagamento (Gemini, Vertex AI, Cloud):** ruota subito (azione umana): crea una nuova chiave **ristretta** (solo le API e le applicazioni o gli IP necessari) ed **elimina** quella esposta. Rimuoverla dal codice NON basta: la chiave esposta resta valida finché non la elimini.
3. **Se è davvero una chiave browser (Maps, Firebase):** non va rimossa, va **ristretta**: *HTTP referrers* limitati ai tuoi domini e solo le API necessarie. Imposta anche quote e avvisi di budget.
4. Le chiavi server-side vanno conservate **solo lato server** (env del backend); il client non le usa mai. Se era committata, ripulisci anche la history.
5. Controlla Metrics e Billing del progetto per consumi anomali nel periodo di esposizione.

**Come verificare il fix.** Ruotata (o ristretta) e ripulita, ri-esegui:
```
bastione verify --target {{ target }}
```
Il finding `SECRET_GOOGLE_API_KEY` deve passare a **FIXED**: per una chiave server-side si chiude quando non compare più nel codice servito, quindi rifai il deploy dopo averla rimossa.

<sub>Evidence (già redatta): `{{ evidence }}`</sub>
