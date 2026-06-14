# Bastione (BAS)

Orchestratore di security testing **difensivo** per applicazioni web **di proprietà**.
Bastione non è uno scanner one-shot: è una sentinella che conosce la *baseline* delle
tue app, **simula un attaccante esterno** contro infrastruttura che possiedi, **segnala
ciò che è nuovo o regredito** e ti dice **come ripararlo** — convergendo in SARIF +
report + alert.

> **Documenti normativi:** `BASTIONE-BLUEPRINT-v2.md` (il *cosa* — architettura,
> contratti, macchina a stati, roadmap) e `BASTIONE-SESSION-STATE.md` (lo *stato di
> sviluppo*, handoff tra sessioni). In caso di dubbio, il blueprint vince.

## ⚠️ Uso ammesso (non negoziabile, §7 del blueprint)

Si testa **solo** ciò che possiedi, o per cui hai **autorizzazione scritta**. Puntare
infrastruttura altrui in Italia è accesso abusivo a sistema informatico (art. 615-ter
c.p.). Questi vincoli sono **codice eseguibile** in `bastione/gate.py`, non buoni
propositi:

- **Produzione = blocco assoluto.** `environment="production"` aborta in `assert_preconditions`.
- **Owned-only.** Si tocca solo un target dichiarato `owned`/`authorized-written` nel TOML.
- **Read-only di default.** Salire a `PROBE`/`MUTATING` richiede flag espliciti + ownership challenge.
- **Segreti redatti** in ogni output.

## Stato

**Milestone M0** — vista read-only dell'attaccante. In corso di costruzione (build
order in `BASTIONE-SESSION-STATE.md` §2). In M0 è **tutto read-only**: nessuna
scrittura, le scritture canary sono M2.

## Requisiti & setup

- **Python 3.11+**
- Gestione dipendenze con **[uv](https://docs.astral.sh/uv/)** (consigliato):

  ```bash
  uv sync
  uv run bastione doctor      # (disponibile dallo step 15)
  ```

- **Fallback `venv + pip`** (L02), se `uv` non è disponibile:

  ```bash
  python -m venv .venv
  # Windows: .venv\Scripts\activate   |   POSIX: source .venv/bin/activate
  pip install -e .            # dipendenze runtime
  pip install pytest         # dev-dep: sta in [dependency-groups] (PEP 735), che pip
                             # non installa via ".[dev]"; in alternativa con pip >= 25.1:
                             # pip install --group dev
  ```

## Test

```bash
uv run pytest            # oppure: python -m pytest
```

## Monitoring / scansioni schedulate (§20)

Il monitoring di Bastione **non** è un daemon né un servizio always-on: è
semplicemente *scan schedulato → diff baseline (§16) → notify (§19)*, coerente con
free-tier e con la filosofia "niente infrastruttura prematura". Ogni notte sai se è
comparsa una **nuova esposizione** (NEW) o una **regressione di posture** (DRIFT) su
una delle tue app, senza doverti ricordare di lanciare nulla.

Gli esempi qui sotto usano l'entrypoint reale: il **console script `bastione`**,
installato da `pip install -e .` (vedi *Requisiti & setup*). Sostituisci `bastione`
con `uv run bastione` se gestisci le dipendenze con `uv`.

> **La baseline va committata (L05/§22).** In CI/cron la baseline
> `baselines/<target>.baseline.json` è **versionata nel repo**: il formato §16
> contiene solo `finding_id`/`status`/`rule_id`/`module` (mai evidenze, mai segreti),
> quindi è sicuro committarla. Senza baseline versionata ogni run vedrebbe **tutto**
> come `NEW` e il gate fallirebbe sempre. Quando emerge un'esposizione legittima la
> promuovi a nota — `bastione scan --target <t> --accept-baseline` — e committi la
> baseline aggiornata.
>
> **I tool esterni opzionali degradano (§24).** `whatweb`, `katana`, `testssl.sh`,
> `nuclei`, `zap` sono opzionali: se assenti il recon **degrada** (§8), non fallisce.
> È esattamente ciò che `bastione doctor` rileva. Una scansione schedulata gira
> comunque, con copertura ridotta.

### Ricetta 1 — crontab (self-host)

Una riga di `crontab -e` su una macchina che possiedi. Scansione READ_ONLY del
target ogni notte alle 03:00:

```cron
0 3 * * * cd /opt/bastione && bastione scan --target gestionale --max-intrusion read-only
```

Note operative:

- la run è **READ_ONLY**: nessuna scrittura sul target (default M0/M2). Per salire a
  `mutating` (scritture canary §11.2) servirebbe `--i-own-this-its-staging` esplicito
  su uno staging di proprietà — sconsigliato in un cron notturno;
- per ricevere l'alert Telegram (§19) esporta le due variabili d'ambiente **prima**
  del comando (es. in un wrapper o nel `crontab` con `BASTIONE_TELEGRAM_BOT_TOKEN=…`):
  `BASTIONE_TELEGRAM_BOT_TOKEN` e `BASTIONE_TELEGRAM_CHAT_ID`. Se mancano, il notify è
  un no-op loggato (best-effort §19), non un errore;
- gli artefatti finiscono in `runs/<target>/<timestamp>/` (SARIF + report MD/HTML);
- ricordati di **committare la baseline** dopo aver accettato i finding noti, anche in
  self-host, così le run successive segnalano solo i veri delta.

### Ricetta 2 — GitHub Actions (`.github/workflows/bastione.yml`)

Un workflow schedulato (`schedule: cron`) + avvio manuale (`workflow_dispatch`) che:
fa il checkout (porta con sé la **baseline committata**), installa il pacchetto
(`pip install -e .`, che registra il console script `bastione`), esegue

```bash
bastione scan --target gestionale --ci --fail-on high
```

carica il **SARIF** dell'ultima run (`runs/<target>/<timestamp>/bastione.sarif`) su
**GitHub code scanning** (`github/codeql-action/upload-sarif`) — e in più come
artifact — e **fallisce sui NEW/DRIFT** propagando l'exit code del gate (§22).

Punti chiave (coerenti con la CLI reale):

- **`--ci` rifiuta `--unsafe-show-secrets`** (P8/§25): un'esecuzione CI non deve mai
  stampare segreti in chiaro → la combinazione esce con codice ≠ 0. In CI si usa solo
  `--ci`/`--fail-on`;
- **gate exit-code (§22, LOCKED):** la scan esce `1` se c'è ≥1 finding `NEW` con
  severità ≥ soglia (`--fail-on high`) **oppure** ≥1 `DRIFT`; `2` per errore
  config/precondizione, `3` per ownership challenge fallito, `4` per errore interno.
  Il workflow rende `1` un fallimento del job **dopo** aver caricato il SARIF;
- **la baseline committata evita falsi `NEW`:** è proprio il checkout della baseline
  versionata a rendere significativo il delta (vedi nota sopra);
- **segreti Telegram nei *repository secrets*:** imposta
  `BASTIONE_TELEGRAM_BOT_TOKEN` e `BASTIONE_TELEGRAM_CHAT_ID` in
  *Settings → Secrets and variables → Actions*; il workflow li passa come `env` al
  solo step di scan. Non vanno mai nel TOML né committati. Se assenti, l'alert è un
  no-op (best-effort §19).

Il file completo, commentato, è in [`.github/workflows/bastione.yml`](.github/workflows/bastione.yml):
cambia `BAS_TARGET` (e l'orario del `cron`) per adattarlo alle tue app.

## Layout

La struttura del repository è **normativa** (§4 del blueprint): non si inventano
cartelle. Un nuovo detector = un file in `bastione/modules/secrets/detectors/`; un
nuovo modulo = una cartella in `bastione/modules/`. I file vengono creati
incrementalmente seguendo il build order M0.
