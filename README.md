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

## Layout

La struttura del repository è **normativa** (§4 del blueprint): non si inventano
cartelle. Un nuovo detector = un file in `bastione/modules/secrets/detectors/`; un
nuovo modulo = una cartella in `bastione/modules/`. I file vengono creati
incrementalmente seguendo il build order M0.
