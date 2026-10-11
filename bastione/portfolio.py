"""Portfolio mode (§21) — scan-all multi-target + report consolidato.

Hai molte app (Numely, Gestionale, Chirsan, i siti…). `portfolio.toml` elenca i
target; `bastione scan-all` esegue OGNI target via `Orchestrator` (READ_ONLY di
default, riusando la pipeline esistente) e produce un **report consolidato**
(markdown) con una **TABELLA DI POSTURA DEL PORTFOLIO**: per ogni app lo score,
il numero di CRITICAL ancora aperti e il numero di DRIFT. Una sola occhiata per
sapere quale app ha bisogno di attenzione.

Invarianti (§21):
- **READ_ONLY di default**: nessuna scrittura sul target. Il portfolio NON declassa
  e NON aggira nulla — ogni target passa comunque dal gate (§7) in fase LOAD, come
  una `scan` normale. `[defaults].max_intrusion` può alzare il tetto, ma resta il
  gate l'autorità (e per > read-only servirebbe comunque l'ownership challenge).
- **RESILIENTE** (P-resilienza §4.7): un target che fallisce — config assente, gate
  denial, errore interno — diventa una **riga d'errore** nella tabella e NON
  interrompe gli altri. Il portfolio è "best-effort per-target": una mela marcia
  non rovina il cesto.
- **DETERMINISTICO**: `now` e i path (`runs_root`/`baselines_root`) sono iniettabili
  come nell'orchestratore, così i test non toccano rete né orologio reale.

Niente rete qui: `run_portfolio` orchestra solo `Orchestrator.run` (che a sua volta
è READ_ONLY in M0/M2 read-only). La factory dell'orchestratore è iniettabile, così i
test passano un fake offline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:                                   # Python ≥3.11
    import tomllib
except ModuleNotFoundError:            # pragma: no cover — fallback <3.11 (§3)
    import tomli as tomllib            # type: ignore[no-redef]

from bastione.enums import IntrusionLevel
from bastione.gate import IntrusionDenied
from bastione.state import RunState

log = logging.getLogger("bastione.portfolio")

DEFAULT_PORTFOLIO_FILE = Path("portfolio.toml")

# Nome del report consolidato scritto sotto runs_root (§21). Single-file markdown,
# come gli altri report (§23) ma a livello di portfolio, non di singola scan.
PORTFOLIO_REPORT_FILENAME = "portfolio-report.md"

# Mapping stringa `[defaults].max_intrusion` → enum di dominio (§5.1). Stesse
# stringhe stabili della CLI (read-only|probe|mutating). Sconosciuto → read-only
# (default sicuro: il portfolio non alza mai il tetto per un typo nel TOML).
_INTRUSION_FROM_STR = {
    "read-only": IntrusionLevel.READ_ONLY,
    "probe": IntrusionLevel.PROBE,
    "mutating": IntrusionLevel.MUTATING,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─── config: parse di portfolio.toml ────────────────────────────────────────

@dataclass
class PortfolioConfig:
    """Config del portfolio (§21): la lista `targets` + la tabella `[defaults]`.

    `defaults` è tenuta come dict grezzo (chiavi opzionali: `max_intrusion`,
    `notify_channel`, …): il portfolio non impone uno schema rigido sui default,
    li applica solo dove li riconosce (es. `max_intrusion`)."""

    targets: list[str] = field(default_factory=list)
    defaults: dict = field(default_factory=dict)

    def max_intrusion(self) -> IntrusionLevel:
        """Tetto di intrusione effettivo del portfolio (§21). Legge
        `[defaults].max_intrusion` (stringa CLI); assente/sconosciuto →
        READ_ONLY (default sicuro). Il gate (§7) resta comunque l'autorità."""
        raw = self.defaults.get("max_intrusion")
        if isinstance(raw, str):
            return _INTRUSION_FROM_STR.get(raw.strip().lower(), IntrusionLevel.READ_ONLY)
        return IntrusionLevel.READ_ONLY


def load_portfolio(path: str | Path = DEFAULT_PORTFOLIO_FILE) -> PortfolioConfig:
    """Carica e valida `portfolio.toml` → `PortfolioConfig` (§21).

    Parse minimale e tollerante sui contenuti, MA esplicito sull'assenza del file:
    - file inesistente → `FileNotFoundError` (la CLI la mappa a un errore chiaro);
    - `targets` assente o non-lista → lista vuota (portfolio vuoto, nessun crash);
    - voci non-stringa in `targets` scartate (difesa contro TOML malformato);
    - `[defaults]` assente → dict vuoto.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Portfolio non trovato: '{path}'. Crea un portfolio.toml con "
            f"'targets = [...]' (vedi portfolio.toml d'esempio) — §21.")
    with path.open("rb") as fh:
        data = tomllib.load(fh)

    raw_targets = data.get("targets") if isinstance(data, dict) else None
    targets = [t for t in raw_targets if isinstance(t, str)] if isinstance(raw_targets, list) else []

    raw_defaults = data.get("defaults") if isinstance(data, dict) else None
    defaults = raw_defaults if isinstance(raw_defaults, dict) else {}

    return PortfolioConfig(targets=targets, defaults=defaults)


# ─── riga della tabella di postura ──────────────────────────────────────────

@dataclass
class PortfolioRow:
    """Una riga della tabella di postura del portfolio (§21): i numeri chiave di
    una app dopo la sua scan, oppure una riga d'errore se la scan è fallita.

    Campi numerici `None` SOLO sulle righe d'errore (dati non disponibili): per le
    righe OK sono sempre valorizzati. `error` è il messaggio se la scan è fallita,
    `None` se è andata a buon fine."""

    target: str
    score: float | None = None
    critical_open: int | None = None   # #CRITICAL APERTI (emessi, esclusi i FIXED)
    drift: int | None = None
    new: int | None = None
    known: int | None = None
    fixed: int | None = None
    error: str | None = None
    # S16 (R6): finding in baseline che la run non poteva ri-controllare (es.
    # scan-all READ_ONLY su finding PROBE): restano aperti, non vanno nascosti.
    not_reverified: int = 0

    @classmethod
    def from_state(cls, target: str, state: RunState) -> "PortfolioRow":
        """Costruisce la riga dai numeri di un `RunState` (§24). I CRITICAL
        APERTI sono `counts.by_severity.critical`: il breakdown conta i SOLI
        finding emessi (NEW/KNOWN/ACCEPTED), che escludono già i FIXED (§16) —
        cioè esattamente i critical ancora aperti."""
        counts = state.counts or {}
        by_sev = counts.get("by_severity", {}) or {}
        return cls(
            target=target,
            score=state.posture_score if state.posture_score is not None else 0.0,
            critical_open=int(by_sev.get("critical", 0)),
            drift=int(counts.get("drift", 0)),
            new=int(counts.get("new", 0)),
            known=int(counts.get("known", 0)),
            fixed=int(counts.get("fixed", 0)),
            error=None,
            not_reverified=int(counts.get("not_reverified", 0) or 0),
        )

    @classmethod
    def error_row(cls, target: str, message: str) -> "PortfolioRow":
        """Riga d'errore (§21 resilienza): un target la cui scan è fallita. I
        campi numerici restano `None` (non disponibili); `error` porta il
        messaggio (già pulito, niente stacktrace)."""
        return cls(target=target, error=message)


# Tipo della factory iniettabile: `() -> Orchestrator-like`. Il chiamante reale
# passa un closure che costruisce un `Orchestrator` con i path giusti; i test
# passano un fake offline. Tipizzato lasco apposta (duck typing su `.run`/`._run_dir`).
OrchFactory = Callable[[], object]


# ─── driver: esegue ogni target e produce il report consolidato ─────────────

def run_portfolio(
    config: PortfolioConfig,
    *,
    orch_factory: OrchFactory,
    runs_root: Path = Path("runs"),
    baselines_root: Path = Path("baselines"),
    now: Callable[[], datetime] = _utcnow,
    write: bool = False,
) -> tuple[str, list[PortfolioRow]]:
    """Esegue OGNI target del portfolio e produce il report consolidato (§21).

    Per ogni target costruisce un orchestratore via `orch_factory` (così la CLI
    può cablare i path reali e i test un fake offline) e ne chiama `run()` in
    READ_ONLY di default (o al tetto `[defaults].max_intrusion`, comunque sotto il
    gate §7). Raccoglie i numeri chiave in una `PortfolioRow`. RESILIENTE: ogni
    eccezione del singolo target — config assente, gate denial, errore interno — è
    catturata e tradotta in una **riga d'errore**; gli altri target proseguono.

    Ritorna `(markdown_consolidato, righe)`. Se `write=True`, scrive anche il
    markdown sotto `runs_root/<timestamp>/portfolio-report.md` (deterministico via
    `now`).
    """
    level = config.max_intrusion()
    rows: list[PortfolioRow] = []

    for target in config.targets:
        try:
            orch = orch_factory()
            # READ_ONLY di default (§21): nessun accept-baseline, nessun resume —
            # il portfolio è una fotografia di postura, non muta la baseline.
            state = orch.run(target, max_intrusion=level)
            rows.append(PortfolioRow.from_state(target, state))
            log.info("portfolio: target %r scansionato (score=%s)",
                     target, getattr(state, "posture_score", None))
        except IntrusionDenied as exc:
            # Gate denial (precondizione/produzione/ownership): riga d'errore
            # chiara, NON un crash del portfolio (§21 resiliente). PreconditionDenied
            # è sottoclasse → coperta qui.
            rows.append(PortfolioRow.error_row(target, f"gate negato (§7): {exc}"))
            log.warning("portfolio: target %r negato dal gate — riga d'errore", target)
        except FileNotFoundError as exc:
            rows.append(PortfolioRow.error_row(target, f"config assente: {exc}"))
            log.warning("portfolio: target %r config assente — riga d'errore", target)
        except Exception as exc:  # noqa: BLE001 — resilienza §21: una run rotta non ferma il portfolio
            rows.append(PortfolioRow.error_row(target, f"errore interno: {exc}"))
            log.warning("portfolio: target %r ha sollevato — riga d'errore (resilienza §21)",
                        target, exc_info=True)

    report = render_portfolio_report(rows, now=now())

    if write:
        out_dir = Path(runs_root) / now().strftime("%Y%m%dT%H%M%S_%fZ")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / PORTFOLIO_REPORT_FILENAME
        out_path.write_text(report, encoding="utf-8")
        log.info("portfolio: report consolidato scritto in %s", out_path)

    return report, rows


# ─── render del report consolidato (markdown) ───────────────────────────────

def render_portfolio_report(rows: list[PortfolioRow], *, now: datetime) -> str:
    """Rende il report CONSOLIDATO del portfolio in markdown (§21).

    In testa la **tabella di postura del portfolio**: per ogni app lo score, i
    CRITICAL aperti e i DRIFT (più NEW/KNOWN/FIXED per contesto). Le righe d'errore
    sono rese in modo visibile (colonna `error`), così non passano inosservate.
    Sotto, un riepilogo del portfolio (quante app scansionate, quante in errore,
    quante con CRITICAL aperti)."""
    lines: list[str] = []
    lines.append("# Bastione — Portfolio posture report (§21)")
    lines.append("")
    lines.append(f"_Generato: {now.isoformat()}_")
    lines.append("")

    if not rows:
        lines.append("_Portfolio vuoto: nessun target in `portfolio.toml`._")
        lines.append("")
        return "\n".join(lines)

    # ── tabella di postura ──────────────────────────────────────────────────
    lines.append("## Tabella di postura")
    lines.append("")
    lines.append("| App | Score | #CRITICAL aperti | #DRIFT | NEW | KNOWN | FIXED | Stato |")
    lines.append("|-----|------:|-----------------:|-------:|----:|------:|------:|-------|")
    for r in rows:
        if r.error is not None:
            # Riga d'errore: numeri non disponibili, messaggio nella colonna Stato.
            lines.append(
                f"| {r.target} | — | — | — | — | — | — | "
                f"⚠️ error: {_escape_cell(r.error)} |")
        else:
            score = f"{r.score:.1f}" if r.score is not None else "—"
            stato = (f"⚠️ {r.not_reverified} non ri-verificati" if r.not_reverified
                     else "ok")
            lines.append(
                f"| {r.target} | {score} | {r.critical_open} | {r.drift} | "
                f"{r.new} | {r.known} | {r.fixed} | {stato} |")
    lines.append("")

    # ── riepilogo del portfolio ─────────────────────────────────────────────
    n_total = len(rows)
    n_error = sum(1 for r in rows if r.error is not None)
    n_ok = n_total - n_error
    n_crit = sum(1 for r in rows if r.error is None and (r.critical_open or 0) > 0)
    n_drift = sum(1 for r in rows if r.error is None and (r.drift or 0) > 0)

    lines.append("## Riepilogo")
    lines.append("")
    lines.append(f"- App nel portfolio: **{n_total}** "
                 f"({n_ok} scansionate, {n_error} in errore).")
    lines.append(f"- App con ≥1 CRITICAL aperto: **{n_crit}**.")
    lines.append(f"- App con ≥1 DRIFT (regressione di postura): **{n_drift}**.")
    lines.append("")
    if n_crit or n_drift:
        lines.append("> Priorità: agisci prima sulle app con CRITICAL aperti o DRIFT.")
    else:
        lines.append("> Nessun CRITICAL aperto né DRIFT tra le app scansionate.")
    lines.append("")

    return "\n".join(lines)


def _escape_cell(text: str) -> str:
    """Neutralizza i caratteri che romperebbero una cella di tabella markdown
    (`|` e i newline). Difesa minima: il messaggio d'errore finisce in una cella."""
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
