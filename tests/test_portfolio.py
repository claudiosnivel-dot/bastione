"""Test del Portfolio mode (§21) — interamente OFFLINE e deterministico.

Il portfolio (`bastione scan-all`) esegue OGNI target del `portfolio.toml` via
`Orchestrator` (READ_ONLY di default), raccoglie per-target i numeri chiave
(score, #CRITICAL aperti, #DRIFT, conteggi NEW/KNOWN/FIXED/DRIFT) e produce un
REPORT CONSOLIDATO (markdown) con la TABELLA DI POSTURA DEL PORTFOLIO.

Per restare offline e deterministici (come test_cli.py / test_orchestrator.py):
  - non costruiamo MAI un Orchestrator reale: `run_portfolio` accetta una factory
    `orch_factory` iniettabile che ritorna un fake il cui `.run()` non tocca rete
    né disco e restituisce un `RunState` sintetico (oppure SOLLEVA, per provare la
    resilienza);
  - `now` è iniettabile (timestamp deterministico nel report), come fa l'orchestratore.

Copre (§21):
  - `load_portfolio`: parse della lista `targets` + tabella `[defaults]`;
  - `run_portfolio`: aggrega 2 target → tabella consolidata con score/#CRITICAL/#DRIFT;
  - resilienza: un target che SOLLEVA (config assente, gate denial, errore) diventa
    una RIGA D'ERRORE e NON interrompe gli altri;
  - il markdown consolidato contiene per ogni app score, #CRITICAL aperti, #DRIFT.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel
from bastione.gate import IntrusionDenied, PreconditionDenied
from bastione.portfolio import (
    PortfolioConfig,
    PortfolioRow,
    load_portfolio,
    run_portfolio,
)
from bastione.state import RunState, empty_counts


# ─── helper: RunState sintetico + Orchestrator fake ─────────────────────────

def _state(target: str, *, posture: float = 100.0, new: int = 0, known: int = 0,
           fixed: int = 0, drift: int = 0, critical: int = 0) -> RunState:
    """RunState sintetico per i test del portfolio. `critical` popola
    by_severity (i CRITICAL APERTI = emessi NEW/KNOWN, esclusi i FIXED)."""
    counts = empty_counts()
    counts["new"] = new
    counts["known"] = known
    counts["fixed"] = fixed
    counts["drift"] = drift
    counts["by_severity"]["critical"] = critical
    return RunState(
        target=target,
        max_intrusion="read-only",
        posture_score=posture,
        counts=counts,
        phases_completed=["LOAD", "RECON", "SCAN", "PERSIST"],
    )


class _FakeOrch:
    """Orchestratore fake: per ogni target ritorna un RunState dalla mappa
    `states`, oppure SOLLEVA l'eccezione registrata in `raises`. Registra in
    `calls` i parametri di ogni `run()` (per asserire READ_ONLY di default)."""

    def __init__(self, *, states: dict[str, RunState], raises: dict[str, Exception],
                 calls: list[dict], run_dir_base: Path = Path("runs")):
        self._states = states
        self._raises = raises
        self._calls = calls
        # l'orchestratore reale popola self._run_dir: lo imitiamo per i path.
        self._run_dir = run_dir_base

    def run(self, target, *, max_intrusion=IntrusionLevel.READ_ONLY, resume=False,
            accept_baseline=False, no_fix=False, fail_on=None):
        self._calls.append({
            "target": target, "max_intrusion": max_intrusion, "resume": resume,
            "accept_baseline": accept_baseline, "no_fix": no_fix, "fail_on": fail_on,
        })
        self._run_dir = Path("runs") / target / "ts"
        if target in self._raises:
            raise self._raises[target]
        return self._states[target]


def _factory(states=None, raises=None, calls=None):
    """Costruisce una factory `() -> _FakeOrch` con gli stessi mock condivisi.

    Una nuova istanza per target è ammessa (la factory è chiamata per ogni run),
    ma `states`/`raises`/`calls` sono condivisi così i test possono ispezionarli."""
    states = states or {}
    raises = raises or {}
    calls = calls if calls is not None else []

    def make():
        return _FakeOrch(states=states, raises=raises, calls=calls)

    return make


def _fixed_now():
    return datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)


# ─── load_portfolio: parse del TOML ─────────────────────────────────────────

def test_load_portfolio_parses_targets_and_defaults(tmp_path):
    p = tmp_path / "portfolio.toml"
    p.write_text(
        'targets = ["gestionale", "numely", "chirsan"]\n'
        "[defaults]\n"
        'max_intrusion = "read-only"\n'
        'notify_channel = "telegram"\n',
        encoding="utf-8",
    )
    cfg = load_portfolio(p)
    assert isinstance(cfg, PortfolioConfig)
    assert cfg.targets == ["gestionale", "numely", "chirsan"]
    assert cfg.defaults["max_intrusion"] == "read-only"
    assert cfg.defaults["notify_channel"] == "telegram"


def test_load_portfolio_defaults_are_optional(tmp_path):
    # Senza [defaults] il portfolio resta valido: defaults = {} (read-only è il default).
    p = tmp_path / "portfolio.toml"
    p.write_text('targets = ["solo"]\n', encoding="utf-8")
    cfg = load_portfolio(p)
    assert cfg.targets == ["solo"]
    assert cfg.defaults == {}


def test_load_portfolio_missing_file_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_portfolio(tmp_path / "non-esiste.toml")


def test_load_portfolio_empty_targets_is_empty_list(tmp_path):
    # `targets` assente o vuoto → lista vuota (nessun crash; il portfolio è vuoto).
    p = tmp_path / "portfolio.toml"
    p.write_text("[defaults]\nmax_intrusion = \"read-only\"\n", encoding="utf-8")
    cfg = load_portfolio(p)
    assert cfg.targets == []


# ─── run_portfolio: aggregazione di 2 target ────────────────────────────────

def test_run_portfolio_aggregates_two_targets(tmp_path):
    states = {
        "gestionale": _state("gestionale", posture=73.5, new=2, critical=1, drift=0),
        "numely": _state("numely", posture=91.0, known=1, critical=0, drift=2),
    }
    calls: list[dict] = []
    factory = _factory(states=states, calls=calls)

    report, rows = run_portfolio(
        PortfolioConfig(targets=["gestionale", "numely"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )

    # due righe, una per target, nell'ordine del portfolio.
    assert [r.target for r in rows] == ["gestionale", "numely"]
    g = next(r for r in rows if r.target == "gestionale")
    assert g.error is None
    assert g.score == pytest.approx(73.5)
    assert g.critical_open == 1
    assert g.drift == 0
    n = next(r for r in rows if r.target == "numely")
    assert n.score == pytest.approx(91.0)
    assert n.critical_open == 0
    assert n.drift == 2

    # il markdown consolidato è una stringa con i numeri chiave per ogni app.
    assert isinstance(report, str)
    assert "gestionale" in report and "numely" in report
    assert "73" in report and "91" in report


def test_run_portfolio_runs_every_target_read_only_by_default(tmp_path):
    states = {"a": _state("a"), "b": _state("b")}
    calls: list[dict] = []
    factory = _factory(states=states, calls=calls)

    run_portfolio(
        PortfolioConfig(targets=["a", "b"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )

    assert [c["target"] for c in calls] == ["a", "b"]
    # READ_ONLY di default (§21): nessuna scrittura sul target.
    for c in calls:
        assert c["max_intrusion"] == IntrusionLevel.READ_ONLY
        assert c["accept_baseline"] is False


def test_run_portfolio_table_contains_score_critical_drift(tmp_path):
    states = {
        "app1": _state("app1", posture=40.0, new=3, critical=2, drift=1),
    }
    factory = _factory(states=states)
    report, rows = run_portfolio(
        PortfolioConfig(targets=["app1"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )
    # la tabella di postura contiene score, #CRITICAL aperti, #DRIFT.
    assert "app1" in report
    assert "40" in report          # score
    assert "2" in report           # #CRITICAL aperti
    # intestazioni della tabella di postura (markdown).
    low = report.lower()
    assert "score" in low
    assert "critical" in low
    assert "drift" in low


# ─── resilienza: un target che fallisce non interrompe gli altri ────────────

def test_run_portfolio_failing_target_becomes_error_row(tmp_path):
    # gestionale OK, numely SOLLEVA → riga d'errore; chirsan prosegue regolarmente.
    states = {
        "gestionale": _state("gestionale", posture=80.0),
        "chirsan": _state("chirsan", posture=66.0),
    }
    raises = {"numely": RuntimeError("crash interno del motore")}
    factory = _factory(states=states, raises=raises)

    report, rows = run_portfolio(
        PortfolioConfig(targets=["gestionale", "numely", "chirsan"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )

    # tutte e tre le righe presenti, nell'ordine: l'errore NON ha fermato gli altri.
    assert [r.target for r in rows] == ["gestionale", "numely", "chirsan"]
    numely = next(r for r in rows if r.target == "numely")
    assert numely.error is not None
    assert "crash" in numely.error.lower() or "errore" in numely.error.lower()
    # score/critical/drift sono None per la riga d'errore (non disponibili).
    assert numely.score is None
    # gli altri due hanno i loro dati regolarmente.
    assert next(r for r in rows if r.target == "gestionale").score == pytest.approx(80.0)
    assert next(r for r in rows if r.target == "chirsan").score == pytest.approx(66.0)
    # il report segnala la riga d'errore in modo visibile.
    assert "numely" in report
    assert "error" in report.lower() or "errore" in report.lower()


def test_run_portfolio_gate_denial_becomes_error_row(tmp_path):
    # Un target negato dal gate (produzione bloccata / ownership) → riga d'errore,
    # non un crash del portfolio (§21 resiliente).
    states = {"ok": _state("ok", posture=99.0)}
    raises = {"prod": PreconditionDenied("Bastione non opera su 'production'.")}
    factory = _factory(states=states, raises=raises)

    report, rows = run_portfolio(
        PortfolioConfig(targets=["prod", "ok"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )
    prod = next(r for r in rows if r.target == "prod")
    assert prod.error is not None
    assert "production" in prod.error or "Bastione" in prod.error
    # l'altro target è stato comunque eseguito.
    assert next(r for r in rows if r.target == "ok").score == pytest.approx(99.0)


def test_run_portfolio_intrusion_denied_becomes_error_row(tmp_path):
    states = {"ok": _state("ok")}
    raises = {"bad": IntrusionDenied("Ownership challenge fallito (§7.1).")}
    factory = _factory(states=states, raises=raises)
    _report, rows = run_portfolio(
        PortfolioConfig(targets=["bad", "ok"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )
    bad = next(r for r in rows if r.target == "bad")
    assert bad.error is not None
    assert "Ownership" in bad.error or "§7" in bad.error


def test_run_portfolio_missing_config_becomes_error_row(tmp_path):
    states = {"ok": _state("ok")}
    raises = {"ghost": FileNotFoundError("targets/ghost.toml")}
    factory = _factory(states=states, raises=raises)
    _report, rows = run_portfolio(
        PortfolioConfig(targets=["ghost", "ok"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )
    ghost = next(r for r in rows if r.target == "ghost")
    assert ghost.error is not None
    # l'altro prosegue.
    assert next(r for r in rows if r.target == "ok").error is None


def test_run_portfolio_empty_targets_produces_empty_report(tmp_path):
    factory = _factory()
    report, rows = run_portfolio(
        PortfolioConfig(targets=[], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
    )
    assert rows == []
    # un report vuoto è comunque una stringa valida (markdown con header).
    assert isinstance(report, str)
    assert "portfolio" in report.lower() or "Portfolio" in report


def test_run_portfolio_writes_consolidated_report_to_disk(tmp_path):
    # run_portfolio scrive il report consolidato sotto runs_root (deterministico).
    states = {"a": _state("a", posture=88.0)}
    factory = _factory(states=states)
    report, _rows = run_portfolio(
        PortfolioConfig(targets=["a"], defaults={}),
        orch_factory=factory,
        runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines",
        now=_fixed_now,
        write=True,
    )
    # il file consolidato esiste e contiene lo stesso markdown ritornato.
    written = list((tmp_path / "runs").glob("**/portfolio*.md"))
    assert written, "report consolidato non scritto su disco"
    assert written[0].read_text(encoding="utf-8") == report


# ─── PortfolioRow: shape della riga di postura ──────────────────────────────

def test_portfolio_row_ok_and_error_shapes():
    ok = PortfolioRow(target="a", score=70.0, critical_open=1, drift=2,
                      new=1, known=0, fixed=0, error=None)
    assert ok.error is None and ok.score == 70.0
    err = PortfolioRow.error_row("b", "boom")
    assert err.target == "b" and err.error == "boom"
    assert err.score is None and err.critical_open is None and err.drift is None


# ─── S16 (R6): i non ri-verificati non spariscono dalla tabella di postura ───

def test_portfolio_row_and_report_show_not_reverified(tmp_path):
    from bastione.portfolio import PortfolioRow
    st = _state("app", posture=100.0)
    st.counts["not_reverified"] = 2
    row = PortfolioRow.from_state("app", st)
    assert row.not_reverified == 2
    states = {"app": st}
    report, rows = run_portfolio(
        PortfolioConfig(targets=["app"], defaults={}),
        orch_factory=_factory(states), runs_root=tmp_path / "runs",
        baselines_root=tmp_path / "baselines", write=False)
    assert "2 non ri-verificati" in report
