"""Test della CLI typer (§25) — interamente OFFLINE.

La CLI è il guscio sopra l'orchestratore (step 15): qui verifichiamo SOLO il
cablaggio CLI, non la pipeline (già coperta da test_orchestrator.py). Per restare
offline e deterministici:
  - monkeypatchiamo `Orchestrator.run` con un fake che NON tocca rete né disco e
    ritorna un `RunState` sintetico (popolando anche `self._run_dir`, da cui la
    CLI ricava i path di report/SARIF);
  - monkeypatchiamo `shutil.which` per `doctor` (niente dipendenza dai tool reali).

Copre (§25 / vincoli M0):
  - scan invoca Orchestrator.run con i parametri giusti e stampa il sommario;
  - mapping --max-intrusion stringa → IntrusionLevel;
  - --unsafe-show-secrets + --ci → errore (incompatibili), exit != 0;
  - IntrusionDenied dal gate → messaggio chiaro, exit != 0, NESSUNO stacktrace;
  - --fail-on/--ci: ≥1 finding ≥ soglia → exit 1; sotto soglia → exit 0;
  - doctor elenca installato/assente con shutil.which monkeypatchato;
  - list-modules elenca i moduli reali; list-detectors elenca SECRET_SERVICE_ROLE;
  - i flag M1/M2 (--no-fix, --i-own-this-its-staging) sono accettati come no-op.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import bastione.cli as cli_mod
from bastione.cli import app
from bastione.enums import IntrusionLevel
from bastione.gate import IntrusionDenied, PreconditionDenied
from bastione.orchestrator import Orchestrator
from bastione.state import RunState, empty_counts

runner = CliRunner()


def _state(*, by_severity: dict | None = None, new_by_severity: dict | None = None,
           new: int = 0, drift: int = 0, posture: float = 100.0) -> RunState:
    """RunState sintetico per i test della CLI.

    `by_severity` conta TUTTI i finding emessi (NEW/KNOWN/ACCEPTED);
    `new_by_severity` conta i soli NEW (shape §24 estesa). Se `new_by_severity`
    non è dato ma `by_severity` sì, lo specchio NEW resta a zero apposta, così i
    test possono distinguere 'finding KNOWN ≥ soglia' da 'finding NEW ≥ soglia'.
    """
    counts = empty_counts()
    counts["new"] = new
    counts["drift"] = drift
    if by_severity:
        counts["by_severity"].update(by_severity)
    if new_by_severity:
        counts["new_by_severity"].update(new_by_severity)
    return RunState(
        target="g",
        max_intrusion="read-only",
        posture_score=posture,
        counts=counts,
        phases_completed=["LOAD", "RECON", "SCAN", "PERSIST"],
    )


def _patch_run(monkeypatch, *, state: RunState | None = None, capture: dict | None = None,
               run_dir: Path = Path("runs/g/ts"), exc: Exception | None = None):
    """Sostituisce Orchestrator.run con un fake offline.

    - registra in `capture` i parametri ricevuti (per le asserzioni di cablaggio);
    - popola `self._run_dir` come fa l'orchestratore reale (la CLI lo legge per i path);
    - se `exc` è dato, lo solleva (per testare la gestione di IntrusionDenied).
    """
    st = state if state is not None else _state()

    def _fake_run(self, target, *, max_intrusion=IntrusionLevel.READ_ONLY,
                  resume=False, accept_baseline=False):
        if capture is not None:
            capture.update(
                target=target, max_intrusion=max_intrusion,
                resume=resume, accept_baseline=accept_baseline,
            )
        self._run_dir = Path(run_dir)
        if exc is not None:
            raise exc
        return st

    monkeypatch.setattr(Orchestrator, "run", _fake_run, raising=True)


# ─── scan: cablaggio ────────────────────────────────────────────────────────

def test_scan_invokes_orchestrator_with_right_params(monkeypatch):
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 0, result.output
    assert cap["target"] == "g"
    # default read-only
    assert cap["max_intrusion"] == IntrusionLevel.READ_ONLY
    assert cap["resume"] is False
    assert cap["accept_baseline"] is False


def test_scan_maps_max_intrusion_string_to_enum(monkeypatch):
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g", "--max-intrusion", "probe"])
    assert result.exit_code == 0, result.output
    assert cap["max_intrusion"] == IntrusionLevel.PROBE


def test_scan_passes_resume_and_accept_baseline(monkeypatch):
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--resume", "--accept-baseline"])
    assert result.exit_code == 0, result.output
    assert cap["resume"] is True
    assert cap["accept_baseline"] is True


def test_scan_prints_summary(monkeypatch):
    _patch_run(monkeypatch, state=_state(new=2, by_severity={"high": 2}, posture=73.5),
               run_dir=Path("runs/g/20260614T000000Z"))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 0, result.output
    out = result.output
    # posture score, run_dir e nomi dei file generati nel sommario
    assert "73" in out
    assert "20260614T000000Z" in out
    assert "bastione.sarif" in out
    assert "report.md" in out


def test_scan_m1m2_flags_are_noop_in_m0(monkeypatch):
    # --no-fix e --i-own-this-its-staging sono accettati (no-op in M0 read-only)
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--no-fix", "--i-own-this-its-staging"])
    assert result.exit_code == 0, result.output


# ─── scan: incompatibilità e gate ───────────────────────────────────────────

def test_scan_unsafe_show_secrets_with_ci_is_incompatible(monkeypatch):
    _patch_run(monkeypatch)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--unsafe-show-secrets", "--ci"])
    assert result.exit_code != 0
    assert "unsafe-show-secrets" in result.output or "incompat" in result.output.lower()


def test_scan_intrusion_denied_is_clean_error_no_traceback(monkeypatch):
    _patch_run(monkeypatch, exc=IntrusionDenied(
        "Bastione non opera su 'production'. Punta lo staging."))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code != 0
    # messaggio chiaro presente, NESSUNO stacktrace
    assert "production" in result.output or "Bastione" in result.output
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_scan_precondition_denied_maps_to_exit_2(monkeypatch):
    # §22 (LOCKED): errore precondizione (incl. produzione bloccata) → exit 2,
    # NON 3 (3 è riservato all'ownership challenge fallito). In M0 read-only
    # l'unico IntrusionDenied raggiungibile è proprio questo (gate in LOAD).
    _patch_run(monkeypatch, exc=PreconditionDenied(
        "Bastione non opera su 'production'. Punta lo staging."))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 2, result.output
    assert "production" in result.output or "Bastione" in result.output
    assert "Traceback" not in result.output


def test_scan_ownership_challenge_denied_maps_to_exit_3(monkeypatch):
    # §22 (LOCKED): ownership challenge fallito → exit 3 (distinto dal 2 delle
    # precondizioni). Caso reale solo per run > read-only, ma il mapping CLI deve
    # restare corretto.
    _patch_run(monkeypatch, exc=IntrusionDenied(
        "Ownership challenge fallito (§7.1): pubblica il token."))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output


# ─── --fail-on / --ci (gate CI minimale §22) ────────────────────────────────

def test_scan_fail_on_high_with_high_finding_exits_1(monkeypatch):
    # un finding NEW ≥ soglia fa fallire il gate (§22).
    _patch_run(monkeypatch, state=_state(
        new=1, by_severity={"high": 1}, new_by_severity={"high": 1}))
    result = runner.invoke(app, ["scan", "--target", "g", "--fail-on", "high"])
    assert result.exit_code == 1, result.output


def test_scan_fail_on_high_below_threshold_exits_0(monkeypatch):
    _patch_run(monkeypatch, state=_state(
        new=1, by_severity={"low": 1}, new_by_severity={"low": 1}))
    result = runner.invoke(app, ["scan", "--target", "g", "--fail-on", "high"])
    assert result.exit_code == 0, result.output


def test_scan_ci_with_critical_finding_exits_1(monkeypatch):
    _patch_run(monkeypatch, state=_state(
        new=1, by_severity={"critical": 1}, new_by_severity={"critical": 1}))
    result = runner.invoke(app, ["scan", "--target", "g", "--ci"])
    assert result.exit_code == 1, result.output


def test_scan_ci_known_finding_above_threshold_exits_0(monkeypatch):
    # §22/§24 (LOCKED): il gate scatta SOLO sui NEW ≥ soglia. Un finding KNOWN
    # (già in baseline) ≥ soglia, senza alcun NEW, NON deve far fallire il gate:
    # in CI le baseline sono committate e i KNOWN sono lo scenario normale.
    _patch_run(monkeypatch, state=_state(
        new=0, by_severity={"critical": 1}, new_by_severity={}))
    result = runner.invoke(app, ["scan", "--target", "g", "--ci"])
    assert result.exit_code == 0, result.output


def test_scan_ci_drift_without_new_above_threshold_exits_1(monkeypatch):
    # §22 (LOCKED): exit 1 anche con ≥1 DRIFT, pure senza alcun NEW ≥ soglia.
    # Una regressione di posture (drift) deve bloccare il gate.
    _patch_run(monkeypatch, state=_state(new=0, drift=1, new_by_severity={}))
    result = runner.invoke(app, ["scan", "--target", "g", "--ci"])
    assert result.exit_code == 1, result.output


# ─── doctor ─────────────────────────────────────────────────────────────────

def test_doctor_lists_tools_with_which_monkeypatched(monkeypatch):
    installed = {"nuclei", "katana"}
    monkeypatch.setattr(
        cli_mod.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name in installed else None)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    out = result.output
    for tool in ("whatweb", "katana", "testssl.sh", "nuclei", "zap"):
        assert tool in out, f"{tool} non elencato da doctor"
    # httpx è importabile (dipendenza dichiarata) → presente
    assert "httpx" in out


# ─── list-modules / list-detectors ──────────────────────────────────────────

def test_list_modules_lists_real_modules(monkeypatch):
    result = runner.invoke(app, ["list-modules"])
    assert result.exit_code == 0, result.output
    out = result.output
    for name in ("supabase", "secrets", "headers", "cloudflare"):
        assert name in out, f"modulo {name} non elencato"


def test_list_detectors_lists_service_role(monkeypatch):
    result = runner.invoke(app, ["list-detectors"])
    assert result.exit_code == 0, result.output
    assert "SECRET_SERVICE_ROLE" in result.output
