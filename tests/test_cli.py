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
                  resume=False, accept_baseline=False, no_fix=False, fail_on=None):
        if capture is not None:
            capture.update(
                target=target, max_intrusion=max_intrusion,
                resume=resume, accept_baseline=accept_baseline, no_fix=no_fix,
                fail_on=fail_on,
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


def test_scan_m2_flag_is_noop_in_read_only(monkeypatch):
    # --i-own-this-its-staging è accettato anche in read-only (no-op lì: il gate
    # runtime non richiede ownership per read-only). Non blocca, non declassa.
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--i-own-this-its-staging"])
    assert result.exit_code == 0, result.output


# ─── §7/§25: --i-own-this-its-staging è REALE per --max-intrusion mutating ───

def test_scan_mutating_without_flag_is_exit_2(monkeypatch):
    # §7/§25: --max-intrusion mutating SENZA --i-own-this-its-staging (non
    # interattivo) → precondizione non soddisfatta → errore chiaro + exit 2.
    # Orchestrator.run NON deve nemmeno essere invocato (blocco a monte).
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--max-intrusion", "mutating"])
    assert result.exit_code == 2, result.output
    # messaggio chiaro che cita il flag richiesto, niente stacktrace
    assert "i-own-this-its-staging" in result.output
    assert "Traceback" not in result.output
    # il blocco è a monte: orch.run non è stato chiamato
    assert cap == {}


def test_scan_mutating_with_flag_proceeds(monkeypatch):
    # §7/§25: con il flag, mutating PROSEGUE: orch.run è invocato con MUTATING.
    # Il gate runtime (authorize/ownership) resta comunque l'autorità sul target.
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--max-intrusion", "mutating",
              "--i-own-this-its-staging"])
    assert result.exit_code == 0, result.output
    assert cap["max_intrusion"] == IntrusionLevel.MUTATING


def test_scan_probe_without_flag_proceeds(monkeypatch):
    # Il flag è richiesto SOLO per mutating: probe (e read-only) procedono senza.
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(
        app, ["scan", "--target", "g", "--max-intrusion", "probe"])
    assert result.exit_code == 0, result.output
    assert cap["max_intrusion"] == IntrusionLevel.PROBE


def test_scan_no_fix_is_propagated_to_orchestrator(monkeypatch):
    # --no-fix non è più un no-op (M1): viene propagato all'orchestratore, che
    # salta la fase REMEDIATE e non genera il bundle fix/.
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g", "--no-fix"])
    assert result.exit_code == 0, result.output
    assert cap["no_fix"] is True


def test_scan_default_no_fix_is_false(monkeypatch):
    # Senza --no-fix il flag arriva False all'orchestratore (remediation attiva).
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 0, result.output
    assert cap["no_fix"] is False


def test_scan_fail_on_threshold_is_passed_to_orchestrator(monkeypatch):
    # M2 step 3 (§19 LOCKED): la soglia risolta da --fail-on viene passata a
    # orch.run come Severity, così il trigger NOTIFY usa la STESSA soglia del gate.
    from bastione.enums import Severity
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g", "--fail-on", "medium"])
    assert result.exit_code == 0, result.output
    assert cap["fail_on"] == Severity.MEDIUM


def test_scan_without_fail_on_passes_none_threshold(monkeypatch):
    # Senza --fail-on la soglia passata a orch.run è None: il notify ricade sul
    # default del TOML (cfg.notify_min_severity, HIGH) — non sul gate CI.
    cap: dict = {}
    _patch_run(monkeypatch, capture=cap)
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 0, result.output
    assert cap["fail_on"] is None


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


# ─── verify (§18-bis.8) ─────────────────────────────────────────────────────

from bastione.baseline.diff import BaselineResult  # noqa: E402
from bastione.enums import Confidence, Severity, Status  # noqa: E402
from bastione.models import Finding, Location  # noqa: E402


def _vfinding(fid: str, *, rule_id: str, status: Status,
              severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_id=fid, module="supabase", rule_id=rule_id, title=f"{rule_id}",
        severity=severity, confidence=Confidence.FIRM, target="g",
        location=Location(endpoint="/rest/v1/x"), evidence="[REDACTED]",
        description="d", status=status,
    )


def _patch_verify_run(monkeypatch, *, result: BaselineResult | None = None,
                      capture: dict | None = None,
                      run_dir: Path = Path("runs/g/ts"),
                      exc: Exception | None = None):
    """Sostituisce Orchestrator.run con un fake che popola self._result (la
    BaselineResult con gli status per-finding che verify legge) e self._run_dir."""
    res = result if result is not None else BaselineResult()

    def _fake_run(self, target, *, max_intrusion=IntrusionLevel.READ_ONLY,
                  resume=False, accept_baseline=False, no_fix=False, fail_on=None):
        if capture is not None:
            capture.update(target=target, max_intrusion=max_intrusion,
                           no_fix=no_fix, accept_baseline=accept_baseline,
                           fail_on=fail_on)
        self._run_dir = Path(run_dir)
        self._result = res
        if exc is not None:
            raise exc
        return _state()

    monkeypatch.setattr(Orchestrator, "run", _fake_run, raising=True)


def test_verify_renders_table_with_correct_states(monkeypatch):
    # Un FIXED, un NEW→new, un KNOWN→still_open (§18-bis.8).
    result = BaselineResult(
        findings=[
            _vfinding("new111", rule_id="MISSING_CSP", status=Status.NEW),
            _vfinding("known22", rule_id="RLS_DISABLED", status=Status.KNOWN),
        ],
        fixed=[_vfinding("fixed33", rule_id="POSTURE_HSTS", status=Status.FIXED)],
    )
    _patch_verify_run(monkeypatch, result=result)
    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    text = out.output
    # gli id compaiono con lo stato mappato
    assert "new111" in text and "new" in text
    assert "known22" in text and "still_open" in text
    assert "fixed33" in text and "FIXED" in text


def test_verify_runs_orchestrator_read_only(monkeypatch):
    cap: dict = {}
    _patch_verify_run(monkeypatch, capture=cap)
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 0, out.output
    assert cap["target"] == "g"
    # verify è una ri-scansione READ_ONLY del target (§18-bis.8)
    assert cap["max_intrusion"] == IntrusionLevel.READ_ONLY
    # verify non genera bundle: --no-fix attivo per una ri-scansione di sola lettura
    assert cap["no_fix"] is True


def test_verify_precondition_denied_maps_to_exit_2(monkeypatch):
    _patch_verify_run(monkeypatch, exc=PreconditionDenied(
        "Bastione non opera su 'production'."))
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 2, out.output
    assert "Traceback" not in out.output


def test_verify_intrusion_denied_maps_to_exit_3(monkeypatch):
    _patch_verify_run(monkeypatch, exc=IntrusionDenied("Ownership challenge fallito."))
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 3, out.output
    assert "Traceback" not in out.output


def test_verify_missing_target_maps_to_exit_4(monkeypatch):
    _patch_verify_run(monkeypatch, exc=FileNotFoundError("targets/g.toml"))
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 4, out.output
    assert "Traceback" not in out.output


def test_verify_no_findings_is_clean(monkeypatch):
    # Nessun finding e nessun fixed: tutto a posto, exit 0, niente crash.
    _patch_verify_run(monkeypatch, result=BaselineResult())
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 0, out.output


def test_verify_segnala_precondizione_baseline_se_solo_new_e_zero_fixed(monkeypatch):
    """REGRESSIONE (§18-bis.8): nel flusso senza baseline accettata, un finding
    corretto sparisce e quelli ancora aperti compaiono come `new`, mai FIXED. La
    verify deve SEGNALARE la precondizione (serve --accept-baseline) invece di lasciar
    credere che '0 FIXED' significhi 'fix falliti'."""
    result = BaselineResult(
        findings=[_vfinding("n1", rule_id="RLS_DISABLED", status=Status.NEW)],
        fixed=[],
    )
    _patch_verify_run(monkeypatch, result=result)
    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    assert "accept-baseline" in out.output


def test_verify_non_segnala_precondizione_quando_ci_sono_fixed(monkeypatch):
    """Se almeno un finding risulta FIXED, il loop sta funzionando: niente nota sulla
    precondizione (evitiamo rumore quando la baseline è chiaramente stata accettata)."""
    result = BaselineResult(
        findings=[_vfinding("n1", rule_id="RLS_DISABLED", status=Status.NEW)],
        fixed=[_vfinding("f1", rule_id="POSTURE_HSTS", status=Status.FIXED)],
    )
    _patch_verify_run(monkeypatch, result=result)
    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    assert "accept-baseline" not in out.output


def test_verify_help_documenta_precondizione_accept_baseline():
    """L'help di `verify` documenta esplicitamente la precondizione del loop: FIXED si
    misura contro la baseline salvata (serve `scan --accept-baseline` prima)."""
    out = runner.invoke(app, ["verify", "--help"], color=False)
    assert out.exit_code == 0, out.output
    assert "accept-baseline" in out.output
