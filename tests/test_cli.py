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
  - doctor elenca installato/assente con shutil.which monkeypatchato e, per i tool
    con policy (R4), versione + stato via toolcheck (`_read_version` monkeypatchato);
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
                  resume=False, accept_baseline=False, no_fix=False, notify=True,
                  fail_on=None):
        if capture is not None:
            capture.update(
                target=target, max_intrusion=max_intrusion,
                resume=resume, accept_baseline=accept_baseline, no_fix=no_fix,
                notify=notify, fail_on=fail_on,
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


def test_scan_missing_target_maps_to_exit_4(monkeypatch):
    # §22 (LOCKED): config target assente → exit 4 (errore esecuzione/interno).
    _patch_run(monkeypatch, exc=FileNotFoundError("targets/g.toml"))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 4, result.output
    assert "Traceback" not in result.output


def test_scan_unexpected_internal_error_maps_to_exit_4_no_traceback(monkeypatch):
    # §22/§25 (LOCKED): un'eccezione INATTESA durante la run (bug interno, tool
    # esterno esploso) NON deve mostrare uno stacktrace all'utente — messaggio
    # chiaro + exit 4 (errore esecuzione tool/interno). Il catch-all è l'ULTIMO
    # ramo, dopo Precondition/Intrusion/FileNotFound, così non scavalca i mapping
    # specifici 2/3/4-config.
    _patch_run(monkeypatch, exc=RuntimeError("crash inatteso nel motore"))
    result = runner.invoke(app, ["scan", "--target", "g"])
    assert result.exit_code == 4, result.output
    # niente stacktrace in faccia all'utente (§25)
    assert "Traceback" not in result.output
    # messaggio chiaro presente; l'eccezione non risale come crash non gestito
    assert result.exception is None or isinstance(result.exception, SystemExit)


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
    # doctor interroga anche la versione dei tool con policy (R4, nuclei qui): il
    # confine I/O è monkeypatchato → nessun subprocess reale, nessuna dipendenza
    # dai tool davvero installati sulla macchina.
    import bastione.toolcheck as _tc
    monkeypatch.setattr(_tc, "_read_version", lambda name: None)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    out = result.output
    for tool in ("whatweb", "katana", "testssl.sh", "nuclei", "zap"):
        assert tool in out, f"{tool} non elencato da doctor"
    # httpx è importabile (dipendenza dichiarata) → presente
    assert "httpx" in out


def test_doctor_lists_semgrep_and_trivy(monkeypatch):
    # T5: doctor elenca anche i due tool white-box (§14), onesto installato/assente.
    # semgrep installato, trivy assente → nessun crash, entrambi elencati.
    installed = {"semgrep"}
    monkeypatch.setattr(
        cli_mod.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name in installed else None)
    result = runner.invoke(app, ["doctor"], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "semgrep" in out, "semgrep non elencato da doctor"
    assert "trivy" in out, "trivy non elencato da doctor"


# ─── doctor: versione + stato via toolcheck (M5 / R4) ───────────────────────

def _pin_console_width(monkeypatch, width: int = 200) -> None:
    """Console rich a larghezza fissa: la tabella di `doctor` non dipende da COLUMNS
    né dal terminale, quindi i motivi di blocco non vengono spezzati dal wrap."""
    from rich.console import Console
    monkeypatch.setattr(cli_mod, "console", Console(width=width))


def test_doctor_shows_version_and_status_for_policied_tools(monkeypatch):
    import bastione.cli as cli
    import bastione.toolcheck as tc
    from typer.testing import CliRunner
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(tc, "_read_version",
                        lambda n: "Version: 0.72.0" if n == "trivy" else "v3.10.0")
    res = CliRunner().invoke(cli.app, ["doctor"])
    assert res.exit_code == 0
    assert "0.72" in res.stdout                      # versione trivy mostrata


def test_doctor_zap_name_fixed(monkeypatch):
    import bastione.cli as cli
    # il vecchio nome "zap" non è più sondato…
    assert "zap" not in cli._EXTERNAL_TOOLS
    # …e il binario reale è referenziato (niente più mismatch doctor↔modulo)
    assert "zap-baseline.py" in cli._EXTERNAL_TOOLS
    # doctor e modulo zap controllano lo STESSO nome (nessuna deriva futura)
    from bastione.modules.zap.module import _ZAP_BINARY
    assert _ZAP_BINARY in cli._EXTERNAL_TOOLS


def test_doctor_shows_block_reason_for_forbidden_or_unreadable_version(monkeypatch):
    # R4 fail-closed: versione VIETATA (CVE nota) o illeggibile → doctor mostra il
    # motivo del blocco e NON crasha (è un comando diagnostico, exit 0).
    import bastione.toolcheck as tc
    _pin_console_width(monkeypatch)
    monkeypatch.setattr(cli_mod.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(tc, "_read_version",
                        lambda n: "Version: 0.69.4" if n == "trivy" else None)
    res = runner.invoke(app, ["doctor"], color=False)
    assert res.exit_code == 0, res.output
    out = res.output
    assert "0.69.4" in out and "VIETATA" in out      # trivy: versione vietata + motivo
    assert "fail-closed" in out                      # nuclei: versione non leggibile
    assert "ammesso" not in out                      # nessun tool con policy è ammesso


def test_doctor_does_not_probe_version_of_missing_tools(monkeypatch):
    # Tool assente → "assente", nessuna lettura di versione (nessun subprocess), no crash.
    import bastione.toolcheck as tc

    def _boom(name):
        raise AssertionError(f"_read_version({name!r}) chiamata per un tool assente")

    _pin_console_width(monkeypatch)
    monkeypatch.setattr(cli_mod.shutil, "which", lambda n: None)
    monkeypatch.setattr(tc, "_read_version", _boom)
    res = runner.invoke(app, ["doctor"], color=False)
    assert res.exit_code == 0, res.output
    assert "trivy" in res.output and "nuclei" in res.output
    assert "assente" in res.output


# ─── list-modules / list-detectors ──────────────────────────────────────────

def test_list_modules_lists_real_modules(monkeypatch):
    result = runner.invoke(app, ["list-modules"])
    assert result.exit_code == 0, result.output
    out = result.output
    for name in ("supabase", "secrets", "headers", "cloudflare"):
        assert name in out, f"modulo {name} non elencato"


def test_list_modules_lists_semgrep_and_trivy_as_probe(monkeypatch):
    # T5: i due moduli white-box (§14) si auto-registrano via _ensure_modules_loaded
    # e compaiono in list-modules con max_intrusion=PROBE.
    result = runner.invoke(app, ["list-modules"], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "semgrep" in out, "modulo semgrep non elencato"
    assert "trivy" in out, "modulo trivy non elencato"
    # entrambi sono PROBE (§14): la stringa 'probe' deve comparire nella tabella.
    assert "probe" in out


def test_list_modules_semgrep_trivy_registry_probe():
    # Verifica diretta del REGISTRY: semgrep/trivy registrati a PROBE (§14), senza
    # passare dal rendering tabellare (robusto a eventuali wrap di rich).
    from bastione.modules.base import REGISTRY
    from bastione.enums import IntrusionLevel as _IL

    cli_mod._ensure_modules_loaded()
    assert "semgrep" in REGISTRY and "trivy" in REGISTRY
    assert REGISTRY["semgrep"].max_intrusion is _IL.PROBE
    assert REGISTRY["trivy"].max_intrusion is _IL.PROBE


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
                  resume=False, accept_baseline=False, no_fix=False, notify=True,
                  fail_on=None):
        if capture is not None:
            capture.update(target=target, max_intrusion=max_intrusion,
                           no_fix=no_fix, accept_baseline=accept_baseline,
                           notify=notify, fail_on=fail_on)
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
    # contratto outward-facing (§7/§19): verify passa notify=False — NOTIFY soppressa.
    assert cap["notify"] is False


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


def test_verify_unexpected_internal_error_maps_to_exit_4_no_traceback(monkeypatch):
    # §22/§25 (LOCKED): un'eccezione INATTESA in `verify` → exit 4, niente
    # stacktrace (catch-all finale, come per `scan`).
    _patch_verify_run(monkeypatch, exc=RuntimeError("crash inatteso in verify"))
    out = runner.invoke(app, ["verify", "--target", "g"])
    assert out.exit_code == 4, out.output
    assert "Traceback" not in out.output
    assert out.exception is None or isinstance(out.exception, SystemExit)


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


# ─── REGRESSIONE: verify/export-defectdojo NON emettono notifiche (§7/§19) ────
#
# Difetto confermato (area integration): _rescan_read_only invocava orch.run, che
# esegue l'INTERA pipeline — NOTIFY inclusa. La precondizione NOTIFY non dipende da
# max_intrusion né da no_fix: su un target con [notify].channel='telegram' e ≥1
# finding NEW ≥ soglia, `verify`/`export-defectdojo` facevano partire un POST
# Telegram REALE, contraddicendo il loro contratto "nessuna azione outward-facing".
# I test della CLI non lo coglievano perché Orchestrator.run era interamente fakeato
# (NOTIFY mai raggiunta). Questi due test girano la PIPELINE REALE (offline) e
# falliscono se notify.dispatch viene invocato anche una sola volta.

import bastione.orchestrator as _cli_orch_mod  # noqa: E402
from bastione.models import Fingerprint as _Fingerprint  # noqa: E402

_STAGING_NOTIFY_TOML = (
    'name = "g"\n'
    'base_url = "https://staging.example"\n'
    'environment = "staging"\n'
    'ownership = "owned"\n'
    '\n[notify]\nchannel = "telegram"\n'
)


class _NewHighStubModule:
    """Modulo finto OFFLINE che emette UN finding NEW HIGH (≥ soglia default HIGH):
    senza la soppressione, basterebbe a far scattare il trigger NOTIFY (§19)."""

    name = "supabase"
    max_intrusion = IntrusionLevel.READ_ONLY

    def run(self, ctx):
        finding = Finding(
            finding_id="", module="supabase", rule_id="RLS_DISABLED",
            title="RLS disabilitato", severity=Severity.HIGH,
            confidence=Confidence.FIRM, target="g",
            location=Location(endpoint="/rest/v1/clienti", url="https://staging.example"),
            evidence="[REDACTED]", description="finding di test",
        )
        return BaselineResult(findings=[finding], posture_checks=[])


def _wire_real_rescan_pipeline(monkeypatch, tmp_path):
    """Cabla la PIPELINE REALE (offline) sotto `_rescan_read_only`:

    - scrive un target staging con [notify].channel='telegram' in targets/;
    - fa sì che la `Orchestrator()` costruita dentro _rescan_read_only punti alle
      dir temporanee (targets/runs/baselines) — così la run reale non tocca il repo;
    - sostituisce il recon e la selezione del piano con un fake offline che emette
      UN finding NEW HIGH (il trigger NOTIFY scatterebbe, se non soppresso).

    Ritorna nulla: il chiamante installa la guardia su notify.dispatch."""
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()
    (targets_dir / "g.toml").write_text(_STAGING_NOTIFY_TOML, encoding="utf-8")
    runs_root = tmp_path / "runs"
    baselines_root = tmp_path / "baselines"

    # La classe reale: la usiamo sia per la factory (path temporanei) sia per
    # patchare _plan_phase. La factory NON deve sostituire la classe prima di
    # patchare il metodo, altrimenti il patch cadrebbe sulla factory (una funzione).
    real_orch_cls = cli_mod.Orchestrator

    # Piano offline (sulla CLASSE reale): il solo stub che emette il finding NEW HIGH.
    def _fake_plan(self):
        self._plan = [_NewHighStubModule()]

    monkeypatch.setattr(real_orch_cls, "_plan_phase", _fake_plan, raising=True)

    # Recon offline: nessuna rete, scrive fingerprint.json nella run_dir.
    def _fake_fp(target, run_dir=None):
        fp = _Fingerprint(target=target, resolved_urls=["https://staging.example/"])
        if run_dir is not None:
            run_dir = Path(run_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "fingerprint.json").write_text(
                fp.model_dump_json(indent=2), encoding="utf-8")
        return fp

    monkeypatch.setattr(_cli_orch_mod, "fingerprint", _fake_fp)

    # La CLI costruisce `Orchestrator()` senza argomenti: redirigiamo i path verso
    # le dir temporanee patchando la factory usata dalla CLI, preservando la run reale
    # (la factory istanzia la classe reale, con _plan_phase già patchato sopra).
    def _orch_factory(*args, **kwargs):
        return real_orch_cls(
            targets_dir=targets_dir, runs_root=runs_root,
            baselines_root=baselines_root)

    monkeypatch.setattr(cli_mod, "Orchestrator", _orch_factory)


def test_verify_real_pipeline_never_dispatches_notify(monkeypatch, tmp_path):
    """REGRESSIONE (§7/§19): `verify` esegue la pipeline reale su un target con
    [notify].channel='telegram' e UN finding NEW HIGH (trigger NOTIFY soddisfatto).
    `notify.dispatch` è armato per esplodere se invocato: NON deve mai partire —
    `verify` è dichiarato READ_ONLY e senza azioni outward-facing."""
    _wire_real_rescan_pipeline(monkeypatch, tmp_path)

    def _boom_dispatch(cfg, summary):
        raise AssertionError(
            "notify.dispatch invocato da `verify`: azione outward-facing vietata (§7/§19)")

    monkeypatch.setattr(_cli_orch_mod.notify, "dispatch", _boom_dispatch, raising=True)

    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    # la run reale ha emesso il finding (NEW) ma NON ha notificato.
    assert "RLS_DISABLED" in out.output


def test_verify_real_pipeline_marks_notify_skipped(monkeypatch, tmp_path):
    """Controprova diretta sullo stato: la fase NOTIFY è SALTATA (non completata) in
    una ri-scansione di sola verifica, malgrado il trigger sarebbe soddisfatto."""
    _wire_real_rescan_pipeline(monkeypatch, tmp_path)
    # dispatch innocuo: qui guardiamo lo stato della run, non la guardia anti-rete.
    monkeypatch.setattr(
        _cli_orch_mod.notify, "dispatch", lambda cfg, summary: None, raising=True)

    captured: dict = {}
    real_rescan = cli_mod._rescan

    def _capturing_rescan(target, *, max_intrusion):
        orch = real_rescan(target, max_intrusion=max_intrusion)
        captured["state"] = RunState.load(orch._run_dir / "state.json")
        return orch

    # S16: verify passa per `_rescan` (livello configurabile), non più per il solo
    # wrapper READ_ONLY usato da export-defectdojo.
    monkeypatch.setattr(cli_mod, "_rescan", _capturing_rescan)

    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    state = captured["state"]
    # il trigger sarebbe soddisfatto (NEW HIGH), ma NOTIFY è soppressa → skipped.
    assert state.counts["new_by_severity"]["high"] == 1
    assert "NOTIFY" in state.phases_skipped
    assert "NOTIFY" not in state.phases_completed


def test_export_defectdojo_real_pipeline_never_dispatches_notify(monkeypatch, tmp_path):
    """REGRESSIONE (§7/§19): come sopra ma per `export-defectdojo`, che condivide
    `_rescan_read_only`. Su un target con telegram + NEW HIGH, `notify.dispatch` non
    deve MAI partire. Env DefectDojo non configurato → il push è gated/skip (nessuna
    rete): l'unica azione outward-facing possibile sarebbe proprio la notifica."""
    _wire_real_rescan_pipeline(monkeypatch, tmp_path)
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_TOKEN", raising=False)

    def _boom_dispatch(cfg, summary):
        raise AssertionError(
            "notify.dispatch invocato da `export-defectdojo`: azione outward-facing "
            "vietata (§7/§19)")

    monkeypatch.setattr(_cli_orch_mod.notify, "dispatch", _boom_dispatch, raising=True)

    out = runner.invoke(app, ["export-defectdojo", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    # il push è gated/skip (nessun env) e la notifica NON è partita.
    assert "skipped" in out.output


# ─── scan-all (portfolio mode §21) ──────────────────────────────────────────

from bastione.portfolio import PortfolioConfig, PortfolioRow  # noqa: E402


def test_scan_all_invokes_run_portfolio(monkeypatch, tmp_path):
    # `scan-all` carica il portfolio e chiama run_portfolio; stampa la tabella e
    # NON esplode. Monkeypatchiamo load_portfolio + run_portfolio (offline).
    p = tmp_path / "portfolio.toml"
    p.write_text('targets = ["gestionale", "numely"]\n', encoding="utf-8")

    cap: dict = {}

    def _fake_load(path):
        cap["load_path"] = str(path)
        return PortfolioConfig(targets=["gestionale", "numely"], defaults={})

    def _fake_run(config, **kwargs):
        cap["config"] = config
        cap["kwargs"] = kwargs
        rows = [
            PortfolioRow(target="gestionale", score=73.5, critical_open=1, drift=0,
                         new=2, known=0, fixed=0),
            PortfolioRow(target="numely", score=91.0, critical_open=0, drift=2,
                         new=0, known=1, fixed=0),
        ]
        return ("# Portfolio report\n", rows)

    monkeypatch.setattr(cli_mod, "load_portfolio", _fake_load)
    monkeypatch.setattr(cli_mod, "run_portfolio", _fake_run)

    result = runner.invoke(app, ["scan-all", "--portfolio", str(p)], color=False)
    assert result.exit_code == 0, result.output
    # ha caricato il portfolio dal path passato e invocato run_portfolio.
    assert cap["load_path"] == str(p)
    assert cap["config"].targets == ["gestionale", "numely"]
    # la tabella di postura del portfolio è stampata (score/#CRITICAL/#DRIFT visibili).
    out = result.output
    assert "gestionale" in out and "numely" in out
    assert "73" in out and "91" in out


def test_scan_all_default_portfolio_path(monkeypatch):
    # Senza --portfolio il default è "portfolio.toml".
    cap: dict = {}

    def _fake_load(path):
        cap["load_path"] = str(path)
        return PortfolioConfig(targets=[], defaults={})

    monkeypatch.setattr(cli_mod, "load_portfolio", _fake_load)
    monkeypatch.setattr(
        cli_mod, "run_portfolio",
        lambda config, **kw: ("# vuoto\n", []))

    result = runner.invoke(app, ["scan-all"], color=False)
    assert result.exit_code == 0, result.output
    assert cap["load_path"] == "portfolio.toml"


def test_scan_all_missing_portfolio_is_clean_error(monkeypatch):
    # --portfolio inesistente → errore chiaro (niente stacktrace), exit != 0.
    def _fake_load(path):
        raise FileNotFoundError(f"Portfolio non trovato: '{path}'.")

    monkeypatch.setattr(cli_mod, "load_portfolio", _fake_load)

    result = runner.invoke(
        app, ["scan-all", "--portfolio", "non-esiste.toml"], color=False)
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    # messaggio chiaro che cita il portfolio mancante.
    assert "portfolio" in result.output.lower() or "non trovato" in result.output.lower()


def test_scan_all_reads_only_does_not_construct_real_orchestrator(monkeypatch):
    # GUARDRAIL: scan-all passa una factory a run_portfolio; verifichiamo che la
    # factory costruisca un Orchestrator (non lo invoca qui — run_portfolio è fake).
    captured: dict = {}

    monkeypatch.setattr(
        cli_mod, "load_portfolio",
        lambda path: PortfolioConfig(targets=["a"], defaults={}))

    def _fake_run(config, *, orch_factory, **kwargs):
        captured["factory"] = orch_factory
        captured["kwargs"] = kwargs
        # invochiamo la factory per assicurarci che produca un orchestratore valido
        orch = orch_factory()
        captured["orch"] = orch
        return ("# report\n", [])

    monkeypatch.setattr(cli_mod, "run_portfolio", _fake_run)

    result = runner.invoke(app, ["scan-all"], color=False)
    assert result.exit_code == 0, result.output
    # la factory ha prodotto un Orchestrator (duck typing su .run).
    assert hasattr(captured["orch"], "run")
    # scan-all chiede a run_portfolio di scrivere il report consolidato.
    assert captured["kwargs"].get("write") is True


def test_scan_all_error_rows_are_shown(monkeypatch):
    # Una riga d'errore nel portfolio viene mostrata nella tabella (resilienza §21).
    monkeypatch.setattr(
        cli_mod, "load_portfolio",
        lambda path: PortfolioConfig(targets=["ok", "bad"], defaults={}))

    def _fake_run(config, **kwargs):
        rows = [
            PortfolioRow(target="ok", score=88.0, critical_open=0, drift=0,
                         new=0, known=0, fixed=0),
            PortfolioRow.error_row("bad", "errore interno: boom"),
        ]
        return ("# report\n", rows)

    monkeypatch.setattr(cli_mod, "run_portfolio", _fake_run)

    result = runner.invoke(app, ["scan-all"], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "bad" in out
    # la riga d'errore è visibile come tale.
    assert "error" in out.lower() or "errore" in out.lower()


# ─── surface (attack-surface inventory & diff, M3) ──────────────────────────

from bastione.models import Fingerprint, SurfaceSnapshot  # noqa: E402


def _fp(target: str = "g", *, tables=None, endpoints=None, urls=None) -> Fingerprint:
    return Fingerprint(
        target=target,
        resolved_urls=urls if urls is not None else ["https://g.example/"],
        discovered_tables=tables if tables is not None else [],
        endpoints=endpoints if endpoints is not None else [],
    )


def test_surface_show_prints_baseline_snapshot(monkeypatch, tmp_path):
    # --show stampa lo snapshot baseline corrente (M3): scriviamo una baseline reale
    # in una dir temporanea via --baselines-dir e verifichiamo che venga stampata.
    snap = SurfaceSnapshot.build(
        target="g", tables=["public.users"], endpoints=["/rest/v1/users"],
        urls=["https://g.example/"])
    cli_mod.save_surface_baseline(tmp_path / "g.surface.json", snap)

    result = runner.invoke(
        app, ["surface", "--target", "g", "--show",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert snap.snapshot_id in out
    assert "public.users" in out
    assert "/rest/v1/users" in out


def test_surface_show_no_baseline_is_clean(monkeypatch, tmp_path):
    # --show senza baseline → nota amichevole, exit 0 (non è un errore).
    result = runner.invoke(
        app, ["surface", "--target", "g", "--show",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    assert "Nessuna surface baseline" in result.output or "snap" in result.output.lower()


def test_surface_diff_shows_added_without_saving(monkeypatch, tmp_path):
    # --diff costruisce lo snapshot dal fingerprint corrente e mostra il delta vs
    # baseline SENZA salvare. Monkeypatchiamo il caricamento del fingerprint (offline)
    # e usiamo una baselines-dir vuota → tutta la superficie è 'added'.
    monkeypatch.setattr(
        cli_mod, "_latest_fingerprint",
        lambda target: _fp(target, tables=["public.orders"],
                            endpoints=["/rest/v1/orders"]))

    result = runner.invoke(
        app, ["surface", "--target", "g", "--diff",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "public.orders" in out
    assert "added" in out
    # --diff NON salva: nessun file baseline creato.
    assert not (tmp_path / "g.surface.json").exists()


def test_surface_diff_against_existing_baseline_shows_delta(monkeypatch, tmp_path):
    # Baseline con una tabella, fingerprint corrente con una tabella diversa →
    # added + removed deterministici.
    old = SurfaceSnapshot.build(target="g", tables=["public.old"], endpoints=[], urls=[])
    cli_mod.save_surface_baseline(tmp_path / "g.surface.json", old)
    monkeypatch.setattr(
        cli_mod, "_latest_fingerprint",
        lambda target: _fp(target, tables=["public.new"]))

    result = runner.invoke(
        app, ["surface", "--target", "g", "--diff",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "public.new" in out and "added" in out
    assert "public.old" in out and "removed" in out


def test_surface_snap_saves_baseline(monkeypatch, tmp_path):
    # --snap salva il nuovo snapshot come baseline e mostra il diff col precedente.
    monkeypatch.setattr(
        cli_mod, "_latest_fingerprint",
        lambda target: _fp(target, tables=["public.users"]))

    path = tmp_path / "g.surface.json"
    assert not path.exists()
    result = runner.invoke(
        app, ["surface", "--target", "g", "--snap",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    # il file baseline è stato scritto e contiene la superficie corrente.
    assert path.exists()
    saved = cli_mod.load_surface_baseline(path)
    assert saved is not None
    assert saved.tables == ["public.users"]


def test_surface_mutually_exclusive_options_exit_2(monkeypatch, tmp_path):
    # --snap/--diff/--show sono mutuamente esclusive → exit 2, niente stacktrace.
    result = runner.invoke(
        app, ["surface", "--target", "g", "--snap", "--diff",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_surface_missing_fingerprint_is_honest_error(monkeypatch, tmp_path):
    # --diff senza alcun fingerprint su disco → errore ONESTO + exit 4, niente
    # stacktrace (§25). Usiamo una runs-root vuota (DEFAULT_RUNS_ROOT non ha 'g').
    monkeypatch.setattr(cli_mod, "DEFAULT_RUNS_ROOT", tmp_path / "runs")
    result = runner.invoke(
        app, ["surface", "--target", "g", "--diff",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 4, result.output
    assert "Traceback" not in result.output
    assert "fingerprint" in result.output.lower()


def test_surface_reads_latest_fingerprint_from_runs(monkeypatch, tmp_path):
    # _latest_fingerprint legge l'ULTIMA run con fingerprint.json (READ-ONLY: solo
    # artefatto locale). Scriviamo due run e verifichiamo che prenda la più recente.
    runs = tmp_path / "runs" / "g"
    older = runs / "20260101T000000Z"
    newer = runs / "20260601T000000Z"
    for d, table in ((older, "public.old"), (newer, "public.new")):
        d.mkdir(parents=True)
        fp = _fp("g", tables=[table])
        (d / cli_mod.FINGERPRINT_FILENAME).write_text(
            fp.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(cli_mod, "DEFAULT_RUNS_ROOT", tmp_path / "runs")

    result = runner.invoke(
        app, ["surface", "--target", "g", "--diff",
              "--baselines-dir", str(tmp_path)], color=False)
    assert result.exit_code == 0, result.output
    # ha usato il fingerprint della run più recente.
    assert "public.new" in result.output
    assert "public.old" not in result.output


# ─── export-defectdojo (§T4) ────────────────────────────────────────────────

def _patch_export_run(monkeypatch, *, findings=None, run_dir: Path,
                      exc: Exception | None = None):
    """Sostituisce Orchestrator.run con un fake che popola self._result (con i
    finding da esportare) e self._run_dir, come fa il ri-scan reale."""
    res = BaselineResult(findings=list(findings) if findings else [])

    def _fake_run(self, target, *, max_intrusion=IntrusionLevel.READ_ONLY,
                  resume=False, accept_baseline=False, no_fix=False, notify=True,
                  fail_on=None):
        self._run_dir = Path(run_dir)
        self._result = res
        if exc is not None:
            raise exc
        return _state()

    monkeypatch.setattr(Orchestrator, "run", _fake_run, raising=True)


def test_export_defectdojo_writes_file_and_skips_without_env(monkeypatch, tmp_path):
    # T5/§T4: export-defectdojo ri-scansiona (READ_ONLY), scrive il file di export e,
    # senza env DefectDojo, riporta 'skipped' SENZA toccare la rete.
    import json as _json

    run_dir = tmp_path / "runs" / "g" / "ts"
    finding = _vfinding("f1", rule_id="RLS_DISABLED", status=Status.NEW)
    _patch_export_run(monkeypatch, findings=[finding], run_dir=run_dir)

    # env DefectDojo NON configurato → push gated skip.
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_TOKEN", raising=False)
    # guardia anti-rete: se _post_defectdojo venisse chiamato, fallirebbe il test.
    import bastione.normalize.defectdojo as dd_mod

    def _boom(url, token, payload):
        raise AssertionError("rete reale chiamata: il push doveva essere gated/skip")

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom)

    result = runner.invoke(app, ["export-defectdojo", "--target", "g"], color=False)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "skipped" in out
    # il file di export è stato scritto nella run dir.
    export_file = run_dir / cli_mod.DEFECTDOJO_FILENAME
    assert export_file.exists()
    payload = _json.loads(export_file.read_text(encoding="utf-8"))
    assert isinstance(payload.get("findings"), list)
    assert len(payload["findings"]) == 1
    # guardrail P8: nessuna evidence nel payload esportato.
    assert "evidence" not in payload["findings"][0]
    assert "[REDACTED]" not in export_file.read_text(encoding="utf-8")


def test_export_defectdojo_pushed_when_env_configured(monkeypatch, tmp_path):
    # Con env configurato e _post_defectdojo monkeypatchato (OFFLINE), il push
    # risulta 'pushed' senza toccare la rete reale.
    run_dir = tmp_path / "runs" / "g" / "ts"
    finding = _vfinding("f1", rule_id="RLS_DISABLED", status=Status.NEW)
    _patch_export_run(monkeypatch, findings=[finding], run_dir=run_dir)

    monkeypatch.setenv("BASTIONE_DEFECTDOJO_URL", "https://dojo.example")
    monkeypatch.setenv("BASTIONE_DEFECTDOJO_TOKEN", "tok")
    import bastione.normalize.defectdojo as dd_mod
    monkeypatch.setattr(dd_mod, "_post_defectdojo", lambda url, token, payload: 201)

    result = runner.invoke(app, ["export-defectdojo", "--target", "g"], color=False)
    assert result.exit_code == 0, result.output
    assert "pushed" in result.output


def test_export_defectdojo_precondition_denied_exit_2(monkeypatch, tmp_path):
    # Gli errori del gate sono mappati come scan/verify (precondizione → exit 2).
    run_dir = tmp_path / "runs" / "g" / "ts"
    _patch_export_run(monkeypatch, run_dir=run_dir,
                      exc=PreconditionDenied("Bastione non opera su 'production'."))
    result = runner.invoke(app, ["export-defectdojo", "--target", "g"], color=False)
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_export_defectdojo_runs_read_only(monkeypatch, tmp_path):
    # export-defectdojo usa lo STESSO meccanismo di verify: ri-scan READ_ONLY,
    # --no-fix (nessun bundle). Catturiamo i parametri passati a orch.run.
    run_dir = tmp_path / "runs" / "g" / "ts"
    cap: dict = {}

    def _fake_run(self, target, *, max_intrusion=IntrusionLevel.READ_ONLY,
                  resume=False, accept_baseline=False, no_fix=False, notify=True,
                  fail_on=None):
        cap.update(target=target, max_intrusion=max_intrusion, no_fix=no_fix,
                   notify=notify)
        self._run_dir = Path(run_dir)
        self._result = BaselineResult(findings=[])
        return _state()

    monkeypatch.setattr(Orchestrator, "run", _fake_run, raising=True)
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_URL", raising=False)
    monkeypatch.delenv("BASTIONE_DEFECTDOJO_TOKEN", raising=False)

    result = runner.invoke(app, ["export-defectdojo", "--target", "g"], color=False)
    assert result.exit_code == 0, result.output
    assert cap["target"] == "g"
    assert cap["max_intrusion"] == IntrusionLevel.READ_ONLY
    assert cap["no_fix"] is True
    # contratto outward-facing (§7/§19): export-defectdojo passa notify=False.
    assert cap["notify"] is False


# ─── S16: verify al livello giusto + finding NON RI-VERIFICATI (R6) ─────────

def test_verify_accepts_max_intrusion_probe(monkeypatch):
    # Storage/RPC/GraphQL sono PROBE: `verify` deve poterli ri-controllare davvero.
    cap: dict = {}
    _patch_verify_run(monkeypatch, capture=cap)
    out = runner.invoke(app, ["verify", "--target", "g", "--max-intrusion", "probe"])
    assert out.exit_code == 0, out.output
    assert cap["max_intrusion"] == IntrusionLevel.PROBE
    assert cap["no_fix"] is True and cap["notify"] is False


def test_verify_mutating_requires_explicit_staging_confirmation(monkeypatch):
    cap: dict = {}
    _patch_verify_run(monkeypatch, capture=cap)
    out = runner.invoke(app, ["verify", "--target", "g", "--max-intrusion", "mutating"])
    assert out.exit_code == 2, out.output
    assert cap == {}                              # nessuna run partita
    out = runner.invoke(app, ["verify", "--target", "g", "--max-intrusion", "mutating",
                              "--i-own-this-its-staging"])
    assert out.exit_code == 0, out.output
    assert cap["max_intrusion"] == IntrusionLevel.MUTATING


def test_verify_lists_not_reverified_as_open_never_fixed(monkeypatch):
    shell = _vfinding("nrv444", rule_id="STORAGE_PUBLIC_LISTABLE", status=Status.KNOWN,
                      severity=Severity.INFO)
    result = BaselineResult(not_reverified=[shell])
    _patch_verify_run(monkeypatch, result=result)
    out = runner.invoke(app, ["verify", "--target", "g"], color=False)
    assert out.exit_code == 0, out.output
    text = out.output
    assert "nrv444" in text and "not_reverified" in text
    assert "0 FIXED" in text
    assert "--max-intrusion" in text              # indica come ri-verificarli
    assert "Nessun finding" not in text           # mai "target pulito" se restano dubbi


def test_scan_summary_shows_not_reverified_when_present(tmp_path):
    st = _state()
    st.counts["not_reverified"] = 3
    from io import StringIO
    from rich.console import Console
    buf = StringIO()
    old = cli_mod.console
    cli_mod.console = Console(file=buf, width=120, color_system=None)
    try:
        cli_mod._print_summary(st, tmp_path)
    finally:
        cli_mod.console = old
    assert "not_reverified" in buf.getvalue()
