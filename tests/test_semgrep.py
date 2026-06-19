"""Test del modulo semgrep (§14 del blueprint) — OFFLINE.

semgrep è un binario esterno di analisi statica (white-box, SAST). Bastione gli
mette intorno una colla sottile (§14): which → skip onesto, sorgente locale →
invocazione con output JSON in run_dir/raw/, parse+normalize → Finding[]. Gira
a PROBE (white-box su sorgente locale, NON tocca il target live).

Due path coperti, di proposito:

A. **SKIPPED** — sotto il tetto read-only (self-gate) OPPURE sorgente assente
   OPPURE binario assente (which None): si emette UN Finding INFO `SEMGREP_SKIPPED`
   e si prosegue. Nessun authorize, nessun subprocess.

B. **parse+normalize** — which presente + sorgente presente + ctx a PROBE/ownership
   + il confine I/O (_run_semgrep a livello modulo) monkeypatchato che ritorna
   results realistici: i Finding attesi con severity mappata
   (ERROR→HIGH, WARNING→MEDIUM, INFO→INFO) e dedup via finding_id (§16).
   Più: result malformato → saltato senza crash.

Tutto OFFLINE: nessun subprocess reale, nessuna rete.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied
from bastione.models import (
    Fingerprint,
    Location,
    ModuleResult,
    RunContext,
    TargetConfig,
)


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    """Isola il filesystem: i confini I/O che scrivono il raw artifact su un
    out_path relativo (es. ``_run_semgrep(..., "out.json")``) o un ``run_dir``
    di default ``Path(".")`` NON devono sporcare la root del repo. Ogni test gira
    con cwd = tmp_path (auto-pulita da pytest)."""
    monkeypatch.chdir(tmp_path)


# ─── helper: RunContext minimale ────────────────────────────────────────────

def _make_cfg(
    name: str = "test-target",
    source_path: str | None = None,
) -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
        ownership_token="tok-123",
        source_path=source_path,
    )


def _make_ctx(
    *,
    max_intrusion: IntrusionLevel = IntrusionLevel.PROBE,
    ownership_verified: bool = True,
    cfg: TargetConfig | None = None,
    run_dir: Path | None = None,
) -> RunContext:
    cfg = cfg or _make_cfg()
    fp = Fingerprint(target=cfg.name, resolved_urls=[])
    return RunContext(
        target_cfg=cfg,
        fingerprint=fp,
        max_intrusion=max_intrusion,
        run_dir=run_dir or Path("."),
        ownership_verified=ownership_verified,
    )


# ─── results realistici di semgrep --json ───────────────────────────────────

def _semgrep_result(
    *,
    check_id: str = "python.lang.security.audit.hardcoded-password",
    severity: str = "ERROR",
    path: str = "src/app.py",
    line: int = 42,
    message: str = "Hardcoded password detected.",
) -> dict:
    """Un result come lo emette `semgrep --json` (campi essenziali, §14)."""
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 20},
        "extra": {
            "severity": severity,
            "message": message,
            "lines": "password = 'secret'",  # snippet: NON deve finire in evidence (P8)
        },
    }


# ─── (1) attributi di classe ────────────────────────────────────────────────

def test_semgrep_module_name_and_intrusion():
    """name='semgrep', max_intrusion=PROBE (§14)."""
    from bastione.modules.semgrep.module import SemgrepModule
    assert SemgrepModule.name == "semgrep"
    assert SemgrepModule.max_intrusion == IntrusionLevel.PROBE


def test_semgrep_registered_in_registry():
    """L'import del modulo registra SemgrepModule in REGISTRY (§9)."""
    import importlib

    import bastione.modules.semgrep.module as semgrep_mod
    importlib.reload(semgrep_mod)
    from bastione.modules.base import REGISTRY
    assert "semgrep" in REGISTRY


# ─── (2) should_run ─────────────────────────────────────────────────────────

def test_should_run_true_when_source_path_set():
    """should_run=True se la cfg ha source_path valorizzato (§14)."""
    from bastione.modules.semgrep.module import SemgrepModule
    cfg = _make_cfg(source_path="/repo/src")
    fp = Fingerprint(target="t", resolved_urls=[])
    assert SemgrepModule().should_run(fp, cfg) is True


def test_should_run_false_when_no_source_path():
    """should_run=False senza source_path: niente sorgente da scansionare."""
    from bastione.modules.semgrep.module import SemgrepModule
    cfg = _make_cfg(source_path=None)
    fp = Fingerprint(target="t", resolved_urls=[])
    assert SemgrepModule().should_run(fp, cfg) is False


# ─── (3) path A — SKIPPED ────────────────────────────────────────────────────

def test_run_read_only_emits_skipped_no_subprocess(monkeypatch):
    """Tetto READ_ONLY (self-gate): Finding INFO SEMGREP_SKIPPED, nessun subprocess,
    nessun authorize. Comportamento M0 read-only invariato (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])

    cfg = _make_cfg(source_path="/repo/src")
    ctx = _make_ctx(cfg=cfg,
                    max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False)
    result = SemgrepModule().run(ctx)

    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEMGREP_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.module == "semgrep"
    # Nessun subprocess invocato sotto read-only
    assert called == []


def test_run_probe_without_ownership_emits_skipped(monkeypatch):
    """PROBE ma ownership non verificata (self-gate): SKIPPED, nessun subprocess."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])

    cfg = _make_cfg(source_path="/repo/src")
    ctx = _make_ctx(cfg=cfg,
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)
    result = SemgrepModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEMGREP_SKIPPED"
    assert called == []


def test_run_source_absent_emits_skipped(monkeypatch, tmp_path):
    """source_path presente ma non è una directory: SKIPPED, nessun subprocess (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")

    # path che non esiste come directory
    cfg = _make_cfg(source_path=str(tmp_path / "nonexistent"))
    ctx = _make_ctx(cfg=cfg,
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SemgrepModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEMGREP_SKIPPED"
    assert f.severity == Severity.INFO
    assert "sorgente" in f.description.lower() or "source" in f.description.lower()
    assert called == []


def test_run_source_path_none_emits_skipped(monkeypatch):
    """source_path None (non configurato): SKIPPED, nessun subprocess (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")

    cfg = _make_cfg(source_path=None)
    ctx = _make_ctx(cfg=cfg,
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SemgrepModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEMGREP_SKIPPED"
    assert called == []


def test_run_binary_absent_emits_skipped(monkeypatch, tmp_path):
    """which('semgrep') None (binario assente): SKIPPED onesto, nessun subprocess (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: None)
    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg,
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SemgrepModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "SEMGREP_SKIPPED"
    assert f.severity == Severity.INFO
    assert "assente" in f.description.lower() or "binario" in f.description.lower()
    assert called == []


def test_skipped_finding_has_finding_id(monkeypatch):
    """Anche il Finding SKIPPED deve avere un finding_id non vuoto (§16)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: None)
    cfg = _make_cfg(source_path=None)
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    assert result.findings[0].finding_id != ""


# ─── (4) backstop del gate ──────────────────────────────────────────────────

def test_run_gate_denied_emits_skipped_no_crash(monkeypatch, tmp_path):
    """Se authorize(PROBE) solleva IntrusionDenied (backstop §7), il modulo emette
    SKIPPED e NON crasha, NON invoca il binario (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")

    def deny(level, ctx):
        raise IntrusionDenied("negato dal gate (test)")

    monkeypatch.setattr(semgrep_mod, "authorize", deny)
    called: list = []
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda source_path, out_path: called.append(source_path) or [])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEMGREP_SKIPPED"
    # Binario NON invocato: il gate ha negato prima del subprocess
    assert called == []


# ─── (5) path B — parse+normalize ───────────────────────────────────────────

def test_run_parses_results_into_findings(monkeypatch, tmp_path):
    """which presente + PROBE/ownership + sorgente presente + _run_semgrep monkeypatchato:
    ogni result → un Finding con rule_id=check_id e severity mappata (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    results = [
        _semgrep_result(check_id="python.lang.security.audit.hardcoded-password",
                        severity="ERROR"),
        _semgrep_result(check_id="python.lang.security.audit.sql-injection",
                        severity="WARNING", path="src/db.py", line=10),
        _semgrep_result(check_id="python.lang.correctness.useless-expression",
                        severity="INFO", path="src/utils.py", line=5),
    ]
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: results)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert {
        "python.lang.security.audit.hardcoded-password",
        "python.lang.security.audit.sql-injection",
        "python.lang.correctness.useless-expression",
    } <= rule_ids
    # nessun SKIPPED se il binario e la sorgente sono presenti
    assert "SEMGREP_SKIPPED" not in rule_ids
    # tutti i finding sono del modulo semgrep, confidence FIRM, intrusion PROBE
    semgrep_findings = [f for f in result.findings if f.module == "semgrep"]
    for f in semgrep_findings:
        assert f.confidence == Confidence.FIRM
        assert f.intrusion_used == IntrusionLevel.PROBE


@pytest.mark.parametrize("tool_sev,expected", [
    ("ERROR", Severity.HIGH),
    ("error", Severity.HIGH),      # case-insensitive
    ("WARNING", Severity.MEDIUM),
    ("warning", Severity.MEDIUM),  # case-insensitive
    ("INFO", Severity.INFO),
    ("info", Severity.INFO),       # case-insensitive
    ("UNKNOWN", Severity.INFO),    # sconosciuta → INFO prudenziale
])
def test_severity_mapping(monkeypatch, tmp_path, tool_sev, expected):
    """Mapping severità semgrep → Severity (§14): ERROR→HIGH, WARNING→MEDIUM, INFO→INFO,
    case-insensitive; valore sconosciuto → INFO."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda src, out: [_semgrep_result(severity=tool_sev)])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    semgrep_findings = [f for f in result.findings if f.module == "semgrep"]
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0].severity == expected


def test_run_location_has_file_and_line(monkeypatch, tmp_path):
    """La location del Finding deve avere file e line dal result semgrep (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda src, out: [_semgrep_result(path="src/app.py", line=42)])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    f = next(f for f in result.findings if f.module == "semgrep")
    assert f.location.file == "src/app.py"
    assert f.location.line == 42


def test_evidence_does_not_contain_code_snippet(monkeypatch, tmp_path):
    """L'evidence è REDATTA (P8): non contiene snippet di codice, solo rule_id + path:line."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda src, out: [_semgrep_result(
                            check_id="my-rule", path="src/app.py", line=7)])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    f = next(f for f in result.findings if f.module == "semgrep")
    # evidence deve contenere rule_id, path, line — ma NON il contenuto del codice
    assert "my-rule" in f.evidence
    assert "src/app.py" in f.evidence
    assert "secret" not in f.evidence  # snippet di codice hardcoded NON deve apparire


def test_run_malformed_result_skipped_no_crash(monkeypatch, tmp_path):
    """Un result malformato (senza check_id) viene saltato senza crash; i validi restano (§14/§4.7)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    results = [
        {"no-check-id": "x", "extra": {"severity": "ERROR"}},  # senza check_id
        "not-a-dict",                                            # non è un dict
        _semgrep_result(check_id="valid-rule", severity="WARNING"),
    ]
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: results)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)

    rule_ids = [f.rule_id for f in result.findings if f.module == "semgrep"]
    # solo il result valido produce un finding; nessun crash
    assert rule_ids == ["valid-rule"]


def test_run_dedup_same_finding_id(monkeypatch, tmp_path):
    """Due result identici (stesso check_id + stessa location) → un solo Finding
    (dedup via finding_id §16)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    dup = _semgrep_result(check_id="dup-rule", severity="ERROR",
                          path="src/app.py", line=42)
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: [dup, dup])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    dup_findings = [f for f in result.findings if f.rule_id == "dup-rule"]
    assert len(dup_findings) == 1


def test_finding_id_matches_baseline_formula(monkeypatch, tmp_path):
    """Il finding_id emesso coincide con baseline.diff.finding_id (§16 LOCKED)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule
    from bastione.baseline.diff import finding_id as baseline_finding_id

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep",
                        lambda src, out: [_semgrep_result(check_id="test-rule")])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    f = next(f for f in result.findings if f.module == "semgrep")
    assert f.finding_id == baseline_finding_id(f)


def test_finding_id_helper_locked_formula():
    """_finding_id segue la formula LOCKED §16 SENZA target."""
    from bastione.modules.semgrep.module import _finding_id
    loc = Location(file="src/app.py", line=42)
    expected = hashlib.sha256(
        f"semgrep:my-rule:{loc.canonical()}".encode()).hexdigest()[:16]
    assert _finding_id("semgrep", "my-rule", loc) == expected


def test_run_no_results_returns_empty(monkeypatch, tmp_path):
    """_run_semgrep ritorna [] (nessun match): 0 finding, nessun crash, nessuno SKIPPED."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: [])

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_output_path_under_run_dir_raw(monkeypatch, tmp_path):
    """L'output raw va in ctx.run_dir/raw/semgrep.json (§14/§4)."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    captured: dict = {}

    def capture(source_path, out_path):
        captured["out_path"] = Path(out_path)
        return []

    monkeypatch.setattr(semgrep_mod, "_run_semgrep", capture)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg, run_dir=tmp_path)
    SemgrepModule().run(ctx)

    out = captured["out_path"]
    assert out.parent == tmp_path / "raw"
    assert out.name == "semgrep.json"
    # la cartella raw/ deve esistere (creata dal modulo prima dell'invocazione)
    assert (tmp_path / "raw").is_dir()


# ─── (6) _run_semgrep — confine I/O: argv-list, no shell, degrado ────────────

def test_run_semgrep_uses_argv_list_no_shell(monkeypatch):
    """_run_semgrep invoca subprocess con una LISTA di argv (mai shell=True): niente
    command injection (§14 guardrail subprocess sicuro)."""
    import bastione.modules.semgrep.module as semgrep_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(semgrep_mod.subprocess, "run", fake_run)
    semgrep_mod._run_semgrep("/repo/src", "out.json")

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "semgrep"
    # mai shell=True (niente interpolazione di shell sul path)
    assert captured["kwargs"].get("shell", False) is False


def test_run_semgrep_argv_contains_json_and_quiet(monkeypatch):
    """L'argv di _run_semgrep include --json e --quiet (§14)."""
    import bastione.modules.semgrep.module as semgrep_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return FakeProc()

    monkeypatch.setattr(semgrep_mod.subprocess, "run", fake_run)
    semgrep_mod._run_semgrep("/repo/src", "out.json")

    argv = captured["argv"]
    assert "--json" in argv
    assert "--quiet" in argv
    # source_path passata come ultimo argomento (non interpolata in shell)
    assert "/repo/src" in argv


def test_run_semgrep_degrades_on_oserror(monkeypatch):
    """Se subprocess.run solleva OSError (binario sparito a runtime), _run_semgrep
    degrada a [] senza crash (§4.7)."""
    import bastione.modules.semgrep.module as semgrep_mod

    def boom(argv, **kwargs):
        raise OSError("no such binary")

    monkeypatch.setattr(semgrep_mod.subprocess, "run", boom)
    assert semgrep_mod._run_semgrep("/repo/src", "out.json") == []


# ─── (7) REGRESSIONE — results non-lista (null/scalare) → [] senza crash ──────

def test_run_semgrep_results_null_degrades_to_empty(monkeypatch):
    """REGRESSIONE: stdout `{"results": null}` → _run_semgrep degrada a [] (lista
    vuota), MAI None. Il confine I/O valida il tipo lista (§4.7). Prima del fix
    ritornava None, che faceva poi crashare _parse con TypeError."""
    import bastione.modules.semgrep.module as semgrep_mod

    class FakeProc:
        stdout = '{"results": null}'
        returncode = 0

    monkeypatch.setattr(semgrep_mod.subprocess, "run",
                        lambda argv, **kwargs: FakeProc())
    out = semgrep_mod._run_semgrep("/repo/src", "out.json")
    assert out == []
    assert isinstance(out, list)


def test_run_semgrep_results_scalar_degrades_to_empty(monkeypatch):
    """REGRESSIONE: stdout `{"results": 42}` (scalare non-iterabile come lista) →
    _run_semgrep degrada a [], non ritorna l'intero (§4.7)."""
    import bastione.modules.semgrep.module as semgrep_mod

    class FakeProc:
        stdout = '{"results": 42}'
        returncode = 0

    monkeypatch.setattr(semgrep_mod.subprocess, "run",
                        lambda argv, **kwargs: FakeProc())
    out = semgrep_mod._run_semgrep("/repo/src", "out.json")
    assert out == []
    assert isinstance(out, list)


def test_run_semgrep_results_dict_degrades_to_empty(monkeypatch):
    """REGRESSIONE: stdout `{"results": {"a": 1}}` (dict, non lista) → _run_semgrep
    degrada a []: il confine ritorna SOLO liste (§4.7). Senza la guardia il dict
    veniva ritornato e _parse iterava le sue chiavi-stringa."""
    import bastione.modules.semgrep.module as semgrep_mod

    class FakeProc:
        stdout = '{"results": {"a": 1}}'
        returncode = 0

    monkeypatch.setattr(semgrep_mod.subprocess, "run",
                        lambda argv, **kwargs: FakeProc())
    out = semgrep_mod._run_semgrep("/repo/src", "out.json")
    assert out == []
    assert isinstance(out, list)


def test_run_with_results_null_does_not_crash(monkeypatch, tmp_path):
    """REGRESSIONE end-to-end: _run_semgrep che ritorna None (esattamente ciò che
    produceva `{"results": null}` prima del fix) NON deve far crashare run() con
    `TypeError: 'NoneType' object is not iterable` (§4.7). run() degrada a 0 finding."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    # Simula il confine I/O che ritorna None (regressione esatta del bug)
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: None)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)  # non deve sollevare TypeError

    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_with_results_scalar_does_not_crash(monkeypatch, tmp_path):
    """REGRESSIONE end-to-end: _run_semgrep che ritorna uno scalare non-iterabile
    (es. un int, come `{"results": 42}` ritornava prima del fix) NON deve far
    crashare run() (§4.7). run() degrada a 0 finding."""
    import bastione.modules.semgrep.module as semgrep_mod
    from bastione.modules.semgrep.module import SemgrepModule

    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda name: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod, "_run_semgrep", lambda src, out: 42)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    cfg = _make_cfg(source_path=str(src_dir))
    ctx = _make_ctx(cfg=cfg)
    result = SemgrepModule().run(ctx)  # non deve sollevare TypeError

    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.posture_checks == []


def test_parse_non_list_returns_empty_no_crash():
    """REGRESSIONE difesa-in-profondità: _parse con un input non-lista (None/scalare)
    degrada a [] invece di sollevare `TypeError: ... is not iterable` (§4.7)."""
    from bastione.modules.semgrep.module import SemgrepModule

    mod = SemgrepModule()
    assert mod._parse(None, "t") == []        # type: ignore[arg-type]
    assert mod._parse(42, "t") == []          # type: ignore[arg-type]
    assert mod._parse("not-a-list", "t") == []  # type: ignore[arg-type]
