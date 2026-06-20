"""Test del modulo trivy (§14 del blueprint) — OFFLINE.

trivy è un binario esterno maturo (scanner FS white-box). Bastione gli mette
attorno una colla sottile (§14): which → skip onesto, invocazione con output
JSON in run_dir/raw/, parse+normalize → Finding[]. Gira a PROBE (FS scan).

Due path coperti, di proposito:

A. **SKIPPED** — sotto il tetto read-only (self-gate) OPPURE source_path assente/
   non-dir OPPURE binario assente (which None): si emette UN Finding INFO
   `TRIVY_SKIPPED` e si prosegue. Nessun authorize, nessun subprocess.

B. **parse+normalize** — which presente + source_path dir + ctx a PROBE/ownership
   + il confine I/O (_run_trivy a livello modulo) monkeypatchato che ritorna un
   report JSON sintetico: i Finding attesi con severity mappata
   (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN/ignoto→INFO) e dedup via finding_id (§16).
   Più: Misconfigurations parse; record malformato → saltato senza crash.

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
    out_path relativo (es. ``_run_trivy(..., "out.json")``) o un ``run_dir`` di
    default ``Path(".")`` NON devono sporcare la root del repo. Ogni test gira
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
    source_path: str | None = None,
    max_intrusion: IntrusionLevel = IntrusionLevel.PROBE,
    ownership_verified: bool = True,
    cfg: TargetConfig | None = None,
    run_dir: Path | None = None,
) -> RunContext:
    cfg = cfg or _make_cfg(source_path=source_path)
    fp = Fingerprint(target=cfg.name, resolved_urls=[])
    return RunContext(
        target_cfg=cfg,
        fingerprint=fp,
        max_intrusion=max_intrusion,
        run_dir=run_dir or Path("."),
        ownership_verified=ownership_verified,
    )


# ─── report sintetico trivy (§14) ───────────────────────────────────────────

def _trivy_report(
    *,
    target: str = "pkg",
    vuln_id: str = "CVE-2024-1234",
    severity: str = "HIGH",
    pkg_name: str = "x",
) -> dict:
    """Report JSON sintetico come lo emette `trivy fs --format json` (§14)."""
    return {
        "Results": [
            {
                "Target": target,
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vuln_id,
                        "Severity": severity,
                        "PkgName": pkg_name,
                        "Title": f"Test vuln {vuln_id}",
                    }
                ],
            }
        ]
    }


# ─── (1) attributi di classe ────────────────────────────────────────────────

def test_trivy_module_name_and_intrusion():
    """name='trivy', max_intrusion=PROBE (§14)."""
    from bastione.modules.trivy.module import TrivyModule
    assert TrivyModule.name == "trivy"
    assert TrivyModule.max_intrusion == IntrusionLevel.PROBE


def test_trivy_registered_in_registry():
    """L'import del modulo registra TrivyModule in REGISTRY (§9)."""
    import importlib

    import bastione.modules.trivy.module as trivy_mod
    importlib.reload(trivy_mod)
    from bastione.modules.base import REGISTRY
    assert "trivy" in REGISTRY


# ─── (2) should_run ─────────────────────────────────────────────────────────

def test_should_run_true_when_source_path_set():
    """should_run=True se cfg.source_path è valorizzato (§14)."""
    from bastione.modules.trivy.module import TrivyModule
    fp = Fingerprint(target="t", resolved_urls=[])
    cfg = _make_cfg(source_path="/some/path")
    assert TrivyModule().should_run(fp, cfg) is True


def test_should_run_false_when_no_source_path():
    """should_run=False senza source_path: niente da scansionare."""
    from bastione.modules.trivy.module import TrivyModule
    fp = Fingerprint(target="t", resolved_urls=[])
    cfg = _make_cfg(source_path=None)
    assert TrivyModule().should_run(fp, cfg) is False


# ─── (3) path A — SKIPPED ────────────────────────────────────────────────────

def test_run_read_only_emits_skipped_no_subprocess(monkeypatch):
    """Tetto READ_ONLY (self-gate): Finding INFO TRIVY_SKIPPED, nessun subprocess,
    nessun authorize. Comportamento M0 read-only invariato (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    ctx = _make_ctx(
        source_path="/some/path",
        max_intrusion=IntrusionLevel.READ_ONLY,
        ownership_verified=False,
    )
    result = TrivyModule().run(ctx)

    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "TRIVY_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.module == "trivy"
    # Nessun subprocess invocato sotto read-only
    assert called == []


def test_run_probe_without_ownership_emits_skipped(monkeypatch):
    """PROBE ma ownership non verificata (self-gate): SKIPPED, nessun subprocess."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    ctx = _make_ctx(
        source_path="/some/path",
        max_intrusion=IntrusionLevel.PROBE,
        ownership_verified=False,
    )
    result = TrivyModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "TRIVY_SKIPPED"
    assert called == []


def test_run_no_source_path_emits_skipped(monkeypatch, tmp_path):
    """source_path assente: SKIPPED con motivo 'sorgente non disponibile' (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    ctx = _make_ctx(source_path=None)
    result = TrivyModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "TRIVY_SKIPPED"
    assert "sorgente" in f.evidence.lower() or "source_path" in f.evidence.lower()
    assert called == []


def test_run_source_path_not_dir_emits_skipped(monkeypatch, tmp_path):
    """source_path non è una directory: SKIPPED (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    # File esistente, non directory
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("not a dir")
    ctx = _make_ctx(source_path=str(not_a_dir))
    result = TrivyModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "TRIVY_SKIPPED"
    assert called == []


def test_run_binary_absent_emits_skipped(monkeypatch, tmp_path):
    """which('trivy') None (binario assente): SKIPPED onesto, nessun subprocess (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: None)
    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "TRIVY_SKIPPED"
    assert f.severity == Severity.INFO
    assert "assente" in f.description.lower() or "binario" in f.description.lower()
    assert called == []


def test_skipped_finding_has_finding_id(monkeypatch):
    """Anche il Finding SKIPPED deve avere un finding_id non vuoto (§16)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: None)
    ctx = _make_ctx(source_path="/some/path")
    result = TrivyModule().run(ctx)
    assert result.findings[0].finding_id != ""


# ─── (4) backstop del gate ──────────────────────────────────────────────────

def test_run_gate_denied_emits_skipped_no_crash(monkeypatch, tmp_path):
    """Se authorize(PROBE) solleva IntrusionDenied (backstop §7), il modulo emette
    SKIPPED e NON crasha, NON invoca il binario (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")

    def deny(level, ctx):
        raise IntrusionDenied("negato dal gate (test)")

    monkeypatch.setattr(trivy_mod, "authorize", deny)
    called: list = []
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: called.append(src) or {})

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "TRIVY_SKIPPED"
    # Binario NON invocato: il gate ha negato prima del subprocess
    assert called == []


# ─── (5) path B — parse+normalize ───────────────────────────────────────────

def test_run_parses_vulnerabilities_into_findings(monkeypatch, tmp_path):
    """which presente + source_path dir + PROBE/ownership + _run_trivy monkeypatchato:
    ogni Vulnerability → un Finding con rule_id=VulnerabilityID e severity mappata (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "pkg",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "PkgName": "x"},
                    {"VulnerabilityID": "CVE-2024-0002", "Severity": "MEDIUM", "PkgName": "y"},
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert {"CVE-2024-0001", "CVE-2024-0002"} <= rule_ids
    # nessun SKIPPED se il binario è presente e gira
    assert "TRIVY_SKIPPED" not in rule_ids
    # tutti i finding sono del modulo trivy, confidence FIRM, intrusion PROBE
    for f in result.findings:
        assert f.module == "trivy"
        assert f.confidence == Confidence.FIRM
        assert f.intrusion_used == IntrusionLevel.PROBE


def test_run_parses_misconfigurations(monkeypatch, tmp_path):
    """Misconfigurations nel report → Finding[] (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Severity": "HIGH", "Title": "Root user"},
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert "DS002" in rule_ids
    assert "TRIVY_SKIPPED" not in rule_ids


@pytest.mark.parametrize("tool_sev,expected", [
    ("CRITICAL", Severity.CRITICAL),
    ("HIGH", Severity.HIGH),
    ("MEDIUM", Severity.MEDIUM),
    ("LOW", Severity.LOW),
    ("UNKNOWN", Severity.INFO),    # UNKNOWN → INFO prudenziale
    ("high", Severity.HIGH),       # case-insensitive
    ("unknown-sev", Severity.INFO),  # sconosciuta → INFO prudenziale
])
def test_severity_mapping(monkeypatch, tmp_path, tool_sev, expected):
    """Mapping severità trivy → Severity (§14): CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN,
    case-insensitive; valore sconosciuto → INFO."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_report(severity=tool_sev)
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    trivy_findings = [f for f in result.findings if f.module == "trivy"]
    assert len(trivy_findings) == 1
    assert trivy_findings[0].severity == expected


def test_run_location_is_pkg_name(monkeypatch, tmp_path):
    """La location.file del Finding deve essere il PkgName (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_report(pkg_name="mypackage")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.module == "trivy")
    assert f.location.file == "mypackage"


def test_run_evidence_redacted_p8(monkeypatch, tmp_path):
    """Evidence: solo 'trivy <id> in <pkg>' — mai dati sensibili (P8)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_report(vuln_id="CVE-2024-9999", pkg_name="libssl")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.module == "trivy")
    assert "CVE-2024-9999" in f.evidence
    assert "libssl" in f.evidence


def test_run_malformed_result_skipped_no_crash(monkeypatch, tmp_path):
    """Un Results con record malformati viene saltato senza crash; i validi restano (§4.7)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            "not a dict",            # malformato
            {
                "Target": "pkg",
                "Vulnerabilities": [
                    None,            # malformato
                    {"VulnerabilityID": "CVE-2024-VALID", "Severity": "LOW", "PkgName": "z"},
                    {},              # senza VulnerabilityID — saltato
                ],
            },
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    rule_ids = [f.rule_id for f in result.findings if f.module == "trivy"]
    # solo il record valido produce un finding; nessun crash
    assert "CVE-2024-VALID" in rule_ids
    # i record malformati non producono finding
    assert None not in rule_ids


def test_run_dedup_same_finding_id(monkeypatch, tmp_path):
    """Due vulnerabilità identiche (stesso VulnerabilityID + stesso PkgName) →
    un solo Finding (dedup via finding_id §16)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    dup_vuln = {"VulnerabilityID": "CVE-DUP", "Severity": "MEDIUM", "PkgName": "dup-pkg"}
    report = {
        "Results": [
            {"Target": "pkg", "Vulnerabilities": [dup_vuln, dup_vuln]},
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    dup_findings = [f for f in result.findings if f.rule_id == "CVE-DUP"]
    assert len(dup_findings) == 1


def test_finding_id_helper_locked_formula():
    """_finding_id segue la formula LOCKED §16 SENZA target."""
    from bastione.modules.trivy.module import _finding_id
    loc = Location(file="mypackage")
    expected = hashlib.sha256(
        f"trivy:CVE-2024-1234:{loc.canonical()}".encode()).hexdigest()[:16]
    assert _finding_id("trivy", "CVE-2024-1234", loc) == expected


def test_run_none_report_returns_empty(monkeypatch, tmp_path):
    """_run_trivy ritorna None (fallimento): 0 finding, nessun crash, nessuno SKIPPED."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: None)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_empty_results_returns_empty(monkeypatch, tmp_path):
    """_run_trivy ritorna report con Results vuoti: 0 finding, nessun crash."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: {"Results": []})

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_output_path_under_run_dir_raw(monkeypatch, tmp_path):
    """L'output raw va in ctx.run_dir/raw/trivy.json (§14/§4)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    captured: dict = {}

    def capture(src, out_path):
        captured["out_path"] = Path(out_path)
        return {"Results": []}

    monkeypatch.setattr(trivy_mod, "_run_trivy", capture)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir), run_dir=tmp_path)
    TrivyModule().run(ctx)

    out = captured["out_path"]
    assert out.parent == tmp_path / "raw"
    assert out.name == "trivy.json"
    # la cartella raw/ deve esistere (creata dal modulo prima dell'invocazione)
    assert (tmp_path / "raw").is_dir()


# ─── (6) _run_trivy — confine I/O: argv-list, no shell ─────────────────────

def test_run_trivy_uses_argv_list_no_shell(monkeypatch):
    """_run_trivy invoca subprocess con una LISTA di argv (mai shell=True): niente
    command injection (§14 guardrail subprocess sicuro)."""
    import bastione.modules.trivy.module as trivy_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"Results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(trivy_mod.subprocess, "run", fake_run)
    trivy_mod._run_trivy("/some/path", "out.json")

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "trivy"
    assert argv[1] == "fs"
    # mai shell=True (niente interpolazione di shell sul path)
    assert captured["kwargs"].get("shell", False) is False


def test_run_trivy_argv_has_json_format_and_quiet(monkeypatch):
    """L'argv DEVE contenere --format json e --quiet (§14)."""
    import bastione.modules.trivy.module as trivy_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"Results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return FakeProc()

    monkeypatch.setattr(trivy_mod.subprocess, "run", fake_run)
    trivy_mod._run_trivy("/some/path", "out.json")

    argv = captured["argv"]
    assert "--format" in argv
    assert argv[argv.index("--format") + 1] == "json"
    assert "--quiet" in argv


def test_run_trivy_degrades_on_oserror(monkeypatch):
    """Se subprocess.run solleva OSError (binario sparito a runtime), _run_trivy
    degrada a None senza crash (§4.7)."""
    import bastione.modules.trivy.module as trivy_mod

    def boom(argv, **kwargs):
        raise OSError("no such binary")

    monkeypatch.setattr(trivy_mod.subprocess, "run", boom)
    assert trivy_mod._run_trivy("/some/path", "out.json") is None


def test_run_trivy_degrades_on_invalid_json(monkeypatch):
    """Se l'output non è JSON valido, _run_trivy degrada a None senza crash (§4.7)."""
    import bastione.modules.trivy.module as trivy_mod

    class FakeProc:
        stdout = "this is not json"
        returncode = 0

    monkeypatch.setattr(trivy_mod.subprocess, "run", lambda argv, **kw: FakeProc())
    assert trivy_mod._run_trivy("/some/path", "out.json") is None


# ─── (7) regressione: titolo — prefisso 'trivy:' singolo (correttezza) ──────

def test_run_vuln_title_present_single_prefix(monkeypatch, tmp_path):
    """REGRESSIONE: con il campo Title presente il titolo è 'trivy: <Title>'
    (un solo prefisso), non viene alterato (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "pkg",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-T-1", "Severity": "HIGH",
                     "PkgName": "x", "Title": "Some vuln"},
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.rule_id == "CVE-T-1")
    assert f.title == "trivy: Some vuln"


def test_run_vuln_title_absent_no_double_prefix(monkeypatch, tmp_path):
    """REGRESSIONE (difetto reale): senza il campo Title il titolo deve essere
    'trivy: <id>' — NON 'trivy: trivy: <id>' (doppio prefisso)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "pkg",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-NO-TITLE", "Severity": "HIGH",
                     "PkgName": "x"},  # NESSUN Title
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.rule_id == "CVE-NO-TITLE")
    assert f.title == "trivy: CVE-NO-TITLE"
    assert "trivy: trivy:" not in f.title


def test_run_misconf_title_absent_no_double_prefix(monkeypatch, tmp_path):
    """REGRESSIONE (difetto reale): misconf senza Title → 'trivy: <id>',
    NON 'trivy: trivy: <id>'."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS001", "Severity": "HIGH"},  # NESSUN Title
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.rule_id == "DS001")
    assert f.title == "trivy: DS001"
    assert "trivy: trivy:" not in f.title


def test_run_misconf_title_present_single_prefix(monkeypatch, tmp_path):
    """REGRESSIONE: misconf con Title → 'trivy: <Title>' (un solo prefisso)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Severity": "HIGH", "Title": "Root user"},
                ],
            }
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    f = next(f for f in result.findings if f.rule_id == "DS002")
    assert f.title == "trivy: Root user"


# ─── (8) regressione: parsing degenere top-level (robustezza §4.7) ──────────

def test_run_nondict_report_returns_empty(monkeypatch, tmp_path):
    """REGRESSIONE (difetto reale): _run_trivy ritorna JSON valido ma non-oggetto
    (lista o stringa). Atteso: findings == [] senza eccezioni (§4.7), MAI
    AttributeError. Prima della fix: 'list/str object has no attribute get'."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    for degenerate in ([], "unexpected", 42):
        monkeypatch.setattr(trivy_mod, "_run_trivy",
                            lambda src, out_path, _v=degenerate: _v)
        ctx = _make_ctx(source_path=str(src_dir))
        result = TrivyModule().run(ctx)
        assert isinstance(result, ModuleResult)
        assert result.findings == []
        assert result.posture_checks == []


def test_parse_nondict_report_returns_empty():
    """REGRESSIONE: _parse è difensivo anche se chiamato con un report non-dict
    (difesa in profondità §4.7): nessun crash, lista vuota."""
    from bastione.modules.trivy.module import TrivyModule
    mod = TrivyModule()
    assert mod._parse([], "t") == []
    assert mod._parse("unexpected", "t") == []
    assert mod._parse(42, "t") == []


def test_run_trivy_nondict_json_returns_none(monkeypatch):
    """REGRESSIONE: il confine I/O _run_trivy con output JSON valido ma non-oggetto
    (es. '[]') deve degradare a None (come semgrep), così il guard in run() lo
    intercetta. Prima della fix: ritornava la lista, causando il crash a valle."""
    import bastione.modules.trivy.module as trivy_mod

    class FakeProc:
        stdout = "[]"
        returncode = 0

    monkeypatch.setattr(trivy_mod.subprocess, "run", lambda argv, **kw: FakeProc())
    assert trivy_mod._run_trivy("/some/path", "out.json") is None

    class FakeProcStr:
        stdout = '"just a string"'
        returncode = 0

    monkeypatch.setattr(trivy_mod.subprocess, "run", lambda argv, **kw: FakeProcStr())
    assert trivy_mod._run_trivy("/some/path", "out.json") is None


def test_run_results_null_returns_empty(monkeypatch, tmp_path):
    """REGRESSIONE (difetto reale): report con 'Results': null (output reale di
    trivy quando non c'è nulla da scansionare). Atteso: findings == [] senza
    eccezioni. Prima della fix: 'TypeError: NoneType object is not iterable'."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: {"Results": None})

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


@pytest.mark.parametrize("scalar", [42, 3.14, True])
def test_run_results_scalar_returns_empty_no_crash(monkeypatch, tmp_path, scalar):
    """REGRESSIONE (difetto reale §4.7): report con 'Results' SCALARE (numero/bool)
    invece di lista. Col vecchio `result.get('Results') or []` lo scalare truthy
    NON veniva coalesciato → `for … in 42` sollevava 'TypeError: int object is
    not iterable' fuori da run() (la chiamata _parse NON è in try/except). Atteso
    ora: findings == [] senza eccezioni, via _as_list."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_mod, "_run_trivy",
                        lambda src, out_path: {"Results": scalar})

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


@pytest.mark.parametrize("field", ["Vulnerabilities", "Misconfigurations", "Secrets"])
@pytest.mark.parametrize("scalar", [42, 3.14])
def test_parse_scalar_result_field_no_crash(monkeypatch, tmp_path, field, scalar):
    """REGRESSIONE (difetto reale §4.7): un campo a livello Result
    (Vulnerabilities/Misconfigurations/Secrets) come SCALARE numerico non deve
    crashare il modulo (prima: `for … in 42` => TypeError propagato fuori da
    run()). _as_list lo coalesce a [] → findings == [], nessuna eccezione. Un
    record valido in un Result accanto resta parsato."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {"Target": "degenere", field: scalar},   # campo scalare → niente crash
            {
                "Target": "pkg",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-OK", "Severity": "LOW", "PkgName": "p"},
                ],
            },
        ]
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)  # NON deve sollevare

    rule_ids = {f.rule_id for f in result.findings}
    assert "CVE-OK" in rule_ids


def test_parse_scalar_field_returns_none_branch_direct():
    """REGRESSIONE (difetto reale §4.7): chiamata diretta a _parse con campi
    scalari (riproduzione minimale del crash segnalato:
    `TrivyModule()._parse({'Results':[{'Target':'t','Secrets':42}]},'tgt')`).
    Atteso: lista vuota, nessuna eccezione."""
    from bastione.modules.trivy.module import TrivyModule
    mod = TrivyModule()
    assert mod._parse({"Results": [{"Target": "t", "Secrets": 42}]}, "tgt") == []
    assert mod._parse({"Results": [{"Target": "t", "Vulnerabilities": 3.14}]}, "tgt") == []
    assert mod._parse({"Results": [{"Target": "t", "Misconfigurations": 1}]}, "tgt") == []
    # Results stesso scalare
    assert mod._parse({"Results": 42}, "tgt") == []


# ─── (9) O07 — scanner misconfig nell'argv (vuln,secret,misconfig) ──────────

def test_run_trivy_argv_has_misconfig_scanner(monkeypatch):
    """O07: l'argv DEVE contenere '--scanners' e il valore subito dopo deve
    includere 'misconfig' (oltre a 'vuln' e 'secret'), così trivy esegua anche
    la scansione misconfig (di default `trivy fs` fa solo vuln,secret → il
    parser _misconf_to_finding non verrebbe mai esercitato su dati reali §14)."""
    import bastione.modules.trivy.module as trivy_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"Results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return FakeProc()

    monkeypatch.setattr(trivy_mod.subprocess, "run", fake_run)
    trivy_mod._run_trivy("/some/path", "out.json")

    argv = captured["argv"]
    assert "--scanners" in argv
    scanners_value = argv[argv.index("--scanners") + 1]
    assert "misconfig" in scanners_value
    assert "vuln" in scanners_value
    assert "secret" in scanners_value


def test_run_trivy_argv_misconfig_after_fs_still_json_quiet(monkeypatch):
    """O07 (regressione): l'argv resta argv-list (mai shell=True), argv[0]=='trivy',
    argv[1]=='fs'; --format json e --quiet restano presenti (test esistenti verdi)."""
    import bastione.modules.trivy.module as trivy_mod

    captured: dict = {}

    class FakeProc:
        stdout = '{"Results": []}'
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(trivy_mod.subprocess, "run", fake_run)
    trivy_mod._run_trivy("/some/path", "out.json")

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "trivy"
    assert argv[1] == "fs"
    assert "--format" in argv
    assert argv[argv.index("--format") + 1] == "json"
    assert "--quiet" in argv
    assert captured["kwargs"].get("shell", False) is False


# ─── (10) O06 — parsing dei Secrets (Finding PER-SECRET a severità INFO) ─────

def _trivy_secret_report(
    *,
    target: str = "config/.env",
    rule_id: str = "aws-access-key-id",
    category: str = "AWS",
    severity: str = "CRITICAL",
    title: str = "AWS Access Key ID",
    start_line: int = 7,
    match: str = "AKIAIOSFODNN7EXAMPLE",
) -> dict:
    """Report JSON sintetico con una voce Secrets come la emette `trivy fs` (§14)."""
    return {
        "Results": [
            {
                "Target": target,
                "Secrets": [
                    {
                        "RuleID": rule_id,
                        "Category": category,
                        "Severity": severity,
                        "Title": title,
                        "StartLine": start_line,
                        "Match": match,
                        "Code": {"Lines": [{"Content": match}]},
                    }
                ],
            }
        ],
    }


def test_run_parses_secrets_into_findings_info(monkeypatch, tmp_path):
    """O06 base: ogni Secret → un Finding con rule_id==RuleID, severity SEMPRE
    INFO (NON la severità di trivy), module=='trivy', confidence FIRM,
    intrusion PROBE (§14 — design LOCKED: per-secret a INFO)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_secret_report(rule_id="aws-access-key-id", severity="CRITICAL")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    secret_findings = [f for f in result.findings if f.rule_id == "aws-access-key-id"]
    assert len(secret_findings) == 1
    f = secret_findings[0]
    assert f.severity == Severity.INFO  # NON CRITICAL
    assert f.module == "trivy"
    assert f.confidence == Confidence.FIRM
    assert f.intrusion_used == IntrusionLevel.PROBE
    assert "TRIVY_SKIPPED" not in {x.rule_id for x in result.findings}


def test_run_secret_p8_value_never_leaks(monkeypatch, tmp_path):
    """O06 P8 (CRITICO): il valore del segreto (Match/Code) NON deve MAI comparire
    in evidence, title o description del Finding — solo metadati di regola (§7/P8)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    secret_value = "AKIAIOSFODNN7EXAMPLE"
    report = _trivy_secret_report(match=secret_value)
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    f = next(f for f in result.findings if f.module == "trivy")
    assert secret_value not in f.evidence
    assert secret_value not in f.title
    assert secret_value not in f.description
    # difesa in profondità: nemmeno in remediation_ref
    assert secret_value not in (f.remediation_ref or "")


def test_run_secret_location_file_and_line(monkeypatch, tmp_path):
    """O06 location: location.file==result_target e location.line==StartLine (§16)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_secret_report(target="config/.env", start_line=42)
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    f = next(f for f in result.findings if f.module == "trivy")
    assert f.location.file == "config/.env"
    assert f.location.line == 42


@pytest.mark.parametrize("tool_sev", ["CRITICAL", "HIGH", "LOW", "MEDIUM", "UNKNOWN"])
def test_run_secret_severity_always_info(monkeypatch, tmp_path, tool_sev):
    """O06: la severità di trivy sul secret è IGNORATA — il Finding resta SEMPRE
    INFO (design LOCKED: i secret trivy includono falsi positivi by-design)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_secret_report(severity=tool_sev)
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    secret_findings = [f for f in result.findings if f.module == "trivy"]
    assert len(secret_findings) == 1
    assert secret_findings[0].severity == Severity.INFO


def test_run_secret_per_line_distinct_findings(monkeypatch, tmp_path):
    """O06 per-riga (§16): due secret stessa RuleID, stesso file, ma StartLine
    diverse → 2 Finding con finding_id DISTINTI (la line entra nella location)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "config/.env",
                "Secrets": [
                    {"RuleID": "generic-api-key", "Category": "general",
                     "Severity": "HIGH", "Title": "API key", "StartLine": 3,
                     "Match": "secret-on-line-3"},
                    {"RuleID": "generic-api-key", "Category": "general",
                     "Severity": "HIGH", "Title": "API key", "StartLine": 9,
                     "Match": "secret-on-line-9"},
                ],
            }
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    secret_findings = [f for f in result.findings if f.rule_id == "generic-api-key"]
    assert len(secret_findings) == 2
    ids = {f.finding_id for f in secret_findings}
    assert len(ids) == 2


def test_run_secret_dedup_same_rule_file_line(monkeypatch, tmp_path):
    """O06 dedup (§16): due secret identici (stessa RuleID+file+line) → 1 Finding."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    dup = {"RuleID": "generic-api-key", "Category": "general", "Severity": "HIGH",
           "Title": "API key", "StartLine": 5, "Match": "dup-secret"}
    report = {
        "Results": [
            {"Target": "config/.env", "Secrets": [dup, dup]},
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    secret_findings = [f for f in result.findings if f.rule_id == "generic-api-key"]
    assert len(secret_findings) == 1


def test_run_secret_malformed_skipped_no_crash(monkeypatch, tmp_path):
    """O06 §4.7: input degenere (Secrets null, voce non-dict, secret senza RuleID)
    → nessun crash, record saltato; i secret validi restano."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {"Target": "a", "Secrets": None},          # Secrets null
            {
                "Target": "config/.env",
                "Secrets": [
                    None,                               # voce non-dict
                    "not a dict",                       # voce non-dict (scalare)
                    {},                                 # senza RuleID — saltato
                    {"RuleID": "", "StartLine": 1},     # RuleID vuoto — saltato
                    {"RuleID": "valid-rule", "Category": "AWS",
                     "Severity": "HIGH", "Title": "ok", "StartLine": 4,
                     "Match": "x"},                     # valido
                ],
            },
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    rule_ids = [f.rule_id for f in result.findings if f.module == "trivy"]
    assert "valid-rule" in rule_ids
    assert "" not in rule_ids
    assert None not in rule_ids


def test_secret_to_finding_returns_none_on_malformed():
    """O06 §4.7: _secret_to_finding ritorna None su input malformato (non-dict,
    RuleID assente/non-str/vuoto) — esattamente come _vuln_to_finding."""
    from bastione.modules.trivy.module import TrivyModule
    mod = TrivyModule()
    assert mod._secret_to_finding(None, "t", "tgt") is None
    assert mod._secret_to_finding("not a dict", "t", "tgt") is None
    assert mod._secret_to_finding(42, "t", "tgt") is None
    assert mod._secret_to_finding({}, "t", "tgt") is None
    assert mod._secret_to_finding({"RuleID": ""}, "t", "tgt") is None
    assert mod._secret_to_finding({"RuleID": 123}, "t", "tgt") is None


def test_run_secret_title_absent_no_double_prefix(monkeypatch, tmp_path):
    """O06 single prefix: secret senza Title → 'trivy: <RuleID>',
    NON 'trivy: trivy: <RuleID>' (un solo prefisso)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "config/.env",
                "Secrets": [
                    {"RuleID": "no-title-rule", "Category": "AWS",
                     "Severity": "HIGH", "StartLine": 2, "Match": "x"},  # NESSUN Title
                ],
            }
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    f = next(f for f in result.findings if f.rule_id == "no-title-rule")
    assert f.title == "trivy: no-title-rule"
    assert "trivy: trivy:" not in f.title


def test_run_secret_title_present_single_prefix(monkeypatch, tmp_path):
    """O06 single prefix: secret con Title → 'trivy: <Title>' (un solo prefisso,
    e il Title di trivy è il nome-regola umano, non il segreto → P8-safe)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = _trivy_secret_report(rule_id="aws-access-key-id", title="AWS Access Key ID")
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    f = next(f for f in result.findings if f.rule_id == "aws-access-key-id")
    assert f.title == "trivy: AWS Access Key ID"
    assert "trivy: trivy:" not in f.title


def test_run_secret_non_int_startline_line_none(monkeypatch, tmp_path):
    """O06: StartLine non-int (assente o non numerico) → location.line is None,
    nessun crash (§4.7)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "config/.env",
                "Secrets": [
                    {"RuleID": "r1", "Category": "AWS", "Severity": "HIGH",
                     "Title": "t", "StartLine": "not-an-int", "Match": "x"},
                ],
            }
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    f = next(f for f in result.findings if f.rule_id == "r1")
    assert f.location.line is None


def test_run_mixed_vuln_misconf_secret(monkeypatch, tmp_path):
    """O06 regressione misto: report con Vulnerabilities + Misconfigurations +
    Secrets insieme → tutti e tre i tipi compaiono nei finding (§14)."""
    import bastione.modules.trivy.module as trivy_mod
    from bastione.modules.trivy.module import TrivyModule

    monkeypatch.setattr(trivy_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    report = {
        "Results": [
            {
                "Target": "config/.env",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-MIX-1", "Severity": "HIGH", "PkgName": "p"},
                ],
                "Misconfigurations": [
                    {"ID": "MIX-MISCONF", "Severity": "HIGH", "Title": "m"},
                ],
                "Secrets": [
                    {"RuleID": "mix-secret", "Category": "AWS", "Severity": "CRITICAL",
                     "Title": "s", "StartLine": 1, "Match": "x"},
                ],
            }
        ],
    }
    monkeypatch.setattr(trivy_mod, "_run_trivy", lambda src, out_path: report)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    ctx = _make_ctx(source_path=str(src_dir))
    result = TrivyModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert {"CVE-MIX-1", "MIX-MISCONF", "mix-secret"} <= rule_ids
    # il secret resta INFO, non CRITICAL
    secret_f = next(f for f in result.findings if f.rule_id == "mix-secret")
    assert secret_f.severity == Severity.INFO
