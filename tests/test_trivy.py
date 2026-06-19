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
