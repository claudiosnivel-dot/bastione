"""Test del modulo nuclei (§14 del blueprint) — OFFLINE.

nuclei è un binario esterno maturo (template-based). Bastione gli mette intorno
una colla sottile (§14): which → skip onesto, invocazione con output JSONL in
run_dir/raw/, parse+normalize → Finding[]. Gira a PROBE (passive/safe templates).

Due path coperti, di proposito:

A. **SKIPPED** — sotto il tetto read-only (self-gate) OPPURE binario assente
   (which None): si emette UN Finding INFO `NUCLEI_SKIPPED` e si prosegue. Nessun
   authorize, nessun subprocess.

B. **parse+normalize** — which presente + ctx a PROBE/ownership + il confine I/O
   (_run_nuclei a livello modulo) monkeypatchato che ritorna un JSONL realistico:
   i Finding attesi con severity mappata (info/low/medium/high/critical → Severity)
   e dedup via finding_id (§16). Più: riga malformata → saltata senza crash.

Tutto OFFLINE: nessun subprocess reale, nessuna rete.
"""

from __future__ import annotations

import hashlib
import json
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


# ─── helper: RunContext minimale ────────────────────────────────────────────

def _make_cfg(name: str = "test-target") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
        ownership_token="tok-123",
    )


def _make_ctx(
    *,
    resolved_urls: list[str] | None = None,
    max_intrusion: IntrusionLevel = IntrusionLevel.PROBE,
    ownership_verified: bool = True,
    cfg: TargetConfig | None = None,
    run_dir: Path | None = None,
) -> RunContext:
    cfg = cfg or _make_cfg()
    fp = Fingerprint(target=cfg.name, resolved_urls=resolved_urls or [])
    return RunContext(
        target_cfg=cfg,
        fingerprint=fp,
        max_intrusion=max_intrusion,
        run_dir=run_dir or Path("."),
        ownership_verified=ownership_verified,
    )


# ─── un record JSONL realistico di nuclei ───────────────────────────────────

def _nuclei_record(
    *,
    template_id: str = "tech-detect",
    severity: str = "info",
    matched: str = "https://staging.example.com/",
    name: str = "Technology Detection",
) -> str:
    """Una riga JSONL come la emette `nuclei -jsonl` (campi essenziali, §14)."""
    return json.dumps({
        "template-id": template_id,
        "info": {"name": name, "severity": severity},
        "matched-at": matched,
        "host": "staging.example.com",
        "type": "http",
    })


# ─── (1) attributi di classe ────────────────────────────────────────────────

def test_nuclei_module_name_and_intrusion():
    """name='nuclei', max_intrusion=PROBE (§14)."""
    from bastione.modules.nuclei.module import NucleiModule
    assert NucleiModule.name == "nuclei"
    assert NucleiModule.max_intrusion == IntrusionLevel.PROBE


def test_nuclei_registered_in_registry():
    """L'import del modulo registra NucleiModule in REGISTRY (§9)."""
    import importlib

    import bastione.modules.nuclei.module as nuclei_mod
    importlib.reload(nuclei_mod)
    from bastione.modules.base import REGISTRY
    assert "nuclei" in REGISTRY


# ─── (2) should_run ─────────────────────────────────────────────────────────

def test_should_run_true_when_resolved_urls():
    """should_run=True se il fingerprint ha resolved_urls (§14)."""
    from bastione.modules.nuclei.module import NucleiModule
    fp = Fingerprint(target="t", resolved_urls=["https://staging.example.com/"])
    assert NucleiModule().should_run(fp, _make_cfg()) is True


def test_should_run_false_when_no_resolved_urls():
    """should_run=False senza resolved_urls: niente da scansionare."""
    from bastione.modules.nuclei.module import NucleiModule
    fp = Fingerprint(target="t", resolved_urls=[])
    assert NucleiModule().should_run(fp, _make_cfg()) is False


# ─── (3) path A — SKIPPED ────────────────────────────────────────────────────

def test_run_read_only_emits_skipped_no_subprocess(monkeypatch):
    """Tetto READ_ONLY (self-gate): Finding INFO NUCLEI_SKIPPED, nessun subprocess,
    nessun authorize. Comportamento M0 read-only invariato (§14)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    called: list = []
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: called.append(urls) or [])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False)
    result = NucleiModule().run(ctx)

    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "NUCLEI_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.module == "nuclei"
    # Nessun subprocess invocato sotto read-only
    assert called == []


def test_run_probe_without_ownership_emits_skipped(monkeypatch):
    """PROBE ma ownership non verificata (self-gate): SKIPPED, nessun subprocess."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    called: list = []
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: called.append(urls) or [])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)
    result = NucleiModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "NUCLEI_SKIPPED"
    assert called == []


def test_run_binary_absent_emits_skipped(monkeypatch):
    """which('nuclei') None (binario assente): SKIPPED onesto, nessun subprocess (§14)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: None)
    called: list = []
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: called.append(urls) or [])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = NucleiModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "NUCLEI_SKIPPED"
    assert f.severity == Severity.INFO
    assert "assente" in f.description.lower() or "binario" in f.description.lower()
    assert called == []


def test_skipped_finding_has_finding_id(monkeypatch):
    """Anche il Finding SKIPPED deve avere un finding_id non vuoto (§16)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: None)
    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    assert result.findings[0].finding_id != ""


# ─── (4) backstop del gate ──────────────────────────────────────────────────

def test_run_gate_denied_emits_skipped_no_crash(monkeypatch):
    """Se authorize(PROBE) solleva IntrusionDenied (backstop §7), il modulo emette
    SKIPPED e NON crasha, NON invoca il binario (§14)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")

    def deny(level, ctx):
        raise IntrusionDenied("negato dal gate (test)")

    monkeypatch.setattr(nuclei_mod, "authorize", deny)
    called: list = []
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: called.append(urls) or [])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "NUCLEI_SKIPPED"
    # Binario NON invocato: il gate ha negato prima del subprocess
    assert called == []


# ─── (5) path B — parse+normalize ───────────────────────────────────────────

def test_run_parses_records_into_findings(monkeypatch):
    """which presente + PROBE/ownership + _run_nuclei monkeypatchato: ogni record
    JSONL → un Finding con rule_id=template-id e severity mappata (§14)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    lines = [
        _nuclei_record(template_id="tech-detect", severity="info"),
        _nuclei_record(template_id="exposed-panel", severity="medium",
                       matched="https://staging.example.com/admin"),
        _nuclei_record(template_id="ssl-issuer", severity="low",
                       matched="https://staging.example.com:443"),
    ]
    monkeypatch.setattr(nuclei_mod, "_run_nuclei", lambda urls, out_path: lines)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert {"tech-detect", "exposed-panel", "ssl-issuer"} <= rule_ids
    # nessun SKIPPED se il binario è presente e gira
    assert "NUCLEI_SKIPPED" not in rule_ids
    # tutti i finding sono del modulo nuclei, confidence FIRM, intrusion PROBE
    nuclei_findings = [f for f in result.findings if f.module == "nuclei"]
    for f in nuclei_findings:
        assert f.confidence == Confidence.FIRM
        assert f.intrusion_used == IntrusionLevel.PROBE


@pytest.mark.parametrize("tool_sev,expected", [
    ("info", Severity.INFO),
    ("low", Severity.LOW),
    ("medium", Severity.MEDIUM),
    ("high", Severity.HIGH),
    ("critical", Severity.CRITICAL),
    ("INFO", Severity.INFO),          # case-insensitive
    ("unknown-sev", Severity.INFO),   # sconosciuta → INFO prudenziale
])
def test_severity_mapping(monkeypatch, tool_sev, expected):
    """Mapping severità nuclei → Severity (§14): info/low/medium/high/critical,
    case-insensitive; valore sconosciuto → INFO."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: [_nuclei_record(severity=tool_sev)])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    nuclei_findings = [f for f in result.findings if f.module == "nuclei"]
    assert len(nuclei_findings) == 1
    assert nuclei_findings[0].severity == expected


def test_run_location_is_matched_url(monkeypatch):
    """La location del Finding deve essere l'URL matchato dal template (§14)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    matched = "https://staging.example.com/admin"
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: [_nuclei_record(matched=matched)])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    f = next(f for f in result.findings if f.module == "nuclei")
    assert f.location.url == matched


def test_run_malformed_line_skipped_no_crash(monkeypatch):
    """Una riga JSONL malformata viene saltata senza crash; le valide restano (§14/§4.7)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    lines = [
        "{ questo non e' JSON valido",                 # malformata
        "",                                            # riga vuota
        _nuclei_record(template_id="valid-one", severity="high"),
        json.dumps({"no-template-id": "x", "info": {}}),  # senza template-id
    ]
    monkeypatch.setattr(nuclei_mod, "_run_nuclei", lambda urls, out_path: lines)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)

    rule_ids = [f.rule_id for f in result.findings if f.module == "nuclei"]
    # solo il record valido produce un finding; nessun crash
    assert rule_ids == ["valid-one"]


def test_run_dedup_same_finding_id(monkeypatch):
    """Due record identici (stesso template-id + stessa location) → un solo Finding
    (dedup via finding_id §16)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    dup = _nuclei_record(template_id="dup-tpl", severity="medium",
                         matched="https://staging.example.com/x")
    monkeypatch.setattr(nuclei_mod, "_run_nuclei", lambda urls, out_path: [dup, dup])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    dup_findings = [f for f in result.findings if f.rule_id == "dup-tpl"]
    assert len(dup_findings) == 1


def test_finding_id_matches_baseline_formula(monkeypatch):
    """Il finding_id emesso coincide con baseline.diff.finding_id (§16 LOCKED)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule
    from bastione.baseline.diff import finding_id as baseline_finding_id

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_mod, "_run_nuclei",
                        lambda urls, out_path: [_nuclei_record(template_id="abc")])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    f = next(f for f in result.findings if f.module == "nuclei")
    assert f.finding_id == baseline_finding_id(f)


def test_finding_id_helper_locked_formula():
    """_finding_id segue la formula LOCKED §16 SENZA target."""
    from bastione.modules.nuclei.module import _finding_id
    loc = Location(url="https://staging.example.com/admin")
    expected = hashlib.sha256(
        f"nuclei:exposed-panel:{loc.canonical()}".encode()).hexdigest()[:16]
    assert _finding_id("nuclei", "exposed-panel", loc) == expected


def test_run_no_records_returns_empty(monkeypatch):
    """_run_nuclei ritorna [] (nessun match): 0 finding, nessun crash, nessuno SKIPPED."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(nuclei_mod, "_run_nuclei", lambda urls, out_path: [])

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = NucleiModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_output_path_under_run_dir_raw(monkeypatch, tmp_path):
    """L'output raw va in ctx.run_dir/raw/nuclei.jsonl (§14/§4)."""
    import bastione.modules.nuclei.module as nuclei_mod
    from bastione.modules.nuclei.module import NucleiModule

    monkeypatch.setattr(nuclei_mod.shutil, "which", lambda name: "/usr/bin/nuclei")
    captured: dict = {}

    def capture(urls, out_path):
        captured["out_path"] = Path(out_path)
        return []

    monkeypatch.setattr(nuclei_mod, "_run_nuclei", capture)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"], run_dir=tmp_path)
    NucleiModule().run(ctx)

    out = captured["out_path"]
    assert out.parent == tmp_path / "raw"
    assert out.name == "nuclei.jsonl"
    # la cartella raw/ deve esistere (creata dal modulo prima dell'invocazione)
    assert (tmp_path / "raw").is_dir()


# ─── (6) _run_nuclei — confine I/O: argv-list, no shell, degrado ─────────────

def test_run_nuclei_uses_argv_list_no_shell(monkeypatch):
    """_run_nuclei invoca subprocess con una LISTA di argv (mai shell=True): niente
    command injection (§14 guardrail subprocess sicuro)."""
    import bastione.modules.nuclei.module as nuclei_mod

    captured: dict = {}

    class FakeProc:
        stdout = ""
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(nuclei_mod.subprocess, "run", fake_run)
    nuclei_mod._run_nuclei(["https://staging.example.com/"], "out.jsonl")

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == "nuclei"
    # mai shell=True (niente interpolazione di shell sull'URL)
    assert captured["kwargs"].get("shell", False) is False


def test_run_nuclei_argv_has_restrictive_template_filters(monkeypatch):
    """REGRESSIONE (guardrail anti-MUTATING §14): `-include-tags safe` è ADDITIVO,
    non restrittivo. L'argv DEVE contenere filtri RESTRITTIVI reali — `-exclude-tags`
    con le categorie attive (intrusive/dos/fuzz/attack/sqli/xss/ssrf/rce/lfi) e un cap
    `-severity` che esclude high/critical — così i template active/exploit NON girano.

    Senza questi flag un modulo dichiarato PROBE eseguirebbe scansioni attive (payload
    crafted) violando il contratto di intrusione (§7)."""
    import bastione.modules.nuclei.module as nuclei_mod

    captured: dict = {}

    class FakeProc:
        stdout = ""
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return FakeProc()

    monkeypatch.setattr(nuclei_mod.subprocess, "run", fake_run)
    nuclei_mod._run_nuclei(["https://staging.example.com/"], "out.jsonl")

    argv = captured["argv"]

    # filtro restrittivo per tag: -exclude-tags con le categorie MUTATING
    assert "-exclude-tags" in argv
    excl = argv[argv.index("-exclude-tags") + 1]
    excl_tags = {t.strip() for t in excl.split(",")}
    for mutating in ("intrusive", "dos", "fuzz", "attack"):
        assert mutating in excl_tags, f"manca l'esclusione del tag MUTATING {mutating!r}"

    # cap di severità: niente exploit gravi (high/critical fuori)
    assert "-severity" in argv
    sev = argv[argv.index("-severity") + 1]
    sev_levels = {s.strip().lower() for s in sev.split(",")}
    assert "high" not in sev_levels
    assert "critical" not in sev_levels


def test_run_nuclei_degrades_on_oserror(monkeypatch):
    """Se subprocess.run solleva OSError (binario sparito a runtime), _run_nuclei
    degrada a [] senza crash (§4.7)."""
    import bastione.modules.nuclei.module as nuclei_mod

    def boom(argv, **kwargs):
        raise OSError("no such binary")

    monkeypatch.setattr(nuclei_mod.subprocess, "run", boom)
    assert nuclei_mod._run_nuclei(["https://staging.example.com/"], "out.jsonl") == []
