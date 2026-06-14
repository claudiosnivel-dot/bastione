"""Test del modulo ZAP (§14 del blueprint) — OFFLINE.

ZAP è un proxy/scanner maturo (OWASP). Bastione gli mette intorno una colla
sottile (§14): which → skip onesto, invocazione passive documentata con report
JSON in run_dir/raw/, parse+normalize → Finding[]. Gira a PROBE (passive scan).
Active/attack = MUTATING (gated) → NON in questo step.

NOTA ambiente: ZAP NON è installato qui, quindi il path REALE dominante è SKIPPED
(binario assente). I test coprono ENTRAMBI i path:

A. **SKIPPED** — sotto il tetto read-only (self-gate) OPPURE binario assente
   (which None): si emette UN Finding INFO `ZAP_SKIPPED` e si prosegue. Nessun
   authorize, nessun subprocess.

B. **parse+normalize** — which presente + ctx a PROBE/ownership + il confine I/O
   (_run_zap a livello modulo) monkeypatchato che ritorna un report JSON ZAP
   realistico: i Finding attesi con risk High/Medium/Low/Informational → Severity
   e dedup via finding_id (§16). Più: report malformato → niente crash.

Tutto OFFLINE: nessun subprocess reale, nessuna rete, nessun daemon avviato.
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


# ─── un report JSON realistico di zap-baseline ──────────────────────────────

def _zap_report(*alerts: dict) -> dict:
    """Report JSON nel formato `zap-baseline.py -J` / ZAP report JSON (§14):
    `{"site": [{"@name": ..., "alerts": [...]}]}`."""
    return {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "https://staging.example.com",
                "@host": "staging.example.com",
                "alerts": list(alerts),
            }
        ],
    }


def _zap_alert(
    *,
    pluginid: str = "10038",
    name: str = "Content Security Policy (CSP) Header Not Set",
    riskcode: str = "2",
    riskdesc: str = "Medium (High)",
    url: str = "https://staging.example.com/",
) -> dict:
    """Un alert ZAP con uno o più `instances` (§14)."""
    return {
        "pluginid": pluginid,
        "alertRef": pluginid,
        "alert": name,
        "name": name,
        "riskcode": riskcode,
        "riskdesc": riskdesc,
        "instances": [{"uri": url, "method": "GET"}],
    }


# ─── (1) attributi di classe ────────────────────────────────────────────────

def test_zap_module_name_and_intrusion():
    """name='zap', max_intrusion=PROBE (§14)."""
    from bastione.modules.zap.module import ZapModule
    assert ZapModule.name == "zap"
    assert ZapModule.max_intrusion == IntrusionLevel.PROBE


def test_zap_registered_in_registry():
    """L'import del modulo registra ZapModule in REGISTRY (§9)."""
    import importlib

    import bastione.modules.zap.module as zap_mod
    importlib.reload(zap_mod)
    from bastione.modules.base import REGISTRY
    assert "zap" in REGISTRY


# ─── (2) should_run ─────────────────────────────────────────────────────────

def test_should_run_true_when_resolved_urls():
    from bastione.modules.zap.module import ZapModule
    fp = Fingerprint(target="t", resolved_urls=["https://staging.example.com/"])
    assert ZapModule().should_run(fp, _make_cfg()) is True


def test_should_run_false_when_no_resolved_urls():
    from bastione.modules.zap.module import ZapModule
    fp = Fingerprint(target="t", resolved_urls=[])
    assert ZapModule().should_run(fp, _make_cfg()) is False


# ─── (3) path A — SKIPPED ────────────────────────────────────────────────────

def test_run_read_only_emits_skipped_no_subprocess(monkeypatch):
    """Tetto READ_ONLY (self-gate): Finding INFO ZAP_SKIPPED, nessun subprocess (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    called: list = []
    monkeypatch.setattr(zap_mod, "_run_zap",
                        lambda urls, out_path: called.append(urls) or None)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=False)
    result = ZapModule().run(ctx)

    assert isinstance(result, ModuleResult)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "ZAP_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.module == "zap"
    assert called == []


def test_run_probe_without_ownership_emits_skipped(monkeypatch):
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    called: list = []
    monkeypatch.setattr(zap_mod, "_run_zap",
                        lambda urls, out_path: called.append(urls) or None)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)
    result = ZapModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "ZAP_SKIPPED"
    assert called == []


def test_run_binary_absent_emits_skipped(monkeypatch):
    """which(...) None (binario assente — il path reale in questo ambiente): SKIPPED
    onesto, nessun subprocess, nessun daemon (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: None)
    called: list = []
    monkeypatch.setattr(zap_mod, "_run_zap",
                        lambda urls, out_path: called.append(urls) or None)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = ZapModule().run(ctx)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "ZAP_SKIPPED"
    assert f.severity == Severity.INFO
    assert "assente" in f.description.lower() or "binario" in f.description.lower()
    assert called == []


def test_skipped_finding_has_finding_id(monkeypatch):
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: None)
    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    assert result.findings[0].finding_id != ""


# ─── (4) backstop del gate ──────────────────────────────────────────────────

def test_run_gate_denied_emits_skipped_no_crash(monkeypatch):
    """authorize(PROBE) → IntrusionDenied (backstop §7): SKIPPED, niente crash, niente
    subprocess (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")

    def deny(level, ctx):
        raise IntrusionDenied("negato dal gate (test)")

    monkeypatch.setattr(zap_mod, "authorize", deny)
    called: list = []
    monkeypatch.setattr(zap_mod, "_run_zap",
                        lambda urls, out_path: called.append(urls) or None)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "ZAP_SKIPPED"
    assert called == []


# ─── (5) path B — parse+normalize ───────────────────────────────────────────

def test_run_parses_alerts_into_findings(monkeypatch):
    """which presente + PROBE/ownership + _run_zap monkeypatchato: ogni alert →
    un Finding con severity mappata dal riskcode (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    report = _zap_report(
        _zap_alert(pluginid="10038", name="CSP Header Not Set", riskcode="2"),
        _zap_alert(pluginid="10020", name="X-Frame-Options Header Not Set",
                   riskcode="1", url="https://staging.example.com/page"),
    )
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)

    rule_ids = {f.rule_id for f in result.findings}
    assert {"10038", "10020"} <= rule_ids
    assert "ZAP_SKIPPED" not in rule_ids
    for f in (f for f in result.findings if f.module == "zap"):
        assert f.confidence == Confidence.FIRM
        assert f.intrusion_used == IntrusionLevel.PROBE


@pytest.mark.parametrize("riskcode,expected", [
    ("0", Severity.INFO),       # Informational
    ("1", Severity.LOW),        # Low
    ("2", Severity.MEDIUM),     # Medium
    ("3", Severity.HIGH),       # High
    ("9", Severity.INFO),       # sconosciuto → INFO prudenziale
])
def test_risk_mapping_by_riskcode(monkeypatch, riskcode, expected):
    """Mapping rischio ZAP → Severity via riskcode (§14): 0=Info,1=Low,2=Medium,3=High."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    report = _zap_report(_zap_alert(riskcode=riskcode))
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    zap_findings = [f for f in result.findings if f.module == "zap"]
    assert len(zap_findings) == 1
    assert zap_findings[0].severity == expected


def test_risk_mapping_by_riskdesc_when_no_riskcode(monkeypatch):
    """Se manca il riskcode, il mapping ripiega sul testo riskdesc (High/Medium/Low/
    Informational) (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    alert = _zap_alert(riskdesc="High (Medium)")
    alert.pop("riskcode")
    report = _zap_report(alert)
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    zap_findings = [f for f in result.findings if f.module == "zap"]
    assert len(zap_findings) == 1
    assert zap_findings[0].severity == Severity.HIGH


def test_run_location_is_instance_uri(monkeypatch):
    """La location del Finding è l'URI dell'istanza dell'alert (§14)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    url = "https://staging.example.com/admin"
    report = _zap_report(_zap_alert(url=url))
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    f = next(f for f in result.findings if f.module == "zap")
    assert f.location.url == url


def test_run_malformed_report_no_crash(monkeypatch):
    """Report None / non-dict / senza 'site' → niente crash, 0 finding ZAP (§4.7)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")

    for bad in (None, [], {"unexpected": "shape"}, {"site": "not-a-list"}):
        monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path, b=bad: b)
        ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
        result = ZapModule().run(ctx)
        zap_findings = [f for f in result.findings if f.module == "zap"]
        assert zap_findings == []


def test_run_malformed_alert_skipped(monkeypatch):
    """Un alert senza pluginid/instances viene saltato; gli altri restano (§4.7)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    good = _zap_alert(pluginid="10038")
    report = _zap_report({"garbage": "no fields"}, good)
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    rule_ids = [f.rule_id for f in result.findings if f.module == "zap"]
    assert rule_ids == ["10038"]


def test_run_dedup_same_finding_id(monkeypatch):
    """Stesso pluginid + stessa location (due istanze identiche) → un solo Finding
    (dedup via finding_id §16)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    alert = _zap_alert(pluginid="dup", url="https://staging.example.com/x")
    alert["instances"] = [
        {"uri": "https://staging.example.com/x", "method": "GET"},
        {"uri": "https://staging.example.com/x", "method": "GET"},
    ]
    report = _zap_report(alert)
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    dup_findings = [f for f in result.findings if f.rule_id == "dup"]
    assert len(dup_findings) == 1


def test_finding_id_matches_baseline_formula(monkeypatch):
    """Il finding_id emesso coincide con baseline.diff.finding_id (§16 LOCKED)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule
    from bastione.baseline.diff import finding_id as baseline_finding_id

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    report = _zap_report(_zap_alert(pluginid="42"))
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: report)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    f = next(f for f in result.findings if f.module == "zap")
    assert f.finding_id == baseline_finding_id(f)


def test_finding_id_helper_locked_formula():
    from bastione.modules.zap.module import _finding_id
    loc = Location(url="https://staging.example.com/admin")
    expected = hashlib.sha256(
        f"zap:10038:{loc.canonical()}".encode()).hexdigest()[:16]
    assert _finding_id("zap", "10038", loc) == expected


def test_run_no_alerts_returns_empty(monkeypatch):
    """Report con site ma senza alert: 0 finding, nessun crash, nessuno SKIPPED."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    monkeypatch.setattr(zap_mod, "_run_zap", lambda urls, out_path: _zap_report())

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    result = ZapModule().run(ctx)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_output_path_under_run_dir_raw(monkeypatch, tmp_path):
    """L'output raw va in ctx.run_dir/raw/zap.json (§14/§4)."""
    import bastione.modules.zap.module as zap_mod
    from bastione.modules.zap.module import ZapModule

    monkeypatch.setattr(zap_mod.shutil, "which", lambda name: "/usr/bin/zap-baseline.py")
    captured: dict = {}

    def capture(urls, out_path):
        captured["out_path"] = Path(out_path)
        return _zap_report()

    monkeypatch.setattr(zap_mod, "_run_zap", capture)

    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"], run_dir=tmp_path)
    ZapModule().run(ctx)

    out = captured["out_path"]
    assert out.parent == tmp_path / "raw"
    assert out.name == "zap.json"
    assert (tmp_path / "raw").is_dir()


# ─── (6) _run_zap — confine I/O: argv-list, no shell, degrado ────────────────

def test_run_zap_uses_argv_list_no_shell(monkeypatch, tmp_path):
    """_run_zap invoca subprocess con una LISTA di argv (mai shell=True): niente
    command injection (§14 guardrail subprocess sicuro). Il parser legge il JSON
    dal file di report, non dallo stdout.

    Il fake-subprocess scrive il report ESATTAMENTE dove gli argv lo istruiscono
    (bare-name `-J` relativo a cwd), NON pre-scrivendo a mano in out_path: così se
    scrittura e lettura puntassero a path diversi il test FALLIREBBE (no falso-verde)."""
    import bastione.modules.zap.module as zap_mod

    captured: dict = {}
    out_path = tmp_path / "raw" / "zap.json"

    class FakeProc:
        stdout = ""
        returncode = 0

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        # Emula zap-baseline.py: `-J <bare-name>` scritto nella SUA working dir (cwd),
        # non in un path assoluto. Il bug originale leggeva da out_path assoluto.
        idx = argv.index("-J")
        report_name = argv[idx + 1]
        cwd = Path(kwargs["cwd"])
        (cwd / report_name).write_text(
            json.dumps(_zap_report(_zap_alert())), encoding="utf-8")
        return FakeProc()

    monkeypatch.setattr(zap_mod.subprocess, "run", fake_run)
    report = zap_mod._run_zap(["https://staging.example.com/"], str(out_path))

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert captured["kwargs"].get("shell", False) is False
    # il report è stato riletto dallo STESSO file scritto dal tool (path allineati)
    assert isinstance(report, dict) and "site" in report


def test_run_zap_writes_and_reads_same_path(monkeypatch, tmp_path):
    """REGRESSIONE (path mismatch): zap-baseline risolve `-J <bare-name>` rispetto
    alla propria cwd; _run_zap DEVE lanciarlo con cwd = dir di out_path così che il
    file scritto dal tool e quello riletto coincidano, e l'artefatto raw/ atterri in
    run_dir/raw/ (§4). Se _run_zap leggesse da un path diverso da quello dove il tool
    scrive → ritornerebbe None e il file non esisterebbe."""
    import bastione.modules.zap.module as zap_mod

    out_path = tmp_path / "rundir" / "raw" / "zap.json"

    class FakeProc:
        stdout = ""
        returncode = 0

    def fake_run(argv, **kwargs):
        # Il tool reale NON onora path assoluti in -J: scrive il bare-name in cwd.
        idx = argv.index("-J")
        report_name = argv[idx + 1]
        # -J deve essere SOLO il bare-name (non un path assoluto/relativo annidato)
        assert report_name == "zap.json"
        # subprocess deve girare con cwd = la dir di out_path
        cwd = Path(kwargs["cwd"])
        assert cwd == out_path.parent
        (cwd / report_name).write_text(
            json.dumps(_zap_report(_zap_alert(pluginid="99"))), encoding="utf-8")
        return FakeProc()

    monkeypatch.setattr(zap_mod.subprocess, "run", fake_run)
    report = zap_mod._run_zap(["https://staging.example.com/"], str(out_path))

    # report letto con successo (path allineati) e artefatto presente in run_dir/raw/
    assert isinstance(report, dict)
    assert report["site"][0]["alerts"][0]["pluginid"] == "99"
    assert out_path.exists()


def test_run_zap_degrades_on_oserror(monkeypatch):
    """Se subprocess.run solleva OSError, _run_zap degrada a None senza crash (§4.7)."""
    import bastione.modules.zap.module as zap_mod

    def boom(argv, **kwargs):
        raise OSError("no such binary")

    monkeypatch.setattr(zap_mod.subprocess, "run", boom)
    assert zap_mod._run_zap(["https://staging.example.com/"], "out.json") is None
