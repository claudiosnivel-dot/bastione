"""Test minimi per i contratti dati (§5.2–§5.6).

Concentrati sul comportamento, non sulle dichiarazioni: la normalizzazione
content-hash di `Location.canonical()` (§5.2, è ciò che rende stabile il
finding_id), i default che le fasi successive danno per scontati (status NEW,
intrusione READ_ONLY, drift False) e la coercizione di Severity da stringa che
`config.py` usa per `notify_min_severity`.
"""

from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from bastione.enums import Confidence, IntrusionLevel, Severity, Status
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    LivenessResult,
    ModuleResult,
    PostureCheck,
    RawSecret,
    RunContext,
    RunSummary,
    TableExpectation,
    TargetConfig,
    TextAsset,
)


# ─── Location.canonical (§5.2) — il cuore della stabilità del finding_id ───

def test_canonical_strips_bundle_content_hash():
    # "assets/index-ab12cd.js" → il suffisso content-hash è rimosso.
    loc = Location(file="assets/index-ab12cd.js")
    assert "ab12cd" not in loc.canonical()
    assert "assets/index.js" in loc.canonical()


def test_canonical_is_stable_across_redeploys():
    # Stesso problema, bundle rinominato a ogni build → STESSO canonical,
    # altrimenti P7 (solo delta) crollerebbe con falsi NEW/FIXED (§16).
    a = Location(file="assets/index-ab12cd.js", endpoint="/rest/v1/clienti")
    b = Location(file="assets/index-ff9900.js", endpoint="/rest/v1/clienti")
    assert a.canonical() == b.canonical()


def test_canonical_excludes_evidence_and_joins_fields():
    loc = Location(url="https://x", endpoint="/e", file="a.js", line=7)
    assert loc.canonical() == "https://x|/e|a.js|7"


# ─── Finding (§5.3) — default su cui contano BASELINE/NORMALIZE ───

def test_finding_defaults():
    f = Finding(
        finding_id="deadbeef",
        module="supabase",
        rule_id="RLS_DISABLED",
        title="RLS disabilitata",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        target="gestionale",
        location=Location(endpoint="/rest/v1/clienti"),
        evidence="redacted",
        description="…",
    )
    assert f.status is Status.NEW
    assert f.intrusion_used is IntrusionLevel.READ_ONLY
    assert f.owasp == []
    assert f.gdpr_relevant is False
    assert f.remediation_ref is None
    assert f.first_seen is None and f.last_seen is None


# ─── PostureCheck (§5.4) — drift parte False, lo valorizza POSTURE ───

def test_posturecheck_drift_defaults_false():
    pc = PostureCheck(
        check_id="POSTURE_HSTS",
        title="HSTS presente",
        passed=True,
        severity_if_failed=Severity.MEDIUM,
        target="gestionale",
        detail="header presente",
    )
    assert pc.drift is False


# ─── Fingerprint (§5.5) — default che pilotano should_run (§9) ───

def test_fingerprint_defaults():
    fp = Fingerprint(target="gestionale", resolved_urls=["https://x"])
    assert fp.is_supabase is False
    assert fp.anon_key is None
    assert fp.is_wordpress is False
    assert fp.endpoints == [] and fp.technologies == []


# ─── TargetConfig (§5.6) — coercizione Severity e default ───

def test_targetconfig_defaults():
    cfg = TargetConfig(
        name="gestionale",
        base_url="https://staging.example",
        environment="staging",
        ownership="owned",
    )
    assert cfg.ownership_token is None
    assert cfg.notify_channel == "none"
    assert cfg.notify_min_severity is Severity.HIGH
    assert cfg.expectations == [] and cfg.modules_disabled == []


def test_targetconfig_coerces_severity_name_from_toml():
    # Il TOML porta min_severity = "high": deve diventare Severity.HIGH.
    cfg = TargetConfig(
        name="g", base_url="https://x", environment="staging",
        ownership="owned", notify_min_severity="high",
    )
    assert cfg.notify_min_severity is Severity.HIGH


def test_targetconfig_rejects_invalid_environment():
    with pytest.raises(ValidationError):
        TargetConfig(name="g", base_url="https://x",
                     environment="prod", ownership="owned")


def test_table_expectation_defaults_deny():
    te = TableExpectation(name="clienti")
    assert te.anon_select is False and te.anon_insert is False


# ─── Aggregati / supporto (§5.5–§5.6) ───

def test_module_result_is_namedtuple():
    mr = ModuleResult(findings=[], posture_checks=[])
    assert mr.findings == [] and mr.posture_checks == []
    assert isinstance(mr, tuple)  # NamedTuple


def test_runcontext_resolves_forward_ref_to_targetconfig(tmp_path: Path):
    cfg = TargetConfig(name="g", base_url="https://x",
                       environment="staging", ownership="owned")
    ctx = RunContext(
        target_cfg=cfg,
        fingerprint=Fingerprint(target="g", resolved_urls=[]),
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=tmp_path,
        ownership_verified=False,
    )
    assert ctx.target_cfg.name == "g"
    assert ctx.run_dir == tmp_path


def test_support_models_construct():
    assert TextAsset(source="u", content="x").content == "x"
    rs = RawSecret(detector_id="D", value="v", location=Location())
    assert rs.entropy is None
    assert LivenessResult(alive=True).mode is None
    rsum = RunSummary(target="g", posture_score=80.0, counts={},
                      drift_count=0, report_path="r.html")
    assert rsum.posture_score == 80.0
