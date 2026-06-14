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
    Applicability,
    Finding,
    Fingerprint,
    FixEntry,
    FixPlan,
    FixType,
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
    Verification,
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


# ─── 18-bis.3 Agent Remediation Bundle — contratti dati (shape LOCKED) ───

def test_fixtype_values_locked():
    # I valori finiscono in fix-plan.json (contratto versionato): LOCKED.
    assert FixType.SQL_MIGRATION.value == "sql_migration"
    assert FixType.CONFIG_CHANGE.value == "config_change"
    assert FixType.INFRA_CHANGE.value == "infra_change"
    assert FixType.CODE_CHANGE.value == "code_change"
    assert FixType.SECRET_ROTATION.value == "secret_rotation"


def test_applicability_values_locked():
    assert Applicability.AGENT.value == "agent"
    assert Applicability.HUMAN.value == "human"
    assert Applicability.AGENT_HUMAN.value == "agent+human"


def test_verification_defaults_method_rescan():
    v = Verification(command="bastione verify --target g", expect="abc → FIXED")
    assert v.method == "bastione-rescan"
    assert v.command == "bastione verify --target g"
    assert v.expect == "abc → FIXED"


def test_fixentry_defaults_depends_on_empty():
    fe = FixEntry(
        finding_id="abc123",
        rule_id="RLS_DISABLED",
        severity=Severity.HIGH,
        title="RLS disabilitata",
        fix_type=FixType.SQL_MIGRATION,
        applicable_by=Applicability.AGENT,
        priority=2,
        context={"resource": "clienti"},
        instructions={"migration_sql": "ALTER TABLE ..."},
        verification=Verification(command="bastione verify --target g", expect="→ FIXED"),
    )
    assert fe.depends_on == []
    assert fe.priority == 2
    assert fe.fix_type is FixType.SQL_MIGRATION


def test_fixplan_schema_version_default():
    plan = FixPlan(
        target="g",
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        run_dir="runs/g/2026",
        summary={"total": 0},
        fixes=[],
    )
    assert plan.schema_version == "bastione-fixplan/1"
    assert plan.fixes == []


def test_fixplan_roundtrip_json_reloadable():
    # fix-plan.json deve essere serializzabile e ricaricabile in FixPlan.
    plan = FixPlan(
        target="g",
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        run_dir="runs/g/2026",
        summary={"total": 1, "agent_applicable": 1, "human_required": 0},
        fixes=[
            FixEntry(
                finding_id="abc123",
                rule_id="RLS_DISABLED",
                severity=Severity.HIGH,
                title="RLS",
                fix_type=FixType.SQL_MIGRATION,
                applicable_by=Applicability.AGENT,
                priority=2,
                context={"resource": "clienti"},
                instructions={"migration_sql": "ALTER TABLE ..."},
                verification=Verification(command="c", expect="e"),
            )
        ],
    )
    dumped = plan.model_dump_json()
    reloaded = FixPlan.model_validate_json(dumped)
    assert reloaded.schema_version == "bastione-fixplan/1"
    assert reloaded.fixes[0].fix_type is FixType.SQL_MIGRATION
    assert reloaded.fixes[0].finding_id == "abc123"
