"""Test del kernel baseline & drift (§16) — il cuore di P7 ("solo delta").

Copriamo:
- `finding_id` stabile ed *esclusivo dell'evidenza*: stessa module/rule/location
  ma evidenza diversa → stesso id (tracciabilità nel tempo, §16);
- normalizzazione content-hash dei bundle (§5.2): lo stesso segreto in
  `index-ab12.js` e `index-cd34.js` produce lo stesso id (niente falsi NEW/FIXED
  ad ogni deploy);
- diff (§16): NEW quando assente; KNOWN/ACCEPTED ereditati con `first_seen`
  preservato; FIXED quando in baseline ma non nella run;
- posture DRIFT quando in baseline era `passed:true` e ora fallisce;
- `counts` (shape §24): new/known/fixed/drift + by_severity dei finding emessi.

Test OFFLINE puri: nessuna rete, nessun I/O salvo `tmp_path` per il round-trip
del file baseline.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from bastione.baseline.diff import (
    accept_finding,
    apply_baseline,
    finding_id,
    load_baseline,
    save_baseline,
)
from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck


NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)
EARLIER = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def make_finding(
    *,
    module="supabase",
    rule_id="RLS_DISABLED",
    location=None,
    evidence="evidenza-x",
    severity=Severity.HIGH,
    title="t",
    target="g",
):
    return Finding(
        finding_id="",  # ricalcolato da apply_baseline; qui placeholder
        module=module,
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        location=location or Location(endpoint="/rest/v1/clienti"),
        evidence=evidence,
        description="d",
    )


def make_posture(*, check_id="POSTURE_HSTS", passed=True, target="g"):
    return PostureCheck(
        check_id=check_id,
        title="t",
        passed=passed,
        severity_if_failed=Severity.HIGH,
        target=target,
        detail="dettaglio",
    )


# ─── finding_id (§16, LOCKED) ───────────────────────────────────────────────

def test_finding_id_is_16_hex_chars():
    fid = finding_id(make_finding())
    assert len(fid) == 16
    assert all(c in "0123456789abcdef" for c in fid)


def test_finding_id_excludes_evidence():
    # Stessa module/rule/location, evidenza diversa → STESSO id (§16):
    # l'evidenza è esclusa apposta per tracciare lo stesso problema nel tempo.
    a = make_finding(evidence="prima evidenza")
    b = make_finding(evidence="evidenza completamente diversa")
    assert finding_id(a) == finding_id(b)


def test_finding_id_normalizes_bundle_content_hash():
    # Lo stesso segreto in due bundle rinominati dal deploy → stesso id (§5.2):
    # senza, ogni build genererebbe un falso NEW + un falso FIXED. Il suffisso
    # content-hash è normalizzato da Location.canonical() (regex HASH_SEGMENT in
    # models.py, ≥6 esadecimali): index-<hash>.js → index.js.
    a = make_finding(location=Location(file="assets/index-ab12cd.js", line=10))
    b = make_finding(location=Location(file="assets/index-cd34ef.js", line=10))
    assert finding_id(a) == finding_id(b)


def test_finding_id_differs_on_rule_or_module():
    base = finding_id(make_finding(module="supabase", rule_id="RLS_DISABLED"))
    assert finding_id(make_finding(module="secrets", rule_id="RLS_DISABLED")) != base
    assert finding_id(make_finding(module="supabase", rule_id="OTHER")) != base


def test_finding_id_matches_documented_formula():
    # Difesa anti-regressione: replica la formula LOCKED del §16.
    from hashlib import sha256
    f = make_finding()
    expected = sha256(
        f"{f.module}:{f.rule_id}:{f.location.canonical()}".encode()
    ).hexdigest()[:16]
    assert finding_id(f) == expected


# ─── load_baseline / save_baseline (formato §16) ────────────────────────────

def test_load_baseline_empty_when_missing(tmp_path: Path):
    bl = load_baseline(tmp_path / "non-esiste.json")
    assert bl["findings"] == {}
    assert bl["posture"] == {}


def test_save_and_load_roundtrip(tmp_path: Path):
    path = tmp_path / "g.baseline.json"
    save_baseline(
        path,
        target="g",
        findings={"abc123": {"status": "known", "first_seen": EARLIER.isoformat()}},
        posture={"POSTURE_HSTS": {"passed": True}},
        updated_at=NOW,
    )
    bl = load_baseline(path)
    assert bl["target"] == "g"
    assert bl["findings"]["abc123"]["status"] == "known"
    assert bl["posture"]["POSTURE_HSTS"]["passed"] is True
    # Formato §16: il file non contiene MAI evidenze (solo id/status/date).
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "evidence" not in json.dumps(raw)


# ─── apply_baseline: diff dei finding (§16) ─────────────────────────────────

def test_new_when_absent_from_baseline():
    f = make_finding()
    res = apply_baseline([f], [], load_baseline(Path("nope")), now=NOW)
    out = res.findings[0]
    assert out.status is Status.NEW
    assert out.first_seen == NOW
    assert out.last_seen == NOW
    assert out.finding_id == finding_id(f)


def test_known_inherited_with_first_seen_preserved():
    f = make_finding()
    fid = finding_id(f)
    baseline = {
        "target": "g",
        "findings": {fid: {"status": "known", "first_seen": EARLIER.isoformat()}},
        "posture": {},
    }
    res = apply_baseline([f], [], baseline, now=NOW)
    out = res.findings[0]
    assert out.status is Status.KNOWN
    assert out.first_seen == EARLIER       # ereditato, non sovrascritto
    assert out.last_seen == NOW            # aggiornato a "ora"


def test_accepted_inherited_with_first_seen_preserved():
    f = make_finding()
    fid = finding_id(f)
    baseline = {
        "target": "g",
        "findings": {fid: {"status": "accepted", "first_seen": EARLIER.isoformat()}},
        "posture": {},
    }
    res = apply_baseline([f], [], baseline, now=NOW)
    out = res.findings[0]
    assert out.status is Status.ACCEPTED
    assert out.first_seen == EARLIER
    assert out.last_seen == NOW


def test_fixed_when_in_baseline_but_not_in_run():
    f = make_finding()
    fid = finding_id(f)
    baseline = {
        "target": "g",
        "findings": {fid: {"status": "known", "first_seen": EARLIER.isoformat()}},
        "posture": {},
    }
    # La run NON contiene f → deve emergere come FIXED.
    res = apply_baseline([], [], baseline, now=NOW)
    assert len(res.fixed) == 1
    assert res.fixed[0].finding_id == fid
    assert res.fixed[0].status is Status.FIXED
    # Un FIXED non è un finding "emesso": non compare in res.findings.
    assert res.findings == []


def test_fixed_first_seen_preserved():
    f = make_finding()
    fid = finding_id(f)
    baseline = {
        "target": "g",
        "findings": {fid: {"status": "accepted", "first_seen": EARLIER.isoformat()}},
        "posture": {},
    }
    res = apply_baseline([], [], baseline, now=NOW)
    assert res.fixed[0].first_seen == EARLIER
    assert res.fixed[0].last_seen == NOW


# ─── apply_baseline: posture DRIFT (§16) ────────────────────────────────────

def test_posture_drift_when_was_passed_now_failed():
    pc = make_posture(check_id="POSTURE_HSTS", passed=False)
    baseline = {
        "target": "g",
        "findings": {},
        "posture": {"POSTURE_HSTS": {"passed": True}},
    }
    res = apply_baseline([], [pc], baseline, now=NOW)
    assert res.posture_checks[0].drift is True


def test_no_drift_when_still_passing():
    pc = make_posture(check_id="POSTURE_HSTS", passed=True)
    baseline = {
        "target": "g",
        "findings": {},
        "posture": {"POSTURE_HSTS": {"passed": True}},
    }
    res = apply_baseline([], [pc], baseline, now=NOW)
    assert res.posture_checks[0].drift is False


def test_no_drift_when_failed_already_failing_in_baseline():
    # In baseline era già failed → non è una *regressione*, niente drift.
    pc = make_posture(check_id="POSTURE_HSTS", passed=False)
    baseline = {
        "target": "g",
        "findings": {},
        "posture": {"POSTURE_HSTS": {"passed": False}},
    }
    res = apply_baseline([], [pc], baseline, now=NOW)
    assert res.posture_checks[0].drift is False


def test_no_drift_when_check_absent_from_baseline():
    # Nuovo check non presente in baseline e fallito: non è drift (non c'era
    # un "passed:true" da cui regredire).
    pc = make_posture(check_id="POSTURE_NEW", passed=False)
    res = apply_baseline([], [pc], load_baseline(Path("nope")), now=NOW)
    assert res.posture_checks[0].drift is False


# ─── apply_baseline: counts (shape §24) ─────────────────────────────────────

def test_counts_shape_and_values():
    f_new = make_finding(rule_id="NEW_ONE", severity=Severity.CRITICAL)
    f_known = make_finding(rule_id="KNOWN_ONE", severity=Severity.MEDIUM)
    f_fixed = make_finding(rule_id="FIXED_ONE")

    baseline = {
        "target": "g",
        "findings": {
            finding_id(f_known): {"status": "known", "first_seen": EARLIER.isoformat()},
            finding_id(f_fixed): {"status": "known", "first_seen": EARLIER.isoformat()},
        },
        "posture": {"POSTURE_HSTS": {"passed": True}},
    }
    posture = [make_posture(check_id="POSTURE_HSTS", passed=False)]  # → drift

    res = apply_baseline([f_new, f_known], posture, baseline, now=NOW)
    c = res.counts
    assert c["new"] == 1
    assert c["known"] == 1
    assert c["fixed"] == 1
    assert c["drift"] == 1
    # by_severity conta SOLO i finding emessi (new+known), non i fixed né i posture.
    assert c["by_severity"]["critical"] == 1   # f_new
    assert c["by_severity"]["medium"] == 1     # f_known
    assert c["by_severity"]["high"] == 0
    assert c["by_severity"]["low"] == 0
    assert c["by_severity"]["info"] == 0
    # new_by_severity conta i SOLI finding NEW (gate CI §22): f_known NON entra.
    assert c["new_by_severity"]["critical"] == 1   # f_new
    assert c["new_by_severity"]["medium"] == 0     # f_known escluso
    assert c["new_by_severity"]["high"] == 0
    assert c["new_by_severity"]["low"] == 0
    assert c["new_by_severity"]["info"] == 0


# ─── accept_finding: promozione pura KNOWN→ACCEPTED (§16 gradino 2) ──────────

def test_accept_finding_promotes_single_known():
    baseline = {
        "target": "g",
        "findings": {
            "id_a": {"status": "known", "first_seen": EARLIER.isoformat()},
            "id_b": {"status": "known", "first_seen": EARLIER.isoformat()},
        },
        "posture": {},
    }
    assert accept_finding(baseline, "id_a") is True
    assert baseline["findings"]["id_a"]["status"] == "accepted"
    # NON tocca gli altri finding (promozione puntuale).
    assert baseline["findings"]["id_b"]["status"] == "known"


def test_accept_finding_unknown_id_returns_false():
    baseline = {"target": "g", "findings": {"id_a": {"status": "known"}}, "posture": {}}
    assert accept_finding(baseline, "nope") is False
    # baseline invariata.
    assert baseline["findings"]["id_a"]["status"] == "known"


def test_accept_finding_already_accepted_is_idempotent():
    baseline = {"target": "g", "findings": {"id_a": {"status": "accepted"}}, "posture": {}}
    assert accept_finding(baseline, "id_a") is True
    assert baseline["findings"]["id_a"]["status"] == "accepted"


def test_counts_accepted_does_not_count_as_known():
    # ACCEPTED è "rumore noto silenziato": non gonfia il contatore 'known'.
    f = make_finding()
    baseline = {
        "target": "g",
        "findings": {finding_id(f): {"status": "accepted", "first_seen": EARLIER.isoformat()}},
        "posture": {},
    }
    res = apply_baseline([f], [], baseline, now=NOW)
    assert res.counts["known"] == 0
    # ma il finding accepted è comunque emesso e conta nel by_severity.
    assert res.counts["by_severity"]["high"] == 1
