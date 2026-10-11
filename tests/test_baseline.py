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


# ─── FIXED solo se RI-VERIFICATO (R6, validazione live M4+M5 · S16) ─────────
#
# Un finding sparito dalla run è FIXED solo se la run POTEVA ri-osservarlo: il suo
# modulo ha girato senza MODULE_ERROR/`*_SKIPPED` e il livello d'intrusione con cui
# era stato trovato è ≤ al tetto della run corrente. Altrimenti NON è risolto: è
# "non ri-verificato" (resta aperto, mai presentato come chiuso — Missione §5).

from bastione.baseline.diff import ReverifyScope  # noqa: E402
from bastione.enums import IntrusionLevel  # noqa: E402


def _bl_entry(*, module="supabase", rule_id="STORAGE_PUBLIC_LISTABLE",
              intrusion="probe", status="known"):
    entry = {"status": status, "first_seen": EARLIER.isoformat(),
             "last_seen": EARLIER.isoformat(), "rule_id": rule_id, "module": module}
    if intrusion is not None:
        entry["intrusion_used"] = intrusion
    return entry


def _scope(level=IntrusionLevel.READ_ONLY, modules=("supabase",)):
    return ReverifyScope(max_intrusion=level, modules_ok=frozenset(modules))


def test_probe_finding_not_fixed_by_read_only_run():
    # Il cuore del difetto: `verify` (READ_ONLY) dava FIXED a un finding PROBE mai
    # ri-controllato. Ora resta aperto come "non ri-verificato".
    baseline = {"target": "g", "findings": {"id_p": _bl_entry()}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW, scope=_scope())
    assert res.fixed == []
    assert [f.finding_id for f in res.not_reverified] == ["id_p"]
    shell = res.not_reverified[0]
    assert shell.status is Status.KNOWN          # resta aperto (status ereditato)
    assert shell.rule_id == "STORAGE_PUBLIC_LISTABLE"
    assert shell.module == "supabase"
    assert shell.first_seen == EARLIER
    assert shell.last_seen == EARLIER            # NON visto ora: last_seen invariato
    assert "probe" in shell.description
    assert res.counts["fixed"] == 0
    assert res.counts["not_reverified"] == 1


def test_probe_finding_fixed_when_run_reaches_probe():
    baseline = {"target": "g", "findings": {"id_p": _bl_entry()}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW,
                         scope=_scope(IntrusionLevel.PROBE))
    assert [f.finding_id for f in res.fixed] == ["id_p"]
    assert res.not_reverified == []
    assert res.counts["fixed"] == 1
    assert res.counts["not_reverified"] == 0


def test_mutating_finding_not_fixed_by_probe_run():
    baseline = {"target": "g", "findings": {
        "id_m": _bl_entry(rule_id="RLS_WRITE_OPEN", intrusion="mutating")}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW,
                         scope=_scope(IntrusionLevel.PROBE))
    assert res.fixed == []
    assert [f.finding_id for f in res.not_reverified] == ["id_m"]


def test_read_only_finding_fixed_by_read_only_run():
    baseline = {"target": "g", "findings": {
        "id_r": _bl_entry(rule_id="RLS_DISABLED", intrusion="read-only")}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW, scope=_scope())
    assert [f.finding_id for f in res.fixed] == ["id_r"]


def test_finding_not_fixed_when_its_module_did_not_run():
    # Recon fallito / modulo non selezionato / MODULE_ERROR / *_SKIPPED: il modulo
    # non ha ri-controllato nulla → nessun FIXED (prima: sito giù = tutto FIXED).
    baseline = {"target": "g", "findings": {
        "id_r": _bl_entry(rule_id="RLS_DISABLED", intrusion="read-only")}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW,
                         scope=_scope(IntrusionLevel.MUTATING, modules=()))
    assert res.fixed == []
    assert [f.finding_id for f in res.not_reverified] == ["id_r"]
    assert "supabase" in res.not_reverified[0].description


def test_legacy_entry_without_intrusion_is_read_only():
    # Baseline scritte prima di S16 non hanno `intrusion_used`: si assume READ_ONLY
    # (comportamento storico) per non bloccarle per sempre in "non ri-verificato".
    baseline = {"target": "g", "findings": {
        "id_l": _bl_entry(rule_id="RLS_DISABLED", intrusion=None)}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW, scope=_scope())
    assert [f.finding_id for f in res.fixed] == ["id_l"]


def test_unknown_intrusion_value_is_conservative():
    # Valore illeggibile/manomesso: non si concede un FIXED non guadagnato (R6).
    baseline = {"target": "g", "findings": {
        "id_x": _bl_entry(intrusion="boh")}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW,
                         scope=_scope(IntrusionLevel.PROBE))
    assert res.fixed == []
    assert [f.finding_id for f in res.not_reverified] == ["id_x"]


def test_accepted_entry_not_reverified_keeps_accepted_status():
    baseline = {"target": "g", "findings": {"id_a": _bl_entry(status="accepted")},
                "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW, scope=_scope())
    assert res.not_reverified[0].status is Status.ACCEPTED


def test_no_scope_keeps_legacy_behaviour():
    # Senza scope (chiamanti storici) ogni id sparito resta FIXED come prima.
    baseline = {"target": "g", "findings": {"id_p": _bl_entry()}, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW)
    assert [f.finding_id for f in res.fixed] == ["id_p"]
    assert res.not_reverified == []


def test_seen_finding_unaffected_by_scope():
    # Un finding ri-osservato resta KNOWN a prescindere dallo scope.
    f = make_finding(rule_id="STORAGE_PUBLIC_LISTABLE")
    baseline = {"target": "g", "findings": {finding_id(f): _bl_entry()}, "posture": {}}
    res = apply_baseline([f], [], baseline, now=NOW, scope=_scope())
    assert [x.status for x in res.findings] == [Status.KNOWN]
    assert res.fixed == [] and res.not_reverified == []


# ─── S16 blind-review: limiti della run, livello legacy, livello di osservazione ─

from bastione.baseline.diff import (  # noqa: E402
    endpoint_keys,
    observation_level,
    reverify_scope_from_run,
)


def _limit_finding(rule_id, endpoint, *, module="supabase",
                   level=IntrusionLevel.PROBE):
    f = make_finding(module=module, rule_id=rule_id,
                     location=Location(endpoint=endpoint), severity=Severity.INFO)
    f.intrusion_used = level
    return f


def _entry_at(endpoint, *, rule_id="STORAGE_PUBLIC_LISTABLE", intrusion="probe",
              module="supabase"):
    e = _bl_entry(module=module, rule_id=rule_id, intrusion=intrusion)
    e.update(endpoint_keys(module, endpoint))
    return e


def test_endpoint_keys_hide_asset_names():
    # La baseline è committata: niente nomi di tabelle/bucket in chiaro (S5/P8).
    keys = endpoint_keys("supabase", "/storage/v1/object/list/documenti_segreti")
    assert keys["endpoint_family"] == "/storage/v1/object/list/"
    assert "documenti_segreti" not in json.dumps(keys)
    # il frammento (#signup) non cambia la chiave dell'endpoint
    assert (endpoint_keys("supabase", "/auth/v1/settings#signup")["endpoint_key"]
            == endpoint_keys("supabase", "/auth/v1/settings")["endpoint_key"])


def test_not_verifiable_on_same_asset_blocks_fixed():
    # Riprodotto dalla blind-review: STORAGE_PUBLIC_LISTABLE in baseline, la run PROBE
    # emette STORAGE_NOT_VERIFIABLE sullo stesso bucket → prima: FIXED.
    ep = "/storage/v1/object/list/documenti"
    baseline = {"target": "g", "findings": {"id_s": _entry_at(ep)}, "posture": {}}
    scope = reverify_scope_from_run(IntrusionLevel.PROBE, ["supabase"],
                                    [_limit_finding("STORAGE_NOT_VERIFIABLE", ep)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert res.fixed == []
    assert "STORAGE_NOT_VERIFIABLE" in res.not_reverified[0].description


def test_not_verifiable_on_other_asset_does_not_block():
    # Precisione: un bucket non verificabile non blocca il FIXED di un altro bucket
    # (altrimenti un limite permanente bloccherebbe tutto per sempre).
    baseline = {"target": "g", "findings": {
        "id_s": _entry_at("/storage/v1/object/list/documenti")}, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.PROBE, ["supabase"],
        [_limit_finding("STORAGE_NOT_VERIFIABLE", "/storage/v1/object/list/altro")])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert [f.finding_id for f in res.fixed] == ["id_s"]


def test_rls_not_verifiable_blocks_rls_finding_on_same_table():
    baseline = {"target": "g", "findings": {"id_r": _entry_at(
        "/rest/v1/orders", rule_id="RLS_DISABLED", intrusion="read-only")}, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.PROBE, ["supabase"],
        [_limit_finding("RLS_NOT_VERIFIABLE", "/rest/v1/orders",
                        level=IntrusionLevel.READ_ONLY)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert res.fixed == []


def test_family_wide_limit_blocks_the_whole_family():
    # SUPABASE_SCHEMA_NOT_ENUMERABLE su /rest/v1/: nessuna tabella testata.
    baseline = {"target": "g", "findings": {"id_r": _entry_at(
        "/rest/v1/orders", rule_id="RLS_DISABLED", intrusion="read-only")}, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.READ_ONLY, ["supabase"],
        [_limit_finding("SUPABASE_SCHEMA_NOT_ENUMERABLE", "/rest/v1/",
                        level=IntrusionLevel.READ_ONLY)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert res.fixed == []


def test_write_test_skipped_blocks_mutating_findings_only():
    # Riprodotto: RLS_WRITE_OPEN in baseline + CANARY_SKIPPED_NO_SCHEMA → prima FIXED.
    baseline = {"target": "g", "findings": {
        "id_w": _entry_at("/rest/v1/canary", rule_id="RLS_WRITE_OPEN", intrusion="mutating"),
        "id_r": _entry_at("/rest/v1/orders", rule_id="RLS_DISABLED", intrusion="read-only"),
    }, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.MUTATING, ["supabase"],
        [_limit_finding("CANARY_SKIPPED_NO_SCHEMA", "/rest/v1/",
                        level=IntrusionLevel.MUTATING)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert [f.finding_id for f in res.not_reverified] == ["id_w"]
    assert [f.finding_id for f in res.fixed] == ["id_r"]


def test_not_found_limit_means_module_did_not_run():
    baseline = {"target": "g", "findings": {
        "id_s": _entry_at("/storage/v1/object/list/documenti")}, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.PROBE, ["supabase"],
        [_limit_finding("SUPABASE_KEY_NOT_FOUND", "/rest/v1/",
                        level=IntrusionLevel.READ_ONLY)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert res.fixed == []


def test_legacy_entry_level_inferred_from_rule():
    # Le baseline pre-S16 non hanno intrusion_used: un finding di storage trovato a
    # PROBE non deve chiudersi con un verify READ_ONLY (prima: READ_ONLY assunto).
    baseline = {"target": "g", "findings": {
        "id_s": _bl_entry(rule_id="STORAGE_PUBLIC_LISTABLE", intrusion=None),
        "id_w": _bl_entry(rule_id="RLS_WRITE_OPEN", intrusion=None),
        "id_r": _bl_entry(rule_id="RLS_DISABLED", intrusion=None),
        "id_x": _bl_entry(module="server_exposure", rule_id="DEV_SERVER_EXPOSED",
                          intrusion=None),
    }, "posture": {}}
    res = apply_baseline([], [], baseline, now=NOW,
                         scope=_scope(modules=("supabase", "server_exposure")))
    assert [f.finding_id for f in res.fixed] == ["id_r"]
    assert sorted(f.finding_id for f in res.not_reverified) == ["id_s", "id_w", "id_x"]


def test_secret_detection_is_observable_read_only_even_after_liveness():
    # La liveness alza intrusion_used a PROBE, ma la RILEVAZIONE è READ_ONLY: un
    # segreto rimosso deve potersi chiudere con un verify di default.
    f = make_finding(module="secrets", rule_id="SECRET_STRIPE")
    f.intrusion_used = IntrusionLevel.PROBE
    assert observation_level(f) is IntrusionLevel.READ_ONLY
    g = make_finding(module="supabase", rule_id="STORAGE_PUBLIC_LISTABLE")
    g.intrusion_used = IntrusionLevel.PROBE
    assert observation_level(g) is IntrusionLevel.PROBE


# ─── S16 re-review: prova positiva, famiglia esatta, entry legacy, nomi in chiaro ─

def _entry_with_proof(endpoint, proof_check, *, rule_id="RLS_WRITE_OPEN",
                      intrusion="mutating"):
    e = _entry_at(endpoint, rule_id=rule_id, intrusion=intrusion)
    e.update(proof_keys(proof_check))
    return e


from bastione.baseline.diff import proof_keys  # noqa: E402


def _posture(check_id, passed=True):
    return PostureCheck(check_id=check_id, title="t", passed=passed,
                        severity_if_failed=Severity.HIGH, target="g", detail="d")


def test_fixed_requires_positive_proof_when_declared():
    # Re-review: RLS_WRITE_OPEN su `ordini`, chiusa solo la SELECT → la tabella esce
    # dalla superficie del canary, nessun test → prima: FIXED con INSERT aperto.
    baseline = {"target": "g", "findings": {"id_w": _entry_with_proof(
        "/rest/v1/ordini", "POSTURE_RLS_WRITE_ordini")}, "posture": {}}
    no_proof = reverify_scope_from_run(IntrusionLevel.MUTATING, ["supabase"], [],
                                       posture_checks=[_posture("POSTURE_RLS_WRITE_altra")])
    res = apply_baseline([], [], baseline, now=NOW, scope=no_proof)
    assert res.fixed == [] and [f.finding_id for f in res.not_reverified] == ["id_w"]
    failed = reverify_scope_from_run(
        IntrusionLevel.MUTATING, ["supabase"], [],
        posture_checks=[_posture("POSTURE_RLS_WRITE_ordini", passed=False)])
    assert apply_baseline([], [], baseline, now=NOW, scope=failed).fixed == []
    proven = reverify_scope_from_run(
        IntrusionLevel.MUTATING, ["supabase"], [],
        posture_checks=[_posture("POSTURE_RLS_WRITE_ordini")])
    res = apply_baseline([], [], baseline, now=NOW, scope=proven)
    assert [f.finding_id for f in res.fixed] == ["id_w"]


def test_proof_keys_do_not_store_names():
    assert "ordini" not in json.dumps(proof_keys("POSTURE_RLS_WRITE_ordini"))
    assert proof_keys(None) == {}


def test_family_limit_does_not_block_the_family_root_finding():
    # Re-review: SUPABASE_SCHEMA_NOT_ENUMERABLE (/rest/v1/) bloccava per sempre i
    # finding sulla radice stessa (es. SUPABASE_LEGACY_KEYS_IN_USE) e le RPC.
    baseline = {"target": "g", "findings": {
        "id_k": _entry_at("/rest/v1/", rule_id="SUPABASE_LEGACY_KEYS_IN_USE",
                          intrusion="read-only"),
        "id_p": _entry_at("/rest/v1/rpc/lista", rule_id="RPC_ANON_INVOCABLE"),
        "id_r": _entry_at("/rest/v1/clienti", rule_id="RLS_DISABLED",
                          intrusion="read-only"),
    }, "posture": {}}
    scope = reverify_scope_from_run(
        IntrusionLevel.PROBE, ["supabase"],
        [_limit_finding("SUPABASE_SCHEMA_NOT_ENUMERABLE", "/rest/v1/",
                        level=IntrusionLevel.READ_ONLY)])
    res = apply_baseline([], [], baseline, now=NOW, scope=scope)
    assert sorted(f.finding_id for f in res.fixed) == ["id_k", "id_p"]
    assert [f.finding_id for f in res.not_reverified] == ["id_r"]


def test_keyless_legacy_entry_only_blocked_by_module_wide_limits():
    # Re-review: un limite ricorrente su un altro asset bloccava per sempre le entry
    # pre-S16 (senza chiavi d'endpoint).
    baseline = {"target": "g", "findings": {
        "id_l": _bl_entry(rule_id="RLS_DISABLED", intrusion=None)}, "posture": {}}
    asset_limit = reverify_scope_from_run(
        IntrusionLevel.READ_ONLY, ["supabase"],
        [_limit_finding("RLS_NOT_VERIFIABLE", "/rest/v1/ordini",
                        level=IntrusionLevel.READ_ONLY)])
    assert [f.finding_id for f in apply_baseline(
        [], [], baseline, now=NOW, scope=asset_limit).fixed] == ["id_l"]


def test_endpoint_family_only_for_known_supabase_families():
    # Re-review: fuori da Supabase la "famiglia" conteneva URL e id reali.
    assert endpoint_keys("idor", "/api/users/1234/orders")["endpoint_family"] == ""
    assert endpoint_keys("login_hardening",
                         "https://staging.example.com/api/auth/login")["endpoint_family"] == ""
    assert endpoint_keys("supabase", "/rest/v1/rpc/lista")["endpoint_family"] == "/rest/v1/rpc/"
