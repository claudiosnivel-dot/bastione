"""Test minimi per gli enum (§5.1). Verificano i contratti che il resto del
sistema dà per scontati: ordinabilità di Severity/IntrusionLevel (soglie, score,
gate) e i valori stringa stabili usati in report e state.json."""

from bastione.enums import (
    Confidence,
    IntrusionLevel,
    Phase,
    Severity,
    Status,
)


def test_severity_is_ordered_int_enum():
    # IntEnum ordinabile: le soglie (§19/§22) e il posture score (§17) ci contano.
    assert Severity.INFO == 0
    assert Severity.CRITICAL == 4
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_lookup_by_name():
    # config.py mappa "high" (TOML) → Severity.HIGH usando il nome.
    assert Severity["HIGH"] is Severity.HIGH


def test_confidence_values():
    assert Confidence.FIRM.value == "firm"
    assert Confidence.TENTATIVE.value == "tentative"


def test_status_values():
    assert Status.NEW.value == "new"
    assert Status.KNOWN.value == "known"
    assert Status.ACCEPTED.value == "accepted"
    assert Status.FIXED.value == "fixed"
    assert Status.DRIFT.value == "drift"


def test_intrusion_level_is_ordered():
    # Il gate (§7) confronta action > ctx.max_intrusion: l'ordine deve reggere.
    assert IntrusionLevel.READ_ONLY == 0
    assert IntrusionLevel.READ_ONLY < IntrusionLevel.PROBE < IntrusionLevel.MUTATING


def test_phase_has_twelve_named_phases():
    # Le 12 fasi della macchina a stati (§6), con i valori stringa di §5.1.
    expected = {
        "load", "ownership", "recon", "plan", "scan", "normalize",
        "baseline", "posture", "report", "remediate", "notify", "persist",
    }
    assert {p.value for p in Phase} == expected
    assert Phase.LOAD.value == "load"
    assert Phase.REMEDIATE.value == "remediate"
