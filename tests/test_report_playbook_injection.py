"""Test dell'iniezione del playbook renderizzato nel report Markdown (§18/§23).

Quando esiste un template per il `remediation_ref`/`check_id` di un finding o di un
posture-drift, il report deve iniettare il playbook RENDERIZZATO accanto al finding
(NEW e KNOWN, più i posture drift). Quando il template manca, resta il fallback
attuale (`**Playbook:** <ref>`), senza crash.

Il seam è iniettabile: `to_markdown` accetta un `render_playbook` (callable) così i
test puntano a una funzione fake deterministica, senza toccare la dir reale.
Tutti i test sono OFFLINE.
"""

from __future__ import annotations

from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.report.markdown import to_markdown


def _finding(
    *,
    finding_id: str = "abc123",
    rule_id: str = "RLS_DISABLED",
    title: str = "RLS disabilitato",
    status: Status = Status.NEW,
    remediation_ref: str | None = "RLS_DISABLED",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        module="supabase",
        rule_id=rule_id,
        title=title,
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        target="https://example.com",
        location=Location(endpoint="/rest/v1/clienti"),
        evidence="[REDACTED]",
        description="desc",
        remediation_ref=remediation_ref,
        status=status,
    )


def _posture_drift() -> PostureCheck:
    c = PostureCheck(
        check_id="POSTURE_HSTS",
        title="HSTS mancante",
        passed=False,
        severity_if_failed=Severity.HIGH,
        target="https://example.com",
        detail="dettaglio",
        remediation_ref="POSTURE_HSTS",
    )
    c.drift = True
    return c


# Render fake deterministico: ritorna un blocco riconoscibile solo per RLS_DISABLED.
def _fake_render(rule_id, context):
    if rule_id == "RLS_DISABLED":
        return f"### PLAYBOOK-RENDERIZZATO per {context.get('table')}"
    return None


_BASE_COUNTS = {
    "new": 1, "known": 0, "fixed": 0, "drift": 0,
    "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
}


def _report(**kw):
    defaults = dict(
        target="https://example.com",
        posture_score=80.0,
        findings=[_finding()],
        fixed=[],
        posture_checks=[],
        counts=_BASE_COUNTS,
    )
    defaults.update(kw)
    return to_markdown(**defaults)


def test_finding_new_inietta_playbook_renderizzato():
    md = _report(render_playbook=_fake_render)
    assert "PLAYBOOK-RENDERIZZATO per clienti" in md


def test_finding_known_inietta_playbook_renderizzato():
    f = _finding(finding_id="k1", status=Status.KNOWN)
    md = _report(
        findings=[f],
        render_playbook=_fake_render,
        counts={
            "new": 0, "known": 1, "fixed": 0, "drift": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert "PLAYBOOK-RENDERIZZATO" in md


def test_finding_senza_template_cade_nel_fallback():
    f = _finding(rule_id="ALTRO", remediation_ref="ALTRO")
    md = _report(findings=[f], render_playbook=_fake_render)
    # Niente blocco renderizzato; resta il riferimento testuale (fallback attuale).
    assert "PLAYBOOK-RENDERIZZATO" not in md
    assert "ALTRO" in md  # il remediation_ref resta visibile come fallback


def test_posture_drift_inietta_playbook_per_check_id():
    # Render fake che risponde sul check_id del posture.
    def render(rule_id, context):
        if rule_id == "POSTURE_HSTS":
            return "### PLAYBOOK-HSTS-RENDERIZZATO"
        return None

    md = _report(
        findings=[],
        posture_checks=[_posture_drift()],
        render_playbook=render,
        counts={
            "new": 0, "known": 0, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert "PLAYBOOK-HSTS-RENDERIZZATO" in md


def test_render_none_per_tutti_non_crasha_e_usa_fallback():
    md = _report(render_playbook=lambda r, c: None)
    # Fallback: il riferimento testuale del playbook resta.
    assert "RLS_DISABLED" in md


def test_default_render_playbook_non_richiede_argomento():
    """Senza passare `render_playbook`, `to_markdown` usa il default reale e non
    crasha (il template RLS_DISABLED bundled esiste → blocco renderizzato)."""
    md = _report()
    # Il template reale RLS_DISABLED contiene il loop di verifica.
    assert "bastione verify" in md


def test_evidence_redatta_resta_invariata_con_iniezione():
    md = _report(render_playbook=_fake_render)
    assert "[REDACTED]" in md
    assert "sk_live_" not in md
