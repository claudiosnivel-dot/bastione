"""Test del generatore di report Markdown (§23) — TDD.

Verifichiamo che `to_markdown` produca:
- intestazione con target, posture score e conteggi (new/known/fixed/drift e per severità);
- sezione NEW (in testa, con i finding NEW) e DRIFT (posture check con drift=True);
- sezione KNOWN (finding known/accepted);
- sezione FIXED (vittorie);
- sezione "Limiti di verifica (§26)" (M5/R6): i finding INFO che dichiarano ciò che
  Bastione NON ha potuto verificare (`*_SKIPPED`, `*_NOT_VERIFIABLE`, ...);
- checklist posture (passed/failed) con icona;
- icona di drift evidente sui check regrediti;
- evidence mostrata così com'è (già redatta), senza de-redazione.

Tutti test OFFLINE: nessuna rete, oggetti sintetici coi veri tipi pydantic.
"""

from __future__ import annotations

import pytest

from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.report.markdown import is_verification_limit, to_markdown


# ─── Fixture sintetiche ──────────────────────────────────────────────────────

def make_finding(
    *,
    finding_id: str = "abc123",
    module: str = "supabase",
    rule_id: str = "RLS_DISABLED",
    title: str = "RLS disabilitato",
    severity: Severity = Severity.HIGH,
    status: Status = Status.NEW,
    evidence: str = "[REDACTED]",
    remediation_ref: str | None = "RLS_DISABLED",
    target: str = "https://example.com",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        module=module,
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        location=Location(endpoint="/rest/v1/clienti"),
        evidence=evidence,
        description="Descrizione di test.",
        remediation_ref=remediation_ref,
        status=status,
    )


def make_posture(
    *,
    check_id: str = "POSTURE_HSTS",
    title: str = "HSTS abilitato",
    passed: bool = True,
    drift: bool = False,
    severity_if_failed: Severity = Severity.HIGH,
    target: str = "https://example.com",
) -> PostureCheck:
    check = PostureCheck(
        check_id=check_id,
        title=title,
        passed=passed,
        severity_if_failed=severity_if_failed,
        target=target,
        detail="Dettaglio di test",
    )
    check.drift = drift
    return check


def _build_report(**kwargs) -> str:
    """Helper: costruisce un report con valori di default sensati."""
    defaults: dict = dict(
        target="https://example.com",
        posture_score=72.5,
        findings=[make_finding(status=Status.NEW)],
        fixed=[make_finding(finding_id="fix01", status=Status.FIXED)],
        posture_checks=[make_posture(passed=True)],
        counts={
            "new": 1, "known": 0, "fixed": 1, "drift": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    defaults.update(kwargs)
    return to_markdown(**defaults)


# ─── Intestazione ────────────────────────────────────────────────────────────

def test_header_contiene_target():
    md = _build_report(target="https://mio-target.it")
    assert "mio-target.it" in md


def test_header_contiene_posture_score():
    md = _build_report(posture_score=65.3)
    assert "65.3" in md


def test_header_contiene_conteggior_new():
    counts = {
        "new": 3, "known": 1, "fixed": 2, "drift": 1,
        "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    }
    md = _build_report(counts=counts)
    assert "3" in md   # new count presente


def test_header_contiene_conteggi_per_severita():
    counts = {
        "new": 0, "known": 0, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0},
    }
    md = _build_report(counts=counts)
    # I conteggi per severità devono comparire nell'intestazione
    assert "critical" in md.lower() or "CRITICAL" in md
    assert "medium" in md.lower() or "MEDIUM" in md


# ─── Sezione NEW ─────────────────────────────────────────────────────────────

def test_sezione_new_presente():
    md = _build_report()
    assert "NEW" in md


def test_sezione_new_contiene_finding_new():
    finding_new = make_finding(title="Vuln nuova critica", status=Status.NEW)
    md = _build_report(findings=[finding_new], counts={
        "new": 1, "known": 0, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    })
    assert "Vuln nuova critica" in md


def test_sezione_new_precede_known():
    finding_new = make_finding(title="NEW-FINDING", status=Status.NEW)
    finding_known = make_finding(
        finding_id="known01", title="KNOWN-FINDING", status=Status.KNOWN
    )
    md = _build_report(findings=[finding_new, finding_known], counts={
        "new": 1, "known": 1, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
    })
    pos_new = md.find("NEW-FINDING")
    pos_known = md.find("KNOWN-FINDING")
    assert pos_new < pos_known, "La sezione NEW deve precedere KNOWN nel documento"


# ─── Sezione DRIFT ───────────────────────────────────────────────────────────

def test_posture_check_con_drift_evidenziato():
    check_drift = make_posture(
        check_id="POSTURE_HSTS",
        title="HSTS abilitato",
        passed=False,
        drift=True,
    )
    md = _build_report(
        posture_checks=[check_drift],
        counts={
            "new": 0, "known": 0, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    # Il titolo del check in drift deve essere presente con segnalazione di regressione
    assert "HSTS abilitato" in md
    # Il drift deve essere chiaramente segnalato (parola "DRIFT" o "drift" o simbolo)
    assert "drift" in md.lower() or "DRIFT" in md


def test_posture_drift_appare_in_testa():
    """Un posture check con drift deve comparire nella parte alta del report
    (prima della checklist completa / sezione KNOWN), accanto ai NEW."""
    check_drift = make_posture(
        check_id="POSTURE_CSP",
        title="CSP presente",
        passed=False,
        drift=True,
    )
    finding_known = make_finding(
        finding_id="k01", title="VULN-KNOWN", status=Status.KNOWN
    )
    md = _build_report(
        findings=[finding_known],
        posture_checks=[check_drift],
        counts={
            "new": 0, "known": 1, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    # "CSP presente" (drift) deve comparire prima di "VULN-KNOWN" (known)
    pos_drift = md.find("CSP presente")
    pos_known = md.find("VULN-KNOWN")
    assert pos_drift != -1, "Il check in drift deve comparire nel report"
    assert pos_known != -1
    assert pos_drift < pos_known, "DRIFT deve precedere KNOWN nel documento"


# ─── Sezione KNOWN ───────────────────────────────────────────────────────────

def test_sezione_known_presente():
    finding_known = make_finding(
        finding_id="k02", title="Vuln già nota", status=Status.KNOWN
    )
    md = _build_report(findings=[finding_known], counts={
        "new": 0, "known": 1, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    })
    assert "KNOWN" in md or "Noti" in md or "known" in md.lower()
    assert "Vuln già nota" in md


def test_finding_accepted_appare_in_known():
    """I finding ACCEPTED (rumore noto silenziato) devono comparire nella sezione
    KNOWN (non sono nuovi pericoli, ma sono comunque tracciati nel report)."""
    finding_acc = make_finding(
        finding_id="acc01", title="Accettato-silenzioso", status=Status.ACCEPTED
    )
    md = _build_report(findings=[finding_acc], counts={
        "new": 0, "known": 0, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    })
    assert "Accettato-silenzioso" in md


# ─── Sezione FIXED ───────────────────────────────────────────────────────────

def test_sezione_fixed_presente():
    md = _build_report()
    assert "FIXED" in md or "Fixed" in md or "Risolti" in md or "risolti" in md.lower()


def test_sezione_fixed_contiene_finding_fixed():
    fixed = make_finding(finding_id="f99", title="Bug risolto", status=Status.FIXED)
    md = _build_report(fixed=[fixed])
    assert "Bug risolto" in md


def test_sezione_fixed_vuota_non_crasha():
    md = _build_report(fixed=[])
    # Deve ancora produrre un report valido
    assert "https://example.com" in md


# ─── Checklist posture ───────────────────────────────────────────────────────

def test_checklist_posture_presente():
    md = _build_report()
    # Deve esserci una sezione dedicata ai posture check
    assert "posture" in md.lower() or "Posture" in md


def test_checklist_passed_ha_icona_verde():
    check_passed = make_posture(check_id="POSTURE_HSTS", title="HSTS ok", passed=True)
    md = _build_report(posture_checks=[check_passed])
    # I check passed devono avere un'icona/simbolo positivo
    assert "HSTS ok" in md
    # La riga deve contenere un simbolo passato (✅, ✓, [x], OK, PASS, ecc.)
    # Cerchiamo un segno positivo vicino al titolo
    hsts_line_idx = None
    for i, line in enumerate(md.splitlines()):
        if "HSTS ok" in line:
            hsts_line_idx = i
            break
    assert hsts_line_idx is not None
    hsts_line = md.splitlines()[hsts_line_idx]
    positive_markers = ["✅", "✓", "[x]", "PASS", "OK", "passed", "verde", "✔"]
    assert any(m in hsts_line for m in positive_markers), (
        f"Nessun marcatore positivo trovato nella riga: {hsts_line!r}"
    )


def test_checklist_failed_ha_icona_rossa():
    check_failed = make_posture(
        check_id="POSTURE_CSP", title="CSP assente", passed=False, drift=False
    )
    md = _build_report(posture_checks=[check_failed])
    assert "CSP assente" in md
    csp_line = next(
        (l for l in md.splitlines() if "CSP assente" in l), None
    )
    assert csp_line is not None
    negative_markers = ["❌", "✗", "[ ]", "FAIL", "KO", "failed", "rosso", "✘"]
    assert any(m in csp_line for m in negative_markers), (
        f"Nessun marcatore negativo trovato nella riga: {csp_line!r}"
    )


# ─── Evidence già redatta ─────────────────────────────────────────────────────

def test_evidence_redatta_mostrata_tale_quale():
    """L'evidence (già redatta a monte) deve comparire nel report così com'è.
    Il report NON de-redatta e NON sostituisce il valore."""
    evidence_redatta = "[REDACTED:SECRET_KEY]"
    finding = make_finding(evidence=evidence_redatta, status=Status.NEW)
    md = _build_report(findings=[finding])
    assert evidence_redatta in md


def test_evidence_non_contiene_valori_in_chiaro():
    """Se l'evidence fornita è già '[REDACTED]', il report non deve contenere
    valori in chiaro come 'sk_live_...' o 'eyJhbGci...' (niente de-redazione)."""
    finding = make_finding(evidence="[REDACTED]", status=Status.NEW)
    md = _build_report(findings=[finding])
    # L'evidence nel report è esattamente quella passata
    assert "[REDACTED]" in md
    # Nessun valore segreto inventato
    assert "sk_live_" not in md
    assert "eyJhbGci" not in md


# ─── Dettagli dei finding ─────────────────────────────────────────────────────

def test_finding_contiene_severity():
    finding = make_finding(severity=Severity.CRITICAL, status=Status.NEW, title="Critico!")
    md = _build_report(findings=[finding])
    assert "CRITICAL" in md or "critical" in md.lower()


def test_finding_contiene_remediation_ref():
    finding = make_finding(
        remediation_ref="PLAYBOOK_RLS_DISABLED", status=Status.NEW
    )
    md = _build_report(findings=[finding])
    assert "PLAYBOOK_RLS_DISABLED" in md


def test_finding_senza_remediation_ref_non_crasha():
    finding = make_finding(remediation_ref=None, status=Status.NEW)
    md = _build_report(findings=[finding])
    assert "https://example.com" in md


def test_finding_contiene_location():
    finding = make_finding(status=Status.NEW)
    md = _build_report(findings=[finding])
    # La location (endpoint) deve comparire
    assert "/rest/v1/clienti" in md


# ─── Report senza finding ────────────────────────────────────────────────────

def test_report_senza_finding_non_crasha():
    md = to_markdown(
        target="https://vuoto.it",
        posture_score=100.0,
        findings=[],
        fixed=[],
        posture_checks=[],
        counts={
            "new": 0, "known": 0, "fixed": 0, "drift": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert "vuoto.it" in md
    assert "100.0" in md or "100" in md


# ─── Limiti di verifica (§26 / R6) ───────────────────────────────────────────
# Onestà difensiva: ciò che Bastione NON ha potuto verificare (i `*_SKIPPED` e gli
# INFO "non determinabile / non dichiarato") va reso ESPLICITO nel report, in una
# sezione dedicata — mai silenzio, e mai presentato come difetto.

def _f(rule_id, sev=Severity.INFO, status=Status.NEW, *, title=None, evidence="e"):
    return Finding(finding_id=rule_id, module="m", rule_id=rule_id, title=title or rule_id,
                   severity=sev, confidence=Confidence.TENTATIVE, target="t",
                   location=Location(), evidence=evidence, description="d", status=status)


def _md_limiti(**kwargs) -> str:
    """Report MD con i soli `findings` dati (resto neutro)."""
    defaults: dict = dict(target="t", posture_score=100.0, findings=[], fixed=[],
                          posture_checks=[], counts={})
    defaults.update(kwargs)
    return to_markdown(**defaults)


def _sezione_limiti_md(md: str) -> str:
    """Testo della sezione 'Limiti di verifica' (dal suo header al prossimo '## ')."""
    inizio = md.index("## Limiti di verifica")
    resto = md[inizio + 3:]
    fine = resto.find("\n## ")
    return resto if fine == -1 else resto[:fine]


def test_is_verification_limit_predicate():
    assert is_verification_limit(_f("NUCLEI_SKIPPED"))
    assert is_verification_limit(_f("RPC_NOT_VERIFIABLE"))
    assert is_verification_limit(_f("AUTH_EXPECTATION_UNDECLARED"))
    assert not is_verification_limit(_f("RLS_DISABLED", sev=Severity.CRITICAL))


@pytest.mark.parametrize("rule_id", [
    # per suffisso
    "NUCLEI_SKIPPED", "TRIVY_SKIPPED", "ZAP_ACTIVE_SKIPPED",
    "SUPABASE_KEY_NOT_FOUND", "SUPABASE_URL_NOT_FOUND",
    "AUTH_SETTINGS_NOT_READABLE", "SUPABASE_SCHEMA_NOT_ENUMERABLE",
    "RPC_NOT_VERIFIABLE", "AUTH_EXPECTATION_UNDECLARED", "STORAGE_LISTABLE_UNDECLARED",
    "TLS_UNDETERMINED", "STORAGE_NOT_VERIFIABLE", "SUPABASE_GRAPHQL_NOT_VERIFIABLE",
    # SKIPPED come infisso (corsie MUTATING)
    "CANARY_SKIPPED_NO_SCHEMA", "IDOR_WRITE_SKIPPED_NO_CANARY",
    # per rule_id esplicito
    "SUPABASE_SCHEMA_VIA_BUNDLE", "SUPABASE_LEGACY_KEYS_IN_USE", "SUPABASE_JWT_LEGACY_HS256",
    "MODULE_ERROR",
])
def test_is_verification_limit_riconosce_i_limiti_info(rule_id):
    assert is_verification_limit(_f(rule_id))


@pytest.mark.parametrize("sev", [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
@pytest.mark.parametrize("rule_id", ["NUCLEI_SKIPPED", "SUPABASE_JWT_LEGACY_HS256"])
def test_is_verification_limit_solo_se_info(rule_id, sev):
    """Un limite è un INFO onesto, non un difetto: sopra INFO non è mai un limite."""
    assert not is_verification_limit(_f(rule_id, sev=sev))


@pytest.mark.parametrize("rule_id", ["RLS_DISABLED", "SECRET_SERVICE_ROLE", "POSTURE_HSTS"])
def test_is_verification_limit_guarda_il_rule_id_non_solo_la_severita(rule_id):
    """INFO da solo non basta: un INFO ordinario (rule_id non-limite) non è un limite."""
    assert not is_verification_limit(_f(rule_id, sev=Severity.INFO))


def test_markdown_has_limits_section():
    md = to_markdown(target="t", posture_score=100.0,
                     findings=[_f("RPC_NOT_VERIFIABLE"), _f("RLS_DISABLED", Severity.CRITICAL)],
                     fixed=[], posture_checks=[], counts={})
    assert "Limiti di verifica" in md and "RPC_NOT_VERIFIABLE" in md


def test_markdown_limiti_elenca_rule_id_titolo_ed_evidence():
    md = _md_limiti(findings=[
        _f("RPC_NOT_VERIFIABLE", title="RPC non verificabile", evidence="endpoint /rest/v1/rpc/x")])
    sezione = _sezione_limiti_md(md)
    assert "RPC_NOT_VERIFIABLE" in sezione
    assert "RPC non verificabile" in sezione
    assert "endpoint /rest/v1/rpc/x" in sezione


def test_markdown_limiti_non_include_i_difetti():
    """Nella sezione compaiono SOLO i limiti: un difetto resta nelle sue sezioni."""
    md = _md_limiti(findings=[
        _f("RPC_NOT_VERIFIABLE"),
        _f("RLS_DISABLED", Severity.CRITICAL, title="Difetto-RLS"),
        _f("SECRET_FOO", Severity.INFO, title="Info-ordinario"),
    ])
    sezione = _sezione_limiti_md(md)
    assert "RPC_NOT_VERIFIABLE" in sezione
    assert "RLS_DISABLED" not in sezione and "Difetto-RLS" not in sezione
    assert "SECRET_FOO" not in sezione and "Info-ordinario" not in sezione


def test_markdown_limiti_assente_se_nessun_limite():
    """Senza limiti niente sezione vuota né intestazione orfana."""
    md = _md_limiti(findings=[_f("RLS_DISABLED", Severity.CRITICAL), _f("SECRET_FOO")])
    assert "Limiti di verifica" not in md


def test_markdown_limiti_assente_senza_finding():
    assert "Limiti di verifica" not in _md_limiti(findings=[])


def test_markdown_limiti_dopo_fixed_e_prima_della_checklist_posture():
    md = _md_limiti(findings=[_f("NUCLEI_SKIPPED")],
                    fixed=[make_finding(finding_id="fix01", status=Status.FIXED)],
                    posture_checks=[make_posture(passed=True)])
    pos_fixed = md.index("## FIXED")
    pos_limiti = md.index("## Limiti di verifica")
    pos_posture = md.index("## Checklist Posture")
    assert pos_fixed < pos_limiti < pos_posture


def test_markdown_limiti_include_anche_i_finding_known_e_accepted():
    """Il limite è una proprietà della run, non del delta: vale per ogni status emesso."""
    md = _md_limiti(findings=[
        _f("NUCLEI_SKIPPED", status=Status.KNOWN),
        _f("TRIVY_SKIPPED", status=Status.ACCEPTED),
    ])
    sezione = _sezione_limiti_md(md)
    assert "NUCLEI_SKIPPED" in sezione and "TRIVY_SKIPPED" in sezione


def test_markdown_limiti_non_elenca_un_limite_fixed():
    """Un limite FIXED non si applica più a questa run: non va dichiarato come limite."""
    md = _md_limiti(
        findings=[_f("NUCLEI_SKIPPED")],
        fixed=[_f("TRIVY_SKIPPED", status=Status.FIXED)],
    )
    sezione = _sezione_limiti_md(md)
    assert "NUCLEI_SKIPPED" in sezione
    assert "TRIVY_SKIPPED" not in sezione


def test_markdown_limiti_evidence_redatta_mostrata_tale_quale():
    """P8: l'evidence (già redatta a monte) compare invariata anche nei limiti."""
    md = _md_limiti(findings=[_f("RPC_NOT_VERIFIABLE", evidence="[REDACTED:SECRET_KEY]")])
    assert "[REDACTED:SECRET_KEY]" in _sezione_limiti_md(md)
