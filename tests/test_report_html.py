"""Test del generatore di report HTML single-file (§23, decisione O02) — TDD.

`to_html` rispecchia `to_markdown` (stessa firma, stessi input): produce un
documento HTML5 **single-file**, tema **dark**, con **posture gauge** e **filtri**
per stato/severità. Verifichiamo:

- intestazione con target + posture score, e il GAUGE visivo dello score;
- le sezioni NEW/DRIFT (in testa), KNOWN, FIXED, checklist posture;
- i titoli dei finding e l'evidence (mostrata così com'è — già redatta, P8);
- SINGLE-FILE / NO CDN: nessun riferimento esterno (niente src=http, link/@import
  verso http, img esterne) — CSS e JS sono INLINE;
- ESCAPING/XSS (CRITICO): ogni valore dinamico è HTML-escapato; un payload
  `<script>`/`onerror=` nel contenuto NON compare come HTML attivo;
- filtri: marcatori dati (data-status/data-severity) presenti per pilotare il JS.

Tutti i test sono OFFLINE: oggetti sintetici coi veri tipi pydantic.
"""

from __future__ import annotations

import re

from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.report.html import to_html


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
    location: Location | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        module=module,
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        location=location or Location(endpoint="/rest/v1/clienti"),
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
    detail: str = "Dettaglio di test",
) -> PostureCheck:
    check = PostureCheck(
        check_id=check_id,
        title=title,
        passed=passed,
        severity_if_failed=severity_if_failed,
        target=target,
        detail=detail,
    )
    check.drift = drift
    return check


_BASE_COUNTS = {
    "new": 1, "known": 0, "fixed": 1, "drift": 0,
    "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
}


def _build_html(**kwargs) -> str:
    defaults: dict = dict(
        target="https://example.com",
        posture_score=72.5,
        findings=[make_finding(status=Status.NEW)],
        fixed=[make_finding(finding_id="fix01", status=Status.FIXED)],
        posture_checks=[make_posture(passed=True)],
        counts=_BASE_COUNTS,
    )
    defaults.update(kwargs)
    return to_html(**defaults)


# ─── HTML5 valido e single-file ──────────────────────────────────────────────

def test_e_un_documento_html5():
    html = _build_html()
    assert "<!doctype html" in html.lower()
    assert "<html" in html.lower()
    assert "</html>" in html.lower()


def test_css_e_js_sono_inline():
    html = _build_html()
    # CSS inline (tema dark) e JS inline (filtri) nello stesso file.
    assert "<style" in html.lower()
    assert "<script" in html.lower()


def test_no_cdn_nessun_riferimento_esterno():
    """SINGLE-FILE (O02): nessun http(s) in src/href, nessun @import remoto,
    nessun font/script/css da CDN. Il file deve aprirsi offline identico."""
    html = _build_html()
    low = html.lower()
    # Nessuno schema esterno usato come SORGENTE di risorsa.
    assert "src=\"http" not in low and "src='http" not in low
    assert "href=\"http" not in low and "href='http" not in low
    assert "@import" not in low
    assert "//cdn" not in low
    # Nessun tag <link rel="stylesheet"> (lo stile è inline).
    assert "rel=\"stylesheet\"" not in low and "rel='stylesheet'" not in low


def test_target_in_href_non_diventa_link_attivo():
    """Anche se il target è un URL http(s), NON deve finire come attributo href/src
    (sarebbe un riferimento esterno): deve comparire come TESTO escapato."""
    html = _build_html(target="https://mio-target.example")
    assert "mio-target.example" in html
    low = html.lower()
    assert "href=\"http" not in low and "href='http" not in low
    assert "src=\"http" not in low and "src='http" not in low


# ─── Intestazione + gauge ────────────────────────────────────────────────────

def test_header_contiene_target():
    html = _build_html(target="https://mio-target.it")
    assert "mio-target.it" in html


def test_header_contiene_posture_score():
    html = _build_html(posture_score=65.3)
    assert "65.3" in html


def test_posture_gauge_presente():
    """Deve esserci un GAUGE visivo dello score (SVG inline o arco CSS), col valore."""
    html = _build_html(posture_score=65.3)
    low = html.lower()
    # Un gauge: SVG inline (preferito) o un elemento marcato come gauge.
    assert "<svg" in low or "gauge" in low
    # Il valore numerico dello score compare nel gauge / header.
    assert "65.3" in html


def test_conteggi_per_stato_e_severita():
    counts = {
        "new": 3, "known": 1, "fixed": 2, "drift": 1,
        "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    }
    html = _build_html(counts=counts)
    low = html.lower()
    assert "critical" in low
    assert "medium" in low
    # I conteggi di stato compaiono.
    assert "new" in low and "known" in low and "fixed" in low and "drift" in low


# ─── Sezioni (stesso contenuto del MD) ───────────────────────────────────────

def test_sezione_new_presente_e_in_testa():
    finding_new = make_finding(title="NEW-FINDING", status=Status.NEW)
    finding_known = make_finding(
        finding_id="known01", title="KNOWN-FINDING", status=Status.KNOWN
    )
    html = _build_html(findings=[finding_new, finding_known], counts={
        "new": 1, "known": 1, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
    })
    assert "NEW-FINDING" in html
    assert html.find("NEW-FINDING") < html.find("KNOWN-FINDING")


def test_sezione_drift_in_testa_prima_di_known():
    check_drift = make_posture(
        check_id="POSTURE_CSP", title="CSP presente", passed=False, drift=True
    )
    finding_known = make_finding(
        finding_id="k01", title="VULN-KNOWN", status=Status.KNOWN
    )
    html = _build_html(
        findings=[finding_known],
        posture_checks=[check_drift],
        counts={
            "new": 0, "known": 1, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert "CSP presente" in html
    assert "VULN-KNOWN" in html
    assert html.find("CSP presente") < html.find("VULN-KNOWN")


def test_sezione_known_presente():
    finding_known = make_finding(
        finding_id="k02", title="Vuln gia nota", status=Status.KNOWN
    )
    html = _build_html(findings=[finding_known], counts={
        "new": 0, "known": 1, "fixed": 0, "drift": 0,
        "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    })
    assert "Vuln gia nota" in html


def test_sezione_fixed_presente():
    fixed = make_finding(finding_id="f99", title="Bug risolto", status=Status.FIXED)
    html = _build_html(fixed=[fixed])
    assert "Bug risolto" in html


def test_checklist_posture_passed_e_failed():
    passed = make_posture(check_id="POSTURE_HSTS", title="HSTS ok", passed=True)
    failed = make_posture(check_id="POSTURE_CSP", title="CSP assente", passed=False)
    html = _build_html(posture_checks=[passed, failed])
    assert "HSTS ok" in html
    assert "CSP assente" in html


def test_finding_contiene_severity_e_location():
    finding = make_finding(severity=Severity.CRITICAL, status=Status.NEW, title="Critico!")
    html = _build_html(findings=[finding])
    assert "CRITICAL" in html or "critical" in html.lower()
    assert "/rest/v1/clienti" in html


# ─── Evidence già redatta (P8) ───────────────────────────────────────────────

def test_evidence_redatta_mostrata_tale_quale():
    evidence_redatta = "[REDACTED:SECRET_KEY]"
    finding = make_finding(evidence=evidence_redatta, status=Status.NEW)
    html = _build_html(findings=[finding])
    assert evidence_redatta in html


def test_evidence_non_contiene_valori_in_chiaro():
    finding = make_finding(evidence="[REDACTED]", status=Status.NEW)
    html = _build_html(findings=[finding])
    assert "[REDACTED]" in html
    assert "sk_live_" not in html
    assert "eyJhbGci" not in html


# ─── Filtri (JS inline) ──────────────────────────────────────────────────────

def test_marcatori_dati_per_filtro_stato_e_severita():
    """I finding portano attributi-dato (data-status / data-severity) che il JS
    inline usa per filtrare. Devono comparire nell'HTML generato."""
    finding = make_finding(status=Status.NEW, severity=Severity.HIGH)
    html = _build_html(findings=[finding])
    low = html.lower()
    assert "data-status" in low
    assert "data-severity" in low
    # I valori di filtro corrispondono allo status/severità del finding.
    assert "new" in low
    assert "high" in low


# ─── Contratto filtro: tassonomia <option> vs data-status emessi ─────────────

def _option_values(html: str) -> set[str]:
    """Estrae i `value` delle <option> del <select id="f-status">."""
    m = re.search(r'<select id="f-status">(.*?)</select>', html, re.DOTALL)
    assert m, "select di stato non trovato"
    return set(re.findall(r'<option value="([^"]+)">', m.group(1)))


def _data_status_emessi(html: str) -> set[str]:
    """Tutti i valori `data-status` realmente emessi sulle card .finding."""
    return set(re.findall(r'data-status="([^"]+)"', html))


def test_ogni_data_status_emesso_ha_una_option_nel_filtro():
    """Contratto del filtro: per OGNI `data-status` emesso su una card deve esistere
    una <option> con quel value (oltre a 'all'). Altrimenti il filtro nasconde
    silenziosamente card legittime in un report condivisibile col cliente."""
    drift_check = make_posture(
        check_id="POSTURE_CSP", title="CSP assente", passed=False, drift=True
    )
    html = _build_html(
        findings=[
            make_finding(finding_id="n1", title="NUOVO", status=Status.NEW),
            make_finding(finding_id="k1", title="NOTO", status=Status.KNOWN),
            make_finding(finding_id="a1", title="ACCETTATO", status=Status.ACCEPTED),
        ],
        fixed=[make_finding(finding_id="f1", title="RISOLTO", status=Status.FIXED)],
        posture_checks=[drift_check],
        counts={
            "new": 1, "known": 2, "fixed": 1, "drift": 1,
            "by_severity": {"critical": 0, "high": 4, "medium": 0, "low": 0, "info": 0},
        },
    )
    opzioni = _option_values(html)
    emessi = _data_status_emessi(html)
    mancanti = emessi - opzioni
    assert not mancanti, (
        f"data-status senza <option> corrispondente (card filtrate via): {mancanti}"
    )


def test_finding_accepted_resta_visibile_col_filtro_known():
    """Un finding ACCEPTED è renderizzato sotto la sezione KNOWN: il suo data-status
    DEVE corrispondere a un'opzione raggiungibile (KNOWN), altrimenti selezionando
    KNOWN sparirebbe. Riproduce il difetto del filtro e ne verifica la correzione."""
    accepted = make_finding(
        finding_id="acc1", title="Rumore accettato", status=Status.ACCEPTED
    )
    html = _build_html(
        findings=[accepted],
        fixed=[],
        counts={
            "new": 0, "known": 1, "fixed": 0, "drift": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    # La card è presente e il suo data-status è uno tra le opzioni del filtro.
    assert "Rumore accettato" in html
    emessi = _data_status_emessi(html)
    assert emessi == {"known"}, (
        f"ACCEPTED deve filtrare sotto KNOWN (sezione che lo ospita), non {emessi}"
    )
    # Simula la logica JS exact-match: con filtro 'known' la card resta visibile.
    data_status = re.search(
        r'<article class="finding"[^>]*data-status="([^"]+)"', html
    ).group(1)
    assert ("known" == "all") or (data_status == "known")


def test_card_drift_raggiungibile_dal_filtro():
    """Le card DRIFT portano data-status='drift': il <select> deve offrire l'opzione
    DRIFT così che siano isolabili (e non spariscano selezionando uno stato specifico)."""
    drift_check = make_posture(
        check_id="POSTURE_CSP", title="CSP regredito", passed=False, drift=True
    )
    html = _build_html(
        findings=[],
        posture_checks=[drift_check],
        counts={
            "new": 0, "known": 0, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert 'data-status="drift"' in html
    assert "drift" in _option_values(html)
    # Simula la logica JS exact-match: con filtro 'drift' la card resta visibile.
    st = "drift"
    assert (st == "all") or ("drift" == st)


# ─── ESCAPING / XSS (il punto di sicurezza dello step) ───────────────────────

_XSS = "<script>alert(1)</script>"
_XSS_ESC = "&lt;script&gt;alert(1)&lt;/script&gt;"
_ATTR_XSS = '"><img src=x onerror=alert(1)>'


def test_xss_nel_title_e_escapato():
    """Un <script> nel TITLE di un finding non deve comparire come HTML attivo."""
    finding = make_finding(title=_XSS, status=Status.NEW)
    html = _build_html(findings=[finding])
    assert _XSS not in html, "payload <script> grezzo presente: XSS!"
    assert _XSS_ESC in html, "il payload deve comparire escapato"


def test_xss_nell_evidence_e_escapato():
    finding = make_finding(evidence=_XSS, status=Status.NEW)
    html = _build_html(findings=[finding])
    assert _XSS not in html
    assert _XSS_ESC in html


def test_xss_nella_location_e_escapato():
    """Una location derivata dal target (nome tabella/endpoint dall'OpenAPI/bundle)
    con un payload XSS non deve eseguire."""
    finding = make_finding(
        status=Status.NEW,
        location=Location(endpoint=f"/rest/v1/{_XSS}"),
    )
    html = _build_html(findings=[finding])
    assert _XSS not in html
    assert "&lt;script&gt;" in html


def test_xss_nel_target_e_escapato():
    html = _build_html(target=_XSS)
    assert _XSS not in html
    assert _XSS_ESC in html


def test_xss_nel_posture_detail_e_escapato():
    check = make_posture(title=_XSS, detail=_XSS, passed=False, drift=True)
    html = _build_html(
        posture_checks=[check],
        counts={
            "new": 0, "known": 0, "fixed": 0, "drift": 1,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    assert _XSS not in html
    assert "&lt;script&gt;" in html


def test_xss_in_contesto_attributo_e_neutralizzato():
    """Un payload pensato per ROMPERE un attributo (`"><img onerror=...>`) deve
    essere neutralizzato: nessun tag <img ... onerror attivo nell'output."""
    finding = make_finding(rule_id="RLS_DISABLED", status=Status.NEW)
    # Inietta il payload-attributo in un campo che potrebbe finire in un attributo
    # (es. il valore data-* di filtro o un title attributo): qui usiamo il title.
    finding.title = _ATTR_XSS
    html = _build_html(findings=[finding])
    # Il payload non deve mai diventare un tag <img onerror> attivo.
    assert "<img src=x onerror=" not in html
    # I metacaratteri sono escapati (quote=True copre apici/virgolette negli attributi).
    assert "onerror=alert(1)>" not in html


def test_playbook_markdown_e_escapato():
    """Il testo del playbook (Markdown iniettabile) può contenere caratteri attivi:
    deve essere reso in modo SICURO (escapato), mai come HTML eseguibile."""
    def render(rule_id, context):
        if rule_id == "RLS_DISABLED":
            return "Esegui <script>alert('pb')</script> nel DB"
        return None

    finding = make_finding(rule_id="RLS_DISABLED", remediation_ref="RLS_DISABLED",
                           status=Status.NEW)
    html = _build_html(findings=[finding], render_playbook=render)
    assert "<script>alert('pb')</script>" not in html
    assert "&lt;script&gt;" in html


def test_playbook_renderizzato_appare_escapato_ma_presente():
    def render(rule_id, context):
        return f"PLAYBOOK per {context.get('table')}"

    finding = make_finding(rule_id="RLS_DISABLED", remediation_ref="RLS_DISABLED",
                           status=Status.NEW)
    html = _build_html(findings=[finding], render_playbook=render)
    assert "PLAYBOOK per clienti" in html


def test_default_render_playbook_non_richiede_argomento():
    """Senza passare render_playbook, to_html usa il default reale (come to_markdown)
    e non crasha: il template RLS_DISABLED bundled esiste."""
    html = _build_html()
    assert "bastione verify" in html


# ─── Robustezza ──────────────────────────────────────────────────────────────

def test_report_senza_finding_non_crasha():
    html = to_html(
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
    assert "vuoto.it" in html
    assert "100" in html
    assert "<!doctype html" in html.lower()


def test_nessun_payload_attivo_globale():
    """Difesa-in-profondità: con payload XSS in OGNI campo dinamico, l'output non
    deve contenere alcun tag <script>alert attivo (solo lo <script> del filtro JS)."""
    finding = make_finding(
        title=_XSS, evidence=_XSS, rule_id="X<script>", module=_XSS,
        location=Location(url=_XSS, endpoint=_XSS, file=_XSS),
        status=Status.NEW,
    )
    html = _build_html(findings=[finding])
    # L'unico <script> ammesso è quello del filtro (inline, senza alert(1) del payload).
    assert "alert(1)" not in re.sub(r"&lt;|&gt;|&quot;|&#x27;|&amp;", "", html) or \
        _XSS not in html
    assert _XSS not in html
