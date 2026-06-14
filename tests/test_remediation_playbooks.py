"""Test del motore di remediation playbook (§18) — TDD.

Copre `bastione.remediation.playbooks`:
  - `render_playbook(rule_id, context)` → MD renderizzato con Jinja2 dal template
    `playbooks/<rule_id>.md`; `None` se il template non esiste (degrada, no crash).
  - costruzione del context da un `Finding` e da un `PostureCheck`
    (title, severity, target, location, table derivata da endpoint, evidence redatta).
  - derivazione `table` dall'ultimo segmento di un endpoint PostgREST
    (`/rest/v1/clienti` → `clienti`); endpoint assente → gestito.
  - P8: l'evidence (già redatta) passa invariata nel render, niente de-redazione.

Tutti i test sono OFFLINE e deterministici: nessuna rete, nessun target.
La root dei template è monkeypatchabile (default `playbooks/` alla root del repo),
così i test puntano a una dir temporanea nota.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.remediation import playbooks


# ─── Fixture: una playbooks-root temporanea con template noti ─────────────────

@pytest.fixture()
def fake_playbooks(tmp_path, monkeypatch) -> Path:
    """Crea una dir di template nota e ci punta `playbooks.PLAYBOOKS_DIR`."""
    root = tmp_path / "playbooks"
    root.mkdir()
    (root / "RLS_DISABLED.md").write_text(
        "## {{ title }} — {{ location.endpoint }}\n"
        "Tabella: {{ table }}\n"
        "Target: {{ target }}\n"
        "Severità: {{ severity }}\n"
        "Evidence: {{ evidence }}\n"
        "Verifica: bastione verify --target {{ target }}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", root)
    return root


def _finding(
    *,
    rule_id: str = "RLS_DISABLED",
    title: str = "RLS disabilitato",
    severity: Severity = Severity.HIGH,
    endpoint: str | None = "/rest/v1/clienti",
    evidence: str = "[REDACTED]",
    remediation_ref: str | None = "RLS_DISABLED",
    target: str = "https://example.com",
) -> Finding:
    return Finding(
        finding_id="abc123",
        module="supabase",
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        location=Location(endpoint=endpoint),
        evidence=evidence,
        description="desc",
        remediation_ref=remediation_ref,
        status=Status.NEW,
    )


def _posture(
    *,
    check_id: str = "POSTURE_HSTS",
    title: str = "HSTS mancante",
    severity_if_failed: Severity = Severity.HIGH,
    remediation_ref: str | None = "POSTURE_HSTS",
    target: str = "https://example.com",
) -> PostureCheck:
    return PostureCheck(
        check_id=check_id,
        title=title,
        passed=False,
        severity_if_failed=severity_if_failed,
        target=target,
        detail="dettaglio",
        remediation_ref=remediation_ref,
    )


# ─── render_playbook ──────────────────────────────────────────────────────────

def test_render_playbook_rule_noto_non_vuoto(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding())
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert md is not None
    assert md.strip() != ""


def test_render_playbook_contiene_valori_del_context(fake_playbooks):
    ctx = playbooks.context_from_finding(
        _finding(target="https://mio.it", endpoint="/rest/v1/clienti")
    )
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert "clienti" in md            # table derivata
    assert "https://mio.it" in md     # target
    assert "RLS disabilitato" in md   # title


def test_render_playbook_rule_senza_template_ritorna_none(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding(rule_id="INESISTENTE"))
    assert playbooks.render_playbook("INESISTENTE", ctx) is None


def test_render_playbook_rule_id_none_ritorna_none(fake_playbooks):
    assert playbooks.render_playbook(None, {}) is None


# ─── derivazione "table" dall'endpoint ────────────────────────────────────────

def test_table_derivata_da_endpoint_postgrest(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding(endpoint="/rest/v1/clienti"))
    assert ctx["table"] == "clienti"


def test_table_ultimo_segmento_con_query(fake_playbooks):
    ctx = playbooks.context_from_finding(
        _finding(endpoint="/rest/v1/ordini?select=*")
    )
    assert ctx["table"] == "ordini"


def test_table_endpoint_assente_gestito(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding(endpoint=None))
    # Niente crash: table assente/vuota, ma il context resta renderizzabile.
    assert "table" in ctx
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert md is not None


# ─── context_from_finding / context_from_posture ──────────────────────────────

def test_context_from_finding_campi_base(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding(severity=Severity.CRITICAL))
    assert ctx["title"] == "RLS disabilitato"
    assert ctx["severity"] == "CRITICAL"
    assert ctx["target"] == "https://example.com"
    assert ctx["location"]["endpoint"] == "/rest/v1/clienti"


def test_context_from_posture_campi_base(fake_playbooks):
    ctx = playbooks.context_from_posture(_posture(title="HSTS mancante"))
    assert ctx["title"] == "HSTS mancante"
    assert ctx["severity"] == "HIGH"
    assert ctx["target"] == "https://example.com"


# ─── P8: evidence redatta passa invariata ─────────────────────────────────────

def test_render_evidence_redatta_invariata(fake_playbooks):
    ctx = playbooks.context_from_finding(_finding(evidence="[REDACTED:KEY]"))
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert "[REDACTED:KEY]" in md
    assert "sk_live_" not in md
    assert "eyJhbGci" not in md


# ─── Resilienza: jinja2 assente → degrada (None) ──────────────────────────────

def test_jinja2_assente_degrada_a_none(fake_playbooks, monkeypatch):
    # Simula l'assenza di jinja2 facendo fallire il lazy import.
    monkeypatch.setattr(playbooks, "_load_jinja_env", lambda: None)
    ctx = playbooks.context_from_finding(_finding())
    assert playbooks.render_playbook("RLS_DISABLED", ctx) is None


# ─── I template bundled reali esistono e renderizzano ─────────────────────────

@pytest.mark.parametrize("rule_id", [
    "RLS_DISABLED", "RLS_WRITE_OPEN", "SECRET_SERVICE_ROLE", "SECRET_STRIPE",
    "STORAGE_PUBLIC_LISTABLE", "ORIGIN_BYPASSABLE", "POSTURE_HSTS",
    "MISSING_CSP", "SIGNUP_OPEN",
])
def test_template_bundled_reali_renderizzano(rule_id):
    """I template del set iniziale §18 esistono nella root reale e renderizzano
    senza crash con un context minimale (no monkeypatch della dir)."""
    ctx = playbooks.context_from_finding(
        _finding(rule_id=rule_id, remediation_ref=rule_id)
    )
    md = playbooks.render_playbook(rule_id, ctx)
    assert md is not None, f"template mancante per {rule_id}"
    assert md.strip() != ""
    # Il loop di verifica (§18) deve comparire.
    assert "bastione verify" in md


# ─── Regressione: endpoint root /rest/v1/ NON è una tabella (finding "table=v1") ─

@pytest.mark.parametrize("endpoint", ["/rest/v1/", "/rest/v1", "/rest/v2/"])
def test_table_root_rest_non_e_tabella(fake_playbooks, endpoint):
    """I finding di enumerazione schema (SUPABASE_SCHEMA_*) usano endpoint=/rest/v1/:
    l'ultimo segmento è il segmento di VERSIONE (`v1`), non una tabella. Derivare
    `table='v1'` produrrebbe SQL errato (`ALTER TABLE public.v1`). Deve risolvere
    a stringa vuota (nessuna tabella)."""
    ctx = playbooks.context_from_finding(_finding(endpoint=endpoint))
    assert ctx["table"] == ""


def test_schema_via_bundle_finding_non_genera_sql_su_v1():
    """End-to-end col template RLS_DISABLED reale (no monkeypatch della dir): un
    finding tipo SUPABASE_SCHEMA_VIA_BUNDLE (endpoint=/rest/v1/, ref=RLS_DISABLED)
    NON deve produrre `public.v1` né `tabella \\`v1\\``: cade sul fallback <tabella>."""
    ctx = playbooks.context_from_finding(
        _finding(
            rule_id="SUPABASE_SCHEMA_VIA_BUNDLE",
            endpoint="/rest/v1/",
            remediation_ref="RLS_DISABLED",
        )
    )
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert md is not None
    assert "public.v1" not in md
    assert "`v1`" not in md
    # Il fallback generico per la tabella deve comparire al posto del nome errato.
    assert "<tabella>" in md


# ─── Regressione: endpoint=None non rende il letterale 'None' / backtick vuoti ──

def test_rls_disabled_posture_drift_non_rende_none_literale():
    """I PostureCheck POSTURE_RLS_<tabella> portano remediation_ref=RLS_DISABLED e
    location.endpoint=None. Il template RLS_DISABLED non deve stampare il letterale
    'None' né backtick vuoti ``: deve usare il fallback `/rest/v1/<tabella>`."""
    # Usa il template reale per cogliere il difetto della riga 3 del .md bundled.
    pc = _posture(
        check_id="POSTURE_RLS_clienti",
        title="RLS NON attiva",
        remediation_ref="RLS_DISABLED",
    )
    ctx = playbooks.context_from_posture(pc)
    assert ctx["location"]["endpoint"] is None
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert md is not None
    assert "(`None`)" not in md        # niente letterale None
    assert "(``)" not in md            # niente backtick vuoti
    assert "/rest/v1/<tabella>" in md  # fallback esplicito


def test_rls_write_open_endpoint_none_non_rende_none_literale():
    """Stessa guardia coerente in RLS_WRITE_OPEN.md (riga 3)."""
    pc = _posture(
        check_id="POSTURE_RLS_WRITE_clienti",
        title="Scrittura aperta",
        remediation_ref="RLS_WRITE_OPEN",
    )
    ctx = playbooks.context_from_posture(pc)
    md = playbooks.render_playbook("RLS_WRITE_OPEN", ctx)
    assert md is not None
    assert "(`None`)" not in md
    assert "(``)" not in md
    assert "/rest/v1/<tabella>" in md


# ─── Regressione: contenimento del path (no traversal / no SSTI su file arbitrari) ─

@pytest.mark.parametrize("rule_id", [
    "../SENTINEL", "..\\SENTINEL", "../../etc/passwd", "a/b",
    "RLS DISABLED", "rls_disabled", "RLS-DISABLED", "RLS_DISABLED.md",
    "/abs", "C:/Windows/win", "RLS_DISABLED/../x",
])
def test_render_playbook_rifiuta_rule_id_non_whitelisted(fake_playbooks, rule_id):
    """`render_playbook` deve rifiutare (None) ogni rule_id che non sia [A-Z0-9_]+,
    PRIMA di toccare il filesystem: niente path-traversal, niente lettura/SSTI di
    `.md` arbitrari (defense-in-depth §4.7)."""
    assert playbooks.render_playbook(rule_id, {}) is None


def test_render_playbook_traversal_non_legge_file_fuori_da_playbooks(
    tmp_path, monkeypatch
):
    """Anche se esistesse un .md fuori da PLAYBOOKS_DIR, un rule_id con `../` non
    deve leggerlo né renderizzarlo come template Jinja2 (no traversal + no SSTI)."""
    root = tmp_path / "playbooks"
    root.mkdir()
    # File-trappola FUORI da playbooks/, col payload SSTI.
    (tmp_path / "SENTINEL.md").write_text("PWNED {{ 7*7 }}", encoding="utf-8")
    monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", root)
    assert playbooks.render_playbook("../SENTINEL", {}) is None


def test_render_playbook_rule_id_valido_passa_la_whitelist(fake_playbooks):
    """La whitelist non deve ostacolare i rule_id legittimi (regressione opposta)."""
    ctx = playbooks.context_from_finding(_finding())
    assert playbooks.render_playbook("RLS_DISABLED", ctx) is not None


# ─── Regressione: PLAYBOOKS_DIR ancorata al package, non alla CWD ──────────────

def test_playbooks_dir_ancorata_al_package_non_cwd():
    """La dir di default dei template è ancorata al repo (sibling di `bastione/`),
    NON relativa alla CWD: i template bundled non devono sparire se il processo gira
    da un'altra working directory."""
    # È un path assoluto, non il relativo "playbooks" risolto sulla CWD.
    assert playbooks.PLAYBOOKS_DIR.is_absolute()
    # Punta a <repo>/playbooks ed è una dir esistente che contiene i template reali.
    assert playbooks.PLAYBOOKS_DIR.name == "playbooks"
    assert (playbooks.PLAYBOOKS_DIR / "RLS_DISABLED.md").is_file()


def test_render_playbook_funziona_con_cwd_diversa(tmp_path, monkeypatch):
    """Con CWD != root del repo i playbook bundled restano renderizzabili (il default
    è ancorato al package, non alla CWD)."""
    monkeypatch.chdir(tmp_path)  # CWD lontana dalla root del repo
    ctx = playbooks.context_from_finding(_finding())
    md = playbooks.render_playbook("RLS_DISABLED", ctx)
    assert md is not None
    assert "bastione verify" in md
