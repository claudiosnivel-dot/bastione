"""Test di bastione/normalize/defectdojo.py (§T4) — OFFLINE puri.

Copertura:
- to_defectdojo: struttura payload, mapping severità TITLE-CASE, tutti i campi;
- P8: nessun segreto (evidence non inclusa) nel payload;
- date/line/cvssv3_score: inclusi solo se valorizzati;
- file_path: priorità url > endpoint > file;
- tags: owasp + [module, status];
- active: True per NEW/KNOWN, False per ACCEPTED/FIXED/DRIFT;
- false_p: sempre False;
- round-trip write / read (write_defectdojo_export su tmp);
- push_to_defectdojo "skipped" quando env assenti (monkeypatch os.environ vuoto,
  asserisce _post NON chiamato);
- push con env presenti → monkeypatch _post_defectdojo, asserisce chiamato con
  url/token corretti, NESSUNA rete reale;
- resilienza: _post che solleva → push ritorna "error:..." senza propagare;
- confine reale _post_defectdojo: monkeypatch httpx.post (mai rete reale) e
  verifica upload MULTIPART (file + data), URL con/senza trailing slash, header
  Authorization, propagazione status_code, engagement nei campi form;
- robustezza: ramo httpx-assente (§4.7) → None senza sollevare;
- robustezza: payload non-mapping documentato (json.dumps lo serializza comunque);
- gating env engagement: BASTIONE_DEFECTDOJO_ENGAGEMENT propagato a _post_defectdojo.
"""

from __future__ import annotations

import builtins
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

from bastione.enums import Confidence, IntrusionLevel, Severity, Status
from bastione.models import Finding, Location
from bastione.normalize import defectdojo as dd_mod
from bastione.normalize.defectdojo import (
    URL_ENV,
    TOKEN_ENV,
    ENGAGEMENT_ENV,
    push_to_defectdojo,
    to_defectdojo,
    write_defectdojo_export,
)


# ─── factory helper ─────────────────────────────────────────────────────────

def make_finding(
    *,
    finding_id: str = "abc123def456789a",
    module: str = "headers",
    rule_id: str = "MISSING_HSTS",
    title: str = "HSTS mancante",
    severity: Severity = Severity.HIGH,
    description: str = "Il sito non invia Strict-Transport-Security.",
    location: Location | None = None,
    owasp: list[str] | None = None,
    cvss: float | None = None,
    status: Status = Status.NEW,
    last_seen: datetime | None = None,
    evidence: str = "[REDATTO]",
) -> Finding:
    """Costruisce un Finding sintetico con valori di default ragionevoli."""
    return Finding(
        finding_id=finding_id,
        module=module,
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target="https://example.com",
        location=location or Location(url="https://example.com"),
        evidence=evidence,
        description=description,
        owasp=owasp or [],
        cvss=cvss,
        status=status,
        last_seen=last_seen,
    )


# ─── struttura di alto livello ───────────────────────────────────────────────

def test_payload_ha_chiave_findings():
    """Il payload deve avere la chiave 'findings' (§T4)."""
    payload = to_defectdojo([], target="https://example.com")
    assert "findings" in payload
    assert isinstance(payload["findings"], list)


def test_lista_vuota_findings_vuota():
    """Lista vuota di finding → payload["findings"] == [] ma struttura valida."""
    payload = to_defectdojo([], target="https://example.com")
    assert payload["findings"] == []


def test_numero_findings_corrisponde():
    """Numero di oggetti in payload["findings"] == numero di finding in input."""
    f1 = make_finding(finding_id="id0000000000001a")
    f2 = make_finding(finding_id="id0000000000002b")
    payload = to_defectdojo([f1, f2], target="https://example.com")
    assert len(payload["findings"]) == 2


# ─── mapping severity → TITLE-CASE (§T4) ───────────────────────────────────

def test_severity_critical_mappa_Critical():
    f = make_finding(severity=Severity.CRITICAL)
    items = to_defectdojo([f], target="t")["findings"]
    assert items[0]["severity"] == "Critical"


def test_severity_high_mappa_High():
    f = make_finding(severity=Severity.HIGH)
    items = to_defectdojo([f], target="t")["findings"]
    assert items[0]["severity"] == "High"


def test_severity_medium_mappa_Medium():
    f = make_finding(severity=Severity.MEDIUM)
    items = to_defectdojo([f], target="t")["findings"]
    assert items[0]["severity"] == "Medium"


def test_severity_low_mappa_Low():
    f = make_finding(severity=Severity.LOW)
    items = to_defectdojo([f], target="t")["findings"]
    assert items[0]["severity"] == "Low"


def test_severity_info_mappa_Info():
    f = make_finding(severity=Severity.INFO)
    items = to_defectdojo([f], target="t")["findings"]
    assert items[0]["severity"] == "Info"


# ─── campi obbligatori (§T4) ─────────────────────────────────────────────────

def test_unique_id_from_tool_uguale_finding_id():
    """unique_id_from_tool deve essere il finding_id stabile (§16)."""
    fid = "deadbeef12345678"
    f = make_finding(finding_id=fid)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["unique_id_from_tool"] == fid


def test_vuln_id_from_tool_uguale_rule_id():
    """vuln_id_from_tool deve essere il rule_id (§T4)."""
    f = make_finding(rule_id="RLS_DISABLED")
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["vuln_id_from_tool"] == "RLS_DISABLED"


def test_title_e_description_presenti():
    """title e description devono essere inclusi (§T4)."""
    f = make_finding(title="HSTS mancante", description="Descrizione dettagliata.")
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["title"] == "HSTS mancante"
    assert item["description"] == "Descrizione dettagliata."


def test_false_p_sempre_False():
    """false_p deve essere sempre False (§T4)."""
    f = make_finding()
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["false_p"] is False


# ─── campo active (§T4) ─────────────────────────────────────────────────────

def test_active_True_per_NEW():
    f = make_finding(status=Status.NEW)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["active"] is True


def test_active_True_per_KNOWN():
    f = make_finding(status=Status.KNOWN)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["active"] is True


def test_active_False_per_ACCEPTED():
    f = make_finding(status=Status.ACCEPTED)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["active"] is False


def test_active_False_per_FIXED():
    f = make_finding(status=Status.FIXED)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["active"] is False


# ─── campo date: presente solo se last_seen valorizzato (§T4) ───────────────

def test_date_formato_YYYY_MM_DD_se_last_seen_presente():
    """date deve essere "YYYY-MM-DD" quando last_seen è valorizzato (§T4)."""
    ts = datetime(2026, 3, 15, 10, 30, 0)
    f = make_finding(last_seen=ts)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["date"] == "2026-03-15"


def test_date_assente_se_last_seen_None():
    """date non deve essere presente se last_seen è None (§T4)."""
    f = make_finding(last_seen=None)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "date" not in item


# ─── campo line: presente solo se location.line valorizzato (§T4) ───────────

def test_line_presente_se_location_line_valorizzata():
    f = make_finding(location=Location(url="https://example.com", line=42))
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["line"] == 42


def test_line_assente_se_location_line_None():
    f = make_finding(location=Location(url="https://example.com"))
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "line" not in item


# ─── campo cvssv3_score: presente solo se cvss non-None (§T4) ───────────────

def test_cvssv3_score_presente_se_cvss_valorizzato():
    f = make_finding(cvss=7.5)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["cvssv3_score"] == 7.5


def test_cvssv3_score_assente_se_cvss_None():
    f = make_finding(cvss=None)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "cvssv3_score" not in item


# ─── file_path: priorità url > endpoint > file (§T4) ────────────────────────

def test_file_path_da_url():
    f = make_finding(location=Location(url="https://example.com/api", endpoint="/ep", file="f.js"))
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["file_path"] == "https://example.com/api"


def test_file_path_da_endpoint_se_url_None():
    f = make_finding(location=Location(endpoint="/rest/v1/users", file="f.js"))
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["file_path"] == "/rest/v1/users"


def test_file_path_da_file_se_url_e_endpoint_None():
    f = make_finding(location=Location(file="assets/index.js"))
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["file_path"] == "assets/index.js"


def test_file_path_stringa_vuota_se_tutto_None():
    f = make_finding(location=Location())
    item = to_defectdojo([f], target="t")["findings"][0]
    assert item["file_path"] == ""


# ─── tags: owasp + [module, status] (§T4) ───────────────────────────────────

def test_tags_contengono_owasp():
    f = make_finding(owasp=["A01:2021", "A05:2021"])
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "A01:2021" in item["tags"]
    assert "A05:2021" in item["tags"]


def test_tags_contengono_module():
    f = make_finding(module="supabase")
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "supabase" in item["tags"]


def test_tags_contengono_status():
    f = make_finding(status=Status.KNOWN)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "known" in item["tags"]


def test_tags_senza_owasp_ha_almeno_module_e_status():
    f = make_finding(owasp=[], module="headers", status=Status.NEW)
    item = to_defectdojo([f], target="t")["findings"][0]
    assert "headers" in item["tags"]
    assert "new" in item["tags"]


# ─── P8: nessun segreto nel payload (§T4) ───────────────────────────────────

def test_p8_evidence_non_inclusa():
    """L'evidence non deve comparire nel payload (P8)."""
    f = make_finding(evidence="TOP-SECRET-CHIAVE-XYZ")
    payload = to_defectdojo([f], target="t")
    payload_str = json.dumps(payload)
    assert "TOP-SECRET-CHIAVE-XYZ" not in payload_str


def test_p8_evidence_redatta_non_inclusa():
    """Anche '[REDATTO]' non è incluso: il campo evidence è omesso."""
    f = make_finding(evidence="[REDATTO]")
    payload = to_defectdojo([f], target="t")
    # Verifica che nessun finding abbia la chiave "evidence"
    for item in payload["findings"]:
        assert "evidence" not in item


# ─── round-trip write / read (§T4) ──────────────────────────────────────────

def test_write_defectdojo_export_crea_file_json(tmp_path):
    """write_defectdojo_export deve creare un file JSON leggibile."""
    f = make_finding()
    payload = to_defectdojo([f], target="https://example.com")
    out = tmp_path / "export" / "dojo.json"

    write_defectdojo_export(out, payload)

    assert out.exists()
    with out.open("r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    assert loaded == payload


def test_write_defectdojo_export_round_trip_multifindings(tmp_path):
    """Round-trip con più finding: il file riletto coincide col payload originale."""
    findings = [
        make_finding(finding_id="id0000000000001a", severity=Severity.CRITICAL, cvss=9.8),
        make_finding(finding_id="id0000000000002b", severity=Severity.LOW, owasp=["A01:2021"]),
    ]
    payload = to_defectdojo(findings, target="https://example.com")
    out = tmp_path / "dojo_multi.json"

    write_defectdojo_export(out, payload)

    with out.open("r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    assert len(loaded["findings"]) == 2
    assert loaded["findings"][0]["severity"] == "Critical"
    assert loaded["findings"][0]["cvssv3_score"] == 9.8
    assert "A01:2021" in loaded["findings"][1]["tags"]


# ─── push_to_defectdojo: gate env assenti → "skipped" (§T4) ─────────────────

def test_push_skipped_quando_env_assenti(monkeypatch):
    """push_to_defectdojo deve ritornare 'skipped' senza chiamare _post se env assenti."""
    monkeypatch.delenv(URL_ENV, raising=False)
    monkeypatch.delenv(TOKEN_ENV, raising=False)

    called = {"n": 0}

    def _boom(url, token, payload, engagement=""):  # pragma: no cover
        called["n"] += 1
        raise AssertionError("_post_defectdojo NON deve essere chiamato senza env")

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom, raising=True)

    result = push_to_defectdojo({"findings": []})

    assert result == "skipped"
    assert called["n"] == 0


def test_push_skipped_quando_solo_url(monkeypatch):
    """Senza token → 'skipped' (gate richiede entrambi)."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.delenv(TOKEN_ENV, raising=False)

    called = {"n": 0}

    def _boom(url, token, payload, engagement=""):  # pragma: no cover
        called["n"] += 1

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom, raising=True)

    result = push_to_defectdojo({"findings": []})
    assert result == "skipped"
    assert called["n"] == 0


def test_push_skipped_quando_solo_token(monkeypatch):
    """Senza url → 'skipped' (gate richiede entrambi)."""
    monkeypatch.delenv(URL_ENV, raising=False)
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    called = {"n": 0}

    def _boom(url, token, payload, engagement=""):  # pragma: no cover
        called["n"] += 1

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom, raising=True)

    result = push_to_defectdojo({"findings": []})
    assert result == "skipped"
    assert called["n"] == 0


# ─── push_to_defectdojo: env presenti → chiama _post con url/token (§T4) ────

def test_push_con_env_chiama_post(monkeypatch):
    """Con env presenti, push_to_defectdojo chiama _post_defectdojo con url e token."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "api-token-xyz")

    captured = {}

    def _fake_post(url, token, payload, engagement=""):
        captured["url"] = url
        captured["token"] = token
        captured["payload"] = payload
        captured["engagement"] = engagement
        return 201

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _fake_post, raising=True)

    result = push_to_defectdojo({"findings": []})

    assert result == "pushed"
    assert captured["url"] == "https://dojo.example.com"
    assert captured["token"] == "api-token-xyz"


def test_push_passa_payload_a_post(monkeypatch):
    """Il payload viene passato intatto a _post_defectdojo."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    f = make_finding(finding_id="id0000000000003c", severity=Severity.MEDIUM)
    payload = to_defectdojo([f], target="https://example.com")

    received = {}

    def _fake_post(url, token, p, engagement=""):
        received["payload"] = p
        return 200

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _fake_post, raising=True)

    push_to_defectdojo(payload)

    assert received["payload"] == payload


def test_push_nessuna_rete_reale(monkeypatch):
    """Garanzia OFFLINE: _post_defectdojo è monkeypatchato, nessuna rete reale."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    network_called = {"n": 0}

    def _fake_post(url, token, payload, engagement=""):
        # Simula un POST riuscito senza rete
        network_called["n"] += 1
        return 201

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _fake_post, raising=True)

    result = push_to_defectdojo({"findings": []})

    assert result == "pushed"
    assert network_called["n"] == 1   # chiamato esattamente una volta


# ─── resilienza: _post che solleva → "error:..." senza propagare (§T4) ──────

def test_push_error_se_post_solleva(monkeypatch):
    """Se _post_defectdojo solleva, push ritorna 'error:<msg>' senza propagare."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    def _boom(url, token, payload, engagement=""):
        raise ConnectionError("timeout di rete")

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom, raising=True)

    result = push_to_defectdojo({"findings": []})   # NON deve sollevare

    assert result.startswith("error:")
    assert "timeout di rete" in result


def test_push_error_msg_non_propaga(monkeypatch):
    """La resilienza vale per qualsiasi Exception: nessuna propagazione."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    def _boom(url, token, payload, engagement=""):
        raise ValueError("unexpected value in response")

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _boom, raising=True)

    # Deve tornare "error:..." senza sollevare
    result = push_to_defectdojo({"findings": []})
    assert result.startswith("error:")
    assert "unexpected value in response" in result


# ─── scenario combinato (§T4) ────────────────────────────────────────────────

def test_scenario_completo_multi_finding():
    """Scenario con tre finding: tutti i campi, severità diverse, dedup non richiesto."""
    f1 = make_finding(
        finding_id="id1111111111111a",
        rule_id="RULE_A",
        title="Titolo A",
        severity=Severity.CRITICAL,
        location=Location(url="https://example.com", endpoint="/api/v1", line=10),
        owasp=["A01:2021"],
        cvss=9.8,
        status=Status.NEW,
        last_seen=datetime(2026, 6, 1, 0, 0, 0),
        module="supabase",
    )
    f2 = make_finding(
        finding_id="id2222222222222b",
        rule_id="RULE_B",
        title="Titolo B",
        severity=Severity.MEDIUM,
        location=Location(file="assets/chunk.js", line=5),
        owasp=[],
        cvss=None,
        status=Status.KNOWN,
        last_seen=None,
        module="secrets",
    )
    f3 = make_finding(
        finding_id="id3333333333333c",
        rule_id="RULE_C",
        title="Titolo C",
        severity=Severity.LOW,
        location=Location(endpoint="/rest/v1/data"),
        owasp=["A05:2021"],
        cvss=3.1,
        status=Status.FIXED,
        last_seen=datetime(2026, 5, 20, 12, 0, 0),
        module="headers",
    )

    payload = to_defectdojo([f1, f2, f3], target="https://example.com")
    findings = payload["findings"]

    assert len(findings) == 3

    by_id = {item["unique_id_from_tool"]: item for item in findings}

    # f1: CRITICAL, NEW (active=True), url, line, cvss, date, owasp
    a = by_id["id1111111111111a"]
    assert a["severity"] == "Critical"
    assert a["active"] is True
    assert a["file_path"] == "https://example.com"
    assert a["line"] == 10
    assert a["cvssv3_score"] == 9.8
    assert a["date"] == "2026-06-01"
    assert "A01:2021" in a["tags"]
    assert "supabase" in a["tags"]
    assert "new" in a["tags"]
    assert a["false_p"] is False
    assert "evidence" not in a          # P8

    # f2: MEDIUM, KNOWN (active=True), file, line=5, no cvss, no date
    b = by_id["id2222222222222b"]
    assert b["severity"] == "Medium"
    assert b["active"] is True
    assert b["file_path"] == "assets/chunk.js"
    assert b["line"] == 5
    assert "cvssv3_score" not in b
    assert "date" not in b
    assert "secrets" in b["tags"]
    assert "known" in b["tags"]

    # f3: LOW, FIXED (active=False), endpoint (no url), cvss, date
    c = by_id["id3333333333333c"]
    assert c["severity"] == "Low"
    assert c["active"] is False
    assert c["file_path"] == "/rest/v1/data"
    assert c["cvssv3_score"] == 3.1
    assert c["date"] == "2026-05-20"
    assert "A05:2021" in c["tags"]
    assert "headers" in c["tags"]
    assert "fixed" in c["tags"]


# ─── confine reale _post_defectdojo: monkeypatch httpx.post (NO rete) ────────
#
# Questi test esercitano il CORPO di _post_defectdojo (non lo sostituiscono):
# monkeypatchano httpx.post — l'unica chiamata di rete reale — con un fake che
# cattura argomenti e ritorna un oggetto con .status_code. ZERO rete reale.

class _FakeResp:
    """Risposta httpx fittizia: espone solo .status_code (come usato dal codice)."""

    def __init__(self, status_code: int):
        self.status_code = status_code


def _install_fake_httpx_post(monkeypatch, *, status_code=201, capture=None):
    """Monkeypatcha httpx.post con un fake che cattura kwargs e ritorna _FakeResp.

    Ritorna il dict `capture` popolato alla chiamata. NESSUNA rete reale: il
    confine è httpx.post stesso, sostituito qui (§7 boundary monkeypatchabile).
    """
    import httpx

    cap = capture if capture is not None else {}

    def _fake_post(endpoint, **kwargs):
        cap["endpoint"] = endpoint
        cap["files"] = kwargs.get("files")
        cap["data"] = kwargs.get("data")
        cap["headers"] = kwargs.get("headers")
        cap["timeout"] = kwargs.get("timeout")
        cap["json"] = kwargs.get("json")
        return _FakeResp(status_code)

    monkeypatch.setattr(httpx, "post", _fake_post, raising=True)
    return cap


def test_post_costruisce_endpoint_import_scan(monkeypatch):
    """_post_defectdojo deve postare su '<base>/api/v2/import-scan/'."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert cap["endpoint"] == "https://dojo.example.com/api/v2/import-scan/"


def test_post_normalizza_trailing_slash(monkeypatch):
    """Un trailing slash sull'URL base NON deve produrre '//api/...' (rstrip)."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com/", "tok", {"findings": []})
    assert cap["endpoint"] == "https://dojo.example.com/api/v2/import-scan/"


def test_post_header_authorization_token(monkeypatch):
    """L'header Authorization deve essere 'Token <token>' (contratto DefectDojo)."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com", "api-token-xyz", {"findings": []})
    assert cap["headers"]["Authorization"] == "Token api-token-xyz"


def test_post_invia_multipart_non_json_inline(monkeypatch):
    """REGRESSIONE (difetto 1): import-scan richiede multipart/form-data.

    Il documento Generic Findings Import va caricato come FILE (campo 'file'),
    NON come body JSON inline. Verifica che httpx.post riceva `files=...` e
    NON `json=...`.
    """
    cap = _install_fake_httpx_post(monkeypatch)
    payload = {"findings": [{"title": "x"}]}
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", payload)

    # json inline NON deve essere usato
    assert cap["json"] is None
    # il file multipart deve esserci
    assert cap["files"] is not None
    assert "file" in cap["files"]


def test_post_file_e_documento_generic_findings_import(monkeypatch):
    """REGRESSIONE (difetto 1): il file caricato contiene il payload serializzato.

    Il campo 'file' è una tupla (filename, contenuto, content-type) e il
    contenuto, una volta riletto, coincide col payload Generic Findings Import.
    """
    cap = _install_fake_httpx_post(monkeypatch)
    payload = {"findings": [{"title": "HSTS mancante", "severity": "High"}]}
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", payload)

    filename, content, content_type = cap["files"]["file"]
    assert filename == "bastione.json"
    assert content_type == "application/json"
    assert json.loads(content) == payload


def test_post_scan_type_in_data_non_in_file(monkeypatch):
    """REGRESSIONE (difetto 1): scan_type è un campo FORM (data), non nel file."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert cap["data"]["scan_type"] == "Generic Findings Import"

    # e NON deve essere finito dentro il documento caricato come file
    _, content, _ = cap["files"]["file"]
    assert "scan_type" not in json.loads(content)


def test_post_engagement_in_data_se_valorizzato(monkeypatch):
    """REGRESSIONE (difetto 2): engagement passato → presente nei campi form."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo(
        "https://dojo.example.com", "tok", {"findings": []}, "42"
    )
    assert cap["data"]["engagement"] == "42"


def test_post_engagement_assente_se_vuoto(monkeypatch):
    """REGRESSIONE (difetto 2): engagement vuoto → chiave 'engagement' omessa."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []}, "")
    assert "engagement" not in cap["data"]


def test_post_propaga_status_code(monkeypatch):
    """REGRESSIONE (difetto 4): il valore di ritorno è resp.status_code."""
    _install_fake_httpx_post(monkeypatch, status_code=201)
    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert rc == 201


def test_post_propaga_status_code_4xx(monkeypatch):
    """REGRESSIONE (difetto 4): anche un 4xx viene propagato (non sollevato qui)."""
    _install_fake_httpx_post(monkeypatch, status_code=400)
    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert rc == 400


def test_post_timeout_passato(monkeypatch):
    """Il timeout HTTP corto (best-effort §19) deve essere passato a httpx.post."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert cap["timeout"] == dd_mod._HTTP_TIMEOUT


def test_post_token_non_in_file_ne_data(monkeypatch):
    """P8: il token NON deve finire nel file caricato né nei campi form."""
    cap = _install_fake_httpx_post(monkeypatch)
    dd_mod._post_defectdojo(
        "https://dojo.example.com", "super-secret-token", {"findings": []}, "7"
    )
    _, content, _ = cap["files"]["file"]
    assert "super-secret-token" not in content
    assert "super-secret-token" not in json.dumps(cap["data"])


# ─── robustezza: ramo httpx ASSENTE (§4.7) → None senza sollevare ───────────

def test_post_httpx_assente_ritorna_None(monkeypatch):
    """REGRESSIONE (difetto 3): se 'import httpx' fallisce, _post ritorna None.

    Simula la dipendenza assente intercettando builtins.__import__ per sollevare
    ImportError su 'httpx'. Verifica il degrado grazioso (§4.7): None, nessuna
    eccezione propagata, nessuna rete toccata.
    """
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("No module named 'httpx'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import, raising=True)

    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert rc is None


def test_post_httpx_assente_via_sys_modules(monkeypatch):
    """REGRESSIONE (difetto 3): httpx=None in sys.modules → None, nessun crash."""
    monkeypatch.setitem(sys.modules, "httpx", None)
    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", {"findings": []})
    assert rc is None


def test_push_pushed_con_httpx_assente(monkeypatch):
    """REGRESSIONE (difetto 3): push_to_defectdojo con env presenti + httpx assente.

    Esercita il percorso REALE (non monkeypatcha _post_defectdojo): env presenti,
    httpx assente → _post ritorna None (degrado grazioso §4.7) → push ritorna
    'pushed' con status None loggato. Nessuna rete reale, nessun crash.
    """
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("No module named 'httpx'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import, raising=True)

    result = push_to_defectdojo({"findings": []})
    assert result == "pushed"


# ─── robustezza: payload NON-mapping (documenta il comportamento del confine) ─

def test_post_payload_non_mapping_viene_serializzato(monkeypatch):
    """REGRESSIONE (difetto 4): payload non-mapping NON crolla più con '**payload'.

    Con l'upload multipart il payload viene serializzato via json.dumps (non più
    fuso con '**payload'): un payload list-of-dict viene comunque caricato come
    file senza TypeError. Documenta il nuovo comportamento robusto del confine.
    """
    cap = _install_fake_httpx_post(monkeypatch)
    payload = [{"title": "x"}]  # NON un mapping
    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", payload)
    assert rc == 201
    _, content, _ = cap["files"]["file"]
    assert json.loads(content) == payload


def test_post_payload_none_viene_serializzato_null(monkeypatch):
    """REGRESSIONE (difetto 4): payload=None → file con 'null', nessun TypeError.

    Prima il merge '**payload' sollevava TypeError su None; ora json.dumps(None)
    produce 'null' e il confine non solleva (resilienza confine I/O).
    """
    cap = _install_fake_httpx_post(monkeypatch)
    rc = dd_mod._post_defectdojo("https://dojo.example.com", "tok", None)
    assert rc == 201
    _, content, _ = cap["files"]["file"]
    assert json.loads(content) is None


# ─── gating env engagement: BASTIONE_DEFECTDOJO_ENGAGEMENT propagato (§T4) ───

def test_push_propaga_engagement_a_post(monkeypatch):
    """REGRESSIONE (difetto 2/5): l'engagement letto dall'env arriva a _post.

    Esercita il ramo ENGAGEMENT_ENV in push_to_defectdojo: con la env valorizzata,
    _post_defectdojo riceve l'engagement come 4° argomento.
    """
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")
    monkeypatch.setenv(ENGAGEMENT_ENV, "99")

    captured = {}

    def _fake_post(url, token, payload, engagement=""):
        captured["engagement"] = engagement
        return 201

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _fake_post, raising=True)

    result = push_to_defectdojo({"findings": []})
    assert result == "pushed"
    assert captured["engagement"] == "99"


def test_push_engagement_assente_passa_stringa_vuota(monkeypatch):
    """REGRESSIONE (difetto 5): senza ENGAGEMENT_ENV, _post riceve '' (default)."""
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")
    monkeypatch.delenv(ENGAGEMENT_ENV, raising=False)

    captured = {}

    def _fake_post(url, token, payload, engagement=""):
        captured["engagement"] = engagement
        return 201

    monkeypatch.setattr(dd_mod, "_post_defectdojo", _fake_post, raising=True)

    result = push_to_defectdojo({"findings": []})
    assert result == "pushed"
    assert captured["engagement"] == ""


def test_push_end_to_end_engagement_in_form_data(monkeypatch):
    """REGRESSIONE (difetto 2): catena completa env→push→_post→httpx multipart.

    Esercita il percorso REALE (httpx.post monkeypatchato, _post_defectdojo NON
    sostituito): la env engagement deve finire nei campi form del POST multipart.
    """
    monkeypatch.setenv(URL_ENV, "https://dojo.example.com")
    monkeypatch.setenv(TOKEN_ENV, "token-abc")
    monkeypatch.setenv(ENGAGEMENT_ENV, "123")

    cap = _install_fake_httpx_post(monkeypatch)

    result = push_to_defectdojo({"findings": []})
    assert result == "pushed"
    assert cap["data"]["engagement"] == "123"
    assert cap["data"]["scan_type"] == "Generic Findings Import"
    assert "file" in cap["files"]
