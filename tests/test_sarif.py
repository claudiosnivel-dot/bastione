"""Test di to_sarif (§23) — conversione Finding[] → SARIF 2.1.0.

Copriamo:
- struttura valida: version "2.1.0", schema ufficiale, tool.driver.name=="Bastione";
- mapping severity → SARIF level per tutti e cinque i livelli;
- partialFingerprints.findingId == finding.finding_id;
- deduplicazione rules per rule_id (2 finding con lo stesso rule_id → 1 rule);
- uri da location.url, file da location.file;
- endpoint → logicalLocations[].fullyQualifiedName;
- line → region.startLine;
- owasp → tags nelle properties;
- cvss → properties["security-severity"];
- lista vuota → runs[0].results vuoto ma struttura valida.

Test OFFLINE puri: Finding sintetici costruiti con i veri tipi bastione.models.
"""

from __future__ import annotations

import bastione
from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import Finding, Location
from bastione.normalize.sarif import to_sarif


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
        evidence="[REDATTO]",
        description=description,
        owasp=owasp or [],
        cvss=cvss,
    )


# ─── struttura di alto livello ───────────────────────────────────────────────

def test_version_e_schema():
    """Il documento SARIF deve avere version "2.1.0" e lo $schema ufficiale (§23)."""
    doc = to_sarif([], target="https://example.com")
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    # Schema ufficiale SARIF 2.1.0
    assert "sarif-schema" in doc["$schema"] or "schemastore" in doc["$schema"] or "json.schemastore" in doc["$schema"] or "sarifweb" in doc["$schema"]


def test_runs_e_tool_driver():
    """runs[0].tool.driver deve avere name="Bastione" e la version del package (§23)."""
    doc = to_sarif([], target="https://example.com")
    assert "runs" in doc
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Bastione"
    assert driver["version"] == bastione.__version__


def test_lista_vuota_results_vuoto():
    """Lista vuota di finding → results=[] ma struttura valida (§23)."""
    doc = to_sarif([], target="https://example.com")
    assert doc["runs"][0]["results"] == []
    assert "rules" in doc["runs"][0]["tool"]["driver"]


# ─── mapping severity → level (§23) ─────────────────────────────────────────

def test_severity_critical_mappa_error():
    f = make_finding(severity=Severity.CRITICAL, finding_id="aaa1")
    doc = to_sarif([f], target="t")
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_severity_high_mappa_error():
    f = make_finding(severity=Severity.HIGH, finding_id="aaa2")
    doc = to_sarif([f], target="t")
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_severity_medium_mappa_warning():
    f = make_finding(severity=Severity.MEDIUM, finding_id="aaa3")
    doc = to_sarif([f], target="t")
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def test_severity_low_mappa_note():
    f = make_finding(severity=Severity.LOW, finding_id="aaa4")
    doc = to_sarif([f], target="t")
    assert doc["runs"][0]["results"][0]["level"] == "note"


def test_severity_info_mappa_note():
    f = make_finding(severity=Severity.INFO, finding_id="aaa5")
    doc = to_sarif([f], target="t")
    assert doc["runs"][0]["results"][0]["level"] == "note"


# ─── partialFingerprints (§23) ───────────────────────────────────────────────

def test_partial_fingerprints_finding_id():
    """partialFingerprints.findingId deve corrispondere a finding.finding_id (§23)."""
    fid = "deadbeef12345678"
    f = make_finding(finding_id=fid)
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    assert result["partialFingerprints"]["findingId"] == fid


# ─── deduplicazione rules per rule_id (§23) ──────────────────────────────────

def test_rules_deduplicati_stesso_rule_id():
    """Due finding con lo stesso rule_id → una sola rule nel driver (§23)."""
    f1 = make_finding(finding_id="id0000000000001a", rule_id="MISSING_HSTS")
    f2 = make_finding(finding_id="id0000000000002b", rule_id="MISSING_HSTS")
    doc = to_sarif([f1, f2], target="t")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids.count("MISSING_HSTS") == 1
    assert len(rules) == 1


def test_rules_separate_per_rule_id_diversi():
    """Finding con rule_id diversi → due rule distinte (§23)."""
    f1 = make_finding(finding_id="id0000000000003c", rule_id="MISSING_HSTS")
    f2 = make_finding(finding_id="id0000000000004d", rule_id="RLS_DISABLED")
    doc = to_sarif([f1, f2], target="t")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"MISSING_HSTS", "RLS_DISABLED"}


def test_rule_ha_short_description():
    """Ogni rule deve avere shortDescription.text (§23)."""
    f = make_finding(rule_id="TEST_RULE", title="Titolo di test")
    doc = to_sarif([f], target="t")
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "shortDescription" in rule
    assert isinstance(rule["shortDescription"]["text"], str)
    assert len(rule["shortDescription"]["text"]) > 0


# ─── locations: uri da url/file (§23) ────────────────────────────────────────

def test_location_uri_da_url():
    """location.url → physicalLocation.artifactLocation.uri (§23)."""
    f = make_finding(location=Location(url="https://example.com/api"))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    locs = result.get("locations", [])
    assert len(locs) >= 1
    uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/api"


def test_location_uri_da_file_se_url_assente():
    """location.file → physicalLocation.artifactLocation.uri quando url è None (§23)."""
    f = make_finding(location=Location(file="assets/index.js"))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    locs = result.get("locations", [])
    assert len(locs) >= 1
    uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "assets/index.js"


def test_location_region_start_line():
    """location.line → region.startLine (§23)."""
    f = make_finding(location=Location(url="https://example.com", line=42))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"].get("region", {})
    assert region.get("startLine") == 42


def test_location_no_region_se_line_assente():
    """Se location.line è None, region non deve essere presente (o startLine assente) (§23)."""
    f = make_finding(location=Location(url="https://example.com"))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    phys = result["locations"][0]["physicalLocation"]
    region = phys.get("region", {})
    assert "startLine" not in region


# ─── logicalLocations da endpoint (§23) ──────────────────────────────────────

def test_logical_location_da_endpoint():
    """location.endpoint → logicalLocations[].fullyQualifiedName (§23)."""
    f = make_finding(location=Location(url="https://example.com", endpoint="/rest/v1/users"))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    logical = result.get("locations", [{}])[0].get("logicalLocations", [])
    assert len(logical) >= 1
    assert logical[0]["fullyQualifiedName"] == "/rest/v1/users"


def test_no_logical_location_se_endpoint_assente():
    """Se endpoint è None, logicalLocations non deve essere presente (§23)."""
    f = make_finding(location=Location(url="https://example.com"))
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    loc = result.get("locations", [{}])[0]
    # O logicalLocations è assente, o è vuoto
    logical = loc.get("logicalLocations", [])
    assert logical == []


# ─── properties: tags OWASP e security-severity CVSS (§23) ──────────────────

def test_owasp_tags_in_properties():
    """finding.owasp → properties.tags (§23)."""
    f = make_finding(owasp=["A01:2021", "A05:2021"])
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    props = result.get("properties", {})
    assert props.get("tags") == ["A01:2021", "A05:2021"]


def test_cvss_in_properties_se_presente():
    """finding.cvss → properties["security-severity"] come stringa (§23)."""
    f = make_finding(cvss=7.5)
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    props = result.get("properties", {})
    assert props.get("security-severity") == "7.5"


def test_no_security_severity_se_cvss_assente():
    """Se cvss è None, "security-severity" non deve apparire nelle properties (§23)."""
    f = make_finding(cvss=None)
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    props = result.get("properties", {})
    assert "security-severity" not in props


# ─── message (§23) ──────────────────────────────────────────────────────────

def test_message_text_contiene_titolo():
    """message.text deve contenere almeno il title del finding (§23)."""
    f = make_finding(title="HSTS mancante")
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    assert "HSTS mancante" in result["message"]["text"]


def test_rule_id_nel_result():
    """results[].ruleId == finding.rule_id (§23)."""
    f = make_finding(rule_id="MISSING_HSTS")
    doc = to_sarif([f], target="t")
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "MISSING_HSTS"


# ─── scenario combinato (§23) ────────────────────────────────────────────────

def test_scenario_completo_multi_finding():
    """Scenario con tre finding: dedup rules, tutti i livelli, fingerprints, locations."""
    f1 = make_finding(
        finding_id="id1111111111111a",
        rule_id="RULE_A",
        severity=Severity.CRITICAL,
        location=Location(url="https://example.com", endpoint="/api/v1", line=10),
        owasp=["A01:2021"],
        cvss=9.8,
    )
    f2 = make_finding(
        finding_id="id2222222222222b",
        rule_id="RULE_A",  # stesso rule_id → regola deduplicata
        severity=Severity.MEDIUM,
        location=Location(file="assets/chunk.js", line=5),
        owasp=[],
        cvss=None,
    )
    f3 = make_finding(
        finding_id="id3333333333333c",
        rule_id="RULE_B",
        severity=Severity.LOW,
        location=Location(url="https://example.com/other"),
        owasp=["A05:2021"],
        cvss=3.1,
    )
    doc = to_sarif([f1, f2, f3], target="https://example.com")

    # Struttura
    assert doc["version"] == "2.1.0"
    runs = doc["runs"]
    assert len(runs) == 1
    results = runs[0]["results"]
    assert len(results) == 3

    # Rules deduplicati: RULE_A appare una volta sola
    rules = runs[0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    assert {r["id"] for r in rules} == {"RULE_A", "RULE_B"}

    # Livelli
    by_id = {r["partialFingerprints"]["findingId"]: r for r in results}
    assert by_id["id1111111111111a"]["level"] == "error"     # CRITICAL
    assert by_id["id2222222222222b"]["level"] == "warning"   # MEDIUM
    assert by_id["id3333333333333c"]["level"] == "note"      # LOW

    # Fingerprints
    assert by_id["id1111111111111a"]["partialFingerprints"]["findingId"] == "id1111111111111a"

    # Locations f1: url + endpoint + line
    loc_f1 = by_id["id1111111111111a"]["locations"][0]
    assert loc_f1["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com"
    assert loc_f1["physicalLocation"]["region"]["startLine"] == 10
    assert loc_f1["logicalLocations"][0]["fullyQualifiedName"] == "/api/v1"

    # Locations f2: file (no url)
    loc_f2 = by_id["id2222222222222b"]["locations"][0]
    assert loc_f2["physicalLocation"]["artifactLocation"]["uri"] == "assets/chunk.js"

    # Properties
    assert by_id["id1111111111111a"]["properties"]["tags"] == ["A01:2021"]
    assert by_id["id1111111111111a"]["properties"]["security-severity"] == "9.8"
    assert "security-severity" not in by_id["id2222222222222b"].get("properties", {})
