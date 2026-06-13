"""Conversione Finding[] → SARIF 2.1.0 (§23).

SARIF (Static Analysis Results Interchange Format) è il formato standard
per i risultati di analisi statiche, caricabile su GitHub code scanning.
Specifica: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Funzione pubblica:
    to_sarif(findings, target) -> dict

Il documento prodotto rispetta SARIF 2.1.0 e può essere caricato direttamente
su GitHub Advanced Security tramite l'azione `github/codeql-action/upload-sarif`.

Guardrail: l'evidence è GIA' redatta a monte (campo `evidence` del Finding);
questa funzione non aggiunge mai segreti né tenta di de-redarre (P8).
"""

from __future__ import annotations

import logging

import bastione
from bastione.enums import Severity
from bastione.models import Finding

log = logging.getLogger("bastione.normalize.sarif")

# Schema ufficiale SARIF 2.1.0 (§23).
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Mapping Severity → SARIF level (§23):
#   CRITICAL/HIGH → "error" (richiede attenzione immediata)
#   MEDIUM        → "warning" (da risolvere nel prossimo sprint)
#   LOW/INFO      → "note" (informativo)
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}


def to_sarif(findings: list[Finding], *, target: str) -> dict:
    """Converte una lista di Finding in un documento SARIF 2.1.0 (§23).

    Parametri:
        findings: lista di Finding prodotti dai moduli di scansione.
                  L'evidence è già redatta a monte (P8): non viene inclusa.
        target:   URL o nome del target scansionato (usato come metadato di run).

    Ritorna:
        dict compatibile con SARIF 2.1.0, direttamente serializzabile in JSON.

    Struttura prodotta (§23):
        {
          "version": "2.1.0",
          "$schema": "<schema ufficiale>",
          "runs": [{
            "tool": { "driver": { "name": "Bastione", "version": "...",
                                   "rules": [ reportingDescriptor per rule unica ] } },
            "results": [ result per ogni Finding ]
          }]
        }
    """
    rules = _build_rules(findings)
    results = [_build_result(f) for f in findings]

    log.debug(
        "SARIF prodotto: %d finding(s), %d rule(s) uniche, target=%r",
        len(findings), len(rules), target,
    )

    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bastione",
                        "version": bastione.__version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# ─── helpers interni ────────────────────────────────────────────────────────

def _build_rules(findings: list[Finding]) -> list[dict]:
    """Costruisce i reportingDescriptor UNICI per rule_id (§23).

    Due finding con lo stesso rule_id producono una sola rule. L'ordine di
    apparizione determina quale Finding "vince" come sorgente della descrizione
    (il primo incontrato, per riproducibilità).
    """
    seen: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {
                    "text": f.title,
                },
            }
    return list(seen.values())


def _build_result(f: Finding) -> dict:
    """Costruisce un SARIF result da un singolo Finding (§23).

    Campi prodotti:
    - ruleId: finding.rule_id
    - level: da severity (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note)
    - message.text: title + description
    - locations: physicalLocation (uri, region.startLine) + logicalLocations (endpoint)
    - partialFingerprints.findingId: finding.finding_id (tracciabilità stabile §16)
    - properties: tags (owasp) + security-severity (cvss se presente)

    Guardrail P8: evidence mai inclusa — è già redatta a monte.
    """
    level = _SEVERITY_TO_LEVEL.get(f.severity, "note")

    # message.text: titolo; se c'è anche la descrizione la aggiunge dopo un punto.
    if f.description and f.description != f.title:
        message_text = f"{f.title}. {f.description}"
    else:
        message_text = f.title

    result: dict = {
        "ruleId": f.rule_id,
        "level": level,
        "message": {"text": message_text},
        "locations": [_build_location(f)],
        "partialFingerprints": {
            "findingId": f.finding_id,
        },
    }

    # properties: opzionali, solo se c'è qualcosa da aggiungere.
    props: dict = {}
    if f.owasp:
        props["tags"] = list(f.owasp)
    if f.cvss is not None:
        # security-severity è una stringa (convenzione GitHub code scanning).
        props["security-severity"] = str(f.cvss)
    if props:
        result["properties"] = props

    return result


def _build_location(f: Finding) -> dict:
    """Costruisce la struttura locations[0] di un SARIF result (§23).

    - physicalLocation.artifactLocation.uri: preferisce location.url,
      poi location.file (il primo non-None).
    - physicalLocation.region.startLine: da location.line se valorizzata.
    - logicalLocations[].fullyQualifiedName: da location.endpoint se presente.
    """
    loc = f.location

    # URI: url ha precedenza su file (§23).
    uri = loc.url if loc.url is not None else loc.file

    physical: dict = {
        "artifactLocation": {
            "uri": uri if uri is not None else "",
        }
    }

    # region.startLine solo se line è valorizzata (§23).
    if loc.line is not None:
        physical["region"] = {"startLine": loc.line}

    location_entry: dict = {"physicalLocation": physical}

    # logicalLocations solo se endpoint è presente (§23).
    if loc.endpoint is not None:
        location_entry["logicalLocations"] = [
            {"fullyQualifiedName": loc.endpoint}
        ]
    else:
        location_entry["logicalLocations"] = []

    return location_entry
