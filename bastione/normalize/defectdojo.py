"""Esportatore DefectDojo (§T4) — trasformazione PURA Finding[] → Generic Findings Import
+ push GATED resiliente.

Funzioni pubbliche:
    to_defectdojo(findings, *, target) -> dict
    write_defectdojo_export(path, payload) -> None
    push_to_defectdojo(payload) -> str

Confine I/O monkeypatchabile:
    _post_defectdojo(url, token, payload, engagement="") -> int | None
        (tutta la rete qui — upload multipart verso /api/v2/import-scan/)

Guardrail P8: il payload NON contiene segreti. I finding portano già evidence
redatta a monte; questa funzione NON include l'evidence nel payload (campo omesso).
Il token DefectDojo NON compare mai nei dati esportati.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from bastione.enums import Severity, Status
from bastione.models import Finding

log = logging.getLogger("bastione.normalize.defectdojo")

# Variabili d'ambiente per il push gated (§T4).
URL_ENV = "BASTIONE_DEFECTDOJO_URL"
TOKEN_ENV = "BASTIONE_DEFECTDOJO_TOKEN"
ENGAGEMENT_ENV = "BASTIONE_DEFECTDOJO_ENGAGEMENT"

# Mapping Bastione Severity → DefectDojo TITLE-CASE (§T4).
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.INFO:     "Info",
    Severity.LOW:      "Low",
    Severity.MEDIUM:   "Medium",
    Severity.HIGH:     "High",
    Severity.CRITICAL: "Critical",
}

# Status che indicano un finding ATTIVO (§T4).
_ACTIVE_STATUSES = {Status.NEW, Status.KNOWN}

# Timeout HTTP: corto — il push è best-effort (§19 pattern).
_HTTP_TIMEOUT = 15.0


def to_defectdojo(findings: list[Finding], *, target: str) -> dict:
    """Converte una lista di Finding nel formato DefectDojo "Generic Findings Import" (§T4).

    Parametri:
        findings: lista di Finding prodotti dai moduli di scansione.
                  L'evidence è già redatta a monte (P8); non viene inclusa nel payload.
        target:   URL o nome del target scansionato (metadato di run).

    Ritorna:
        dict con chiave "findings": lista di oggetti compatibili con
        DefectDojo Generic Findings Import v2.

    Campi per finding:
        title, description, severity (TITLE-CASE), date ("YYYY-MM-DD" o omesso),
        unique_id_from_tool (= finding_id §16), vuln_id_from_tool (= rule_id),
        file_path (= location.url or endpoint or file), line (= location.line),
        tags (owasp + [module, status]), active (status in NEW|KNOWN),
        false_p (sempre False), cvssv3_score (se cvss non-None).

    Guardrail P8: evidence MAI inclusa — è già redatta a monte.
    """
    dojo_findings = [_build_finding(f) for f in findings]

    log.debug(
        "DefectDojo payload prodotto: %d finding(s), target=%r",
        len(findings), target,
    )

    return {"findings": dojo_findings}


def write_defectdojo_export(path: str | Path, payload: dict) -> None:
    """Serializza il payload DefectDojo su disco come JSON (§T4).

    Parametri:
        path:    path del file di output (creato o sovrascritto).
        payload: dizionario prodotto da ``to_defectdojo``.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    log.debug("DefectDojo export scritto in: %s", p)


def _post_defectdojo(
    url: str, token: str, payload: dict, engagement: str = ""
) -> int | None:
    """Confine HTTP verso DefectDojo (§T4) — MONKEYPATCHABILE nei test.

    L'endpoint reale ``/api/v2/import-scan/`` è un endpoint di UPLOAD: NON accetta
    un body JSON inline, ma ``multipart/form-data`` dove il documento "Generic
    Findings Import" (la shape ``{"findings": [...]}`` prodotta da ``to_defectdojo``)
    va caricato come FILE (campo ``file``) e i metadati come campi form.

    POST ``<url>/api/v2/import-scan/`` con:
        - Authorization: Token <token>
        - files={"file": ("bastione.json", <payload-json>, "application/json")}
        - data={"scan_type": "Generic Findings Import",
                "engagement": <engagement> se valorizzato}

    Parametri:
        url:        URL base dell'istanza DefectDojo (eventuale trailing slash normalizzato).
        token:      API token (mai loggato — P8).
        payload:    documento Generic Findings Import (``{"findings": [...]}``).
        engagement: engagement id opzionale; incluso nei campi form solo se valorizzato.

    Ritorna:
        HTTP status code ricevuto, oppure None se httpx non è disponibile.

    NON solleva volontariamente: qualsiasi eccezione viene propagata al chiamante
    (push_to_defectdojo la cattura e la logga). La rete reale NON deve mai essere
    toccata nei test (monkeypatch questo simbolo oppure ``httpx.post``).

    P8: NON logga mai token né payload intero (potrebbe contenere path sensibili).
    """
    try:
        import httpx
    except ImportError:
        log.warning(
            "DEFECTDOJO: 'httpx' non disponibile — push non eseguito "
            "(degrado grazioso, §4.7). Installa httpx per abilitare il push.")
        return None

    endpoint = url.rstrip("/") + "/api/v2/import-scan/"
    headers = {"Authorization": f"Token {token}"}

    # Il documento Generic Findings Import va caricato come FILE multipart,
    # non come body JSON inline (contratto reale di import-scan).
    files = {
        "file": ("bastione.json", json.dumps(payload), "application/json"),
    }
    data: dict[str, str] = {"scan_type": "Generic Findings Import"}
    if engagement:
        data["engagement"] = engagement

    resp = httpx.post(
        endpoint, files=files, data=data, headers=headers, timeout=_HTTP_TIMEOUT
    )
    return resp.status_code


def push_to_defectdojo(payload: dict) -> str:
    """Push GATED + RESILIENTE verso DefectDojo (§T4, §19 pattern).

    Legge le variabili d'ambiente:
        - ``BASTIONE_DEFECTDOJO_URL``        : URL base dell'istanza DefectDojo (obbligatorio)
        - ``BASTIONE_DEFECTDOJO_TOKEN``      : API token (obbligatorio)
        - ``BASTIONE_DEFECTDOJO_ENGAGEMENT`` : engagement id opzionale; se valorizzato
          viene propagato a ``_post_defectdojo`` e incluso nei campi form del POST
          multipart verso import-scan (omesso se assente)

    Comportamento GATED:
        - Se URL o token assenti → ritorna "skipped" SENZA toccare la rete né
          chiamare ``_post_defectdojo``. Nessuna eccezione, nessun crash.
        - Se entrambi presenti → chiama ``_post_defectdojo``; qualsiasi eccezione
          viene catturata, loggata come warning (best-effort) e ritorna "error:<msg>".

    Ritorna:
        "pushed"      — POST completata (qualunque status HTTP ricevuto)
        "skipped"     — env assenti o incompleti
        "error:<msg>" — eccezione catturata durante il push

    P8: NON logga il token. NON propaga mai eccezioni (best-effort, §19).
    """
    url = os.environ.get(URL_ENV, "").strip()
    token = os.environ.get(TOKEN_ENV, "").strip()

    if not url or not token:
        log.debug(
            "DEFECTDOJO push: env %s/%s assenti o vuoti — skip (gate §T4).",
            URL_ENV, TOKEN_ENV,
        )
        return "skipped"

    # env opzionale: engagement id — propagato a _post_defectdojo e incluso
    # tra i campi form del POST multipart (import-scan lo richiede per associare
    # i finding a un engagement esistente). Se assente, l'upload viene comunque
    # tentato senza engagement (best-effort §19): la decisione di gating su
    # engagement è lasciata a chi configura l'istanza DefectDojo.
    engagement = os.environ.get(ENGAGEMENT_ENV, "").strip()
    if engagement:
        log.debug("DEFECTDOJO push: engagement=%r", engagement)

    try:
        status = _post_defectdojo(url, token, payload, engagement)
        log.debug("DEFECTDOJO push completato, HTTP status=%r", status)
        return "pushed"
    except Exception as exc:  # noqa: BLE001 — best-effort §19
        msg = str(exc)
        log.warning(
            "DEFECTDOJO push: eccezione catturata (%s: %s) — push non riuscito "
            "ma la run NON è compromessa (best-effort §19).",
            type(exc).__name__, msg,
        )
        return f"error:{msg}"


# ─── helpers interni ────────────────────────────────────────────────────────

def _build_finding(f: Finding) -> dict:
    """Costruisce un oggetto finding nel formato DefectDojo Generic Findings Import (§T4).

    Campi:
        title                : f.title
        description          : f.description
        severity             : mapping TITLE-CASE (§T4)
        date                 : f.last_seen.strftime("%Y-%m-%d") se non None (omesso altrimenti)
        unique_id_from_tool  : f.finding_id (dedup stabile §16)
        vuln_id_from_tool    : f.rule_id
        file_path            : location.url or location.endpoint or location.file
        line                 : f.location.line (omesso se None)
        tags                 : f.owasp + [f.module, f.status.value]
        active               : True se status in {NEW, KNOWN}
        false_p              : False (sempre)
        cvssv3_score         : f.cvss se non None (omesso altrimenti)

    Guardrail P8: evidence NON inclusa.
    """
    loc = f.location

    # file_path: preferisce url, poi endpoint, poi file (analoga a SARIF _build_location).
    if loc.url is not None:
        file_path = loc.url
    elif loc.endpoint is not None:
        file_path = loc.endpoint
    elif loc.file is not None:
        file_path = loc.file
    else:
        file_path = ""

    # tags: owasp già lista + module + status (come stringa leggibile).
    tags: list[str] = list(f.owasp) + [f.module, f.status.value]

    severity_str = _SEVERITY_MAP.get(f.severity, "Info")
    active = f.status in _ACTIVE_STATUSES

    entry: dict = {
        "title":               f.title,
        "description":         f.description,
        "severity":            severity_str,
        "unique_id_from_tool": f.finding_id,
        "vuln_id_from_tool":   f.rule_id,
        "file_path":           file_path,
        "tags":                tags,
        "active":              active,
        "false_p":             False,
    }

    # Campi opzionali: inclusi solo se valorizzati.
    if f.last_seen is not None:
        entry["date"] = f.last_seen.strftime("%Y-%m-%d")

    if f.location.line is not None:
        entry["line"] = f.location.line

    if f.cvss is not None:
        entry["cvssv3_score"] = f.cvss

    return entry
