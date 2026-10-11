"""Supabase storage probe (§4.3/§11.1.3) — PROBE.

Per i bucket NOTI (bundle + TOML) verifica che l'anon non ne possa ELENCARE gli
oggetti, salvo attesa dichiarata (R7). Il list è una POST a
`/storage/v1/object/list/{bucket}`: è una LETTURA (enumerazione) classificata PROBE
(R1), NON una scrittura (nessuno stato creato, §4.0.3).

Owned-only (§7): si contatta solo l'host di `base`. Il nome bucket è URL-quotato e
usato solo come ultimo segmento del path — non può spostare l'authority (Review #3).
P8: mai i NOMI degli oggetti nel Finding; l'euristica dati-personali li guarda solo
internamente per la severità.
"""
from __future__ import annotations

import hashlib
import logging
import re
from urllib.parse import quote

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.storage")
_HTTP_TIMEOUT = 15.0
_PERSONAL_HINTS = ("email", "nome", "name", "cognome", "telefono", "phone", "cf",
                   "fiscal", "codice_fiscale", "indirizzo", "address", "iban",
                   "card", "carta", "passport", "passaporto", "birth", "nascita",
                   "ssn", "tax", "contratto", "contract", "fattura", "invoice")


# Hint come parola intera (bordo = non-lettera, plurale in -s ammesso): 'tax' non
# scatta su 'syntax', 'name' non su 'filename', 'card' non su 'scorecard'.
_PERSONAL_RE = re.compile(
    r"(?<![a-z])(?:" + "|".join(map(re.escape, _PERSONAL_HINTS)) + r")s?(?![a-z])")


def _post(url: str, headers: dict, json: dict):
    """POST object/list (LETTURA/PROBE). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: storage probe non disponibile (§11.1.3)")
        return None
    try:
        return httpx.post(url, headers=headers, json=json, timeout=_HTTP_TIMEOUT,
                          follow_redirects=False)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # P8: solo il TIPO dell'errore (il messaggio può ripetere un valore d'header,
        # cioè la chiave). `InvalidURL` non è un HTTPError: il confine degrada a None.
        log.warning("storage POST %s fallita: %s", url, type(exc).__name__)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _looks_personal(names: list[str]) -> bool:
    return any(_PERSONAL_RE.search(n.lower()) for n in names)


def _list_outcome(resp) -> tuple[str, list[str] | str | None]:
    """Esito del list anonimo: ("listable", nomi) | ("protected", None) |
    ("unknown", motivo). I nomi servono solo all'euristica interna (mai emessi, P8).

    Solo un rifiuto esplicito (401/403) o un 200 senza oggetti visibili provano la
    protezione; nessuna risposta, 4xx diversi (es. bucket inesistente), 5xx o un body
    non interpretabile NON provano nulla → "unknown" (R6, mai un pass non guadagnato)."""
    if resp is None:
        return "unknown", "nessuna risposta (rete/httpx)"
    status = getattr(resp, "status_code", None)
    if status in (401, 403):
        return "protected", None
    if status != 200:
        return "unknown", f"risposta non conclusiva (HTTP {status})"
    try:
        data = resp.json()
    except (ValueError, TypeError, AttributeError):
        return "unknown", "HTTP 200 con body non JSON"
    if not isinstance(data, list):
        return "unknown", "HTTP 200 con body inatteso"
    names = [str(o.get("name", "")) for o in data if isinstance(o, dict)]
    return ("listable", names) if names else ("protected", None)


def run_storage_checks(ctx: RunContext, base: str, headers: dict[str, str],
                       buckets: list[str], target: str):
    """Probe PROBE dei bucket noti. Self-gate + backstop (§4.0.7). Owned-only."""
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("storage probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    expect = {b.name: b for b in cfg.expect_buckets}
    supa_url = cfg.supabase_url or base
    for bucket in buckets:
        endpoint = f"/storage/v1/object/list/{bucket}"
        url = f"{base}/storage/v1/object/list/{quote(bucket, safe='')}"
        outcome, data = _list_outcome(_post(url, headers, {"prefix": "", "limit": 100}))
        loc = Location(endpoint=endpoint, url=supa_url)
        if outcome == "unknown":
            findings.append(_not_verifiable_finding(bucket, str(data), loc, target))
        elif outcome == "listable":
            names = data
            exp = expect.get(bucket)
            if exp is not None and exp.anon_list:
                posture.append(_posture(bucket, target, True, Severity.HIGH,
                                        "bucket pubblico-elencabile ATTESO (§15)"))
            elif exp is None:
                findings.append(_undeclared_finding(bucket, len(names), loc, target))
            else:   # exp.anon_list is False → violazione
                sev = Severity.CRITICAL if _looks_personal(names) else Severity.HIGH
                findings.append(_listable_finding(bucket, len(names), loc, target, sev))
                posture.append(_posture(bucket, target, False, sev,
                                        "anon può elencare gli oggetti (violazione §15)"))
        else:
            posture.append(_posture(bucket, target, True, Severity.HIGH,
                                    "anon non elenca gli oggetti → bucket protetto"))
    return findings, posture


def _not_verifiable_finding(bucket, motivo, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "STORAGE_NOT_VERIFIABLE", loc),
        module="supabase", rule_id="STORAGE_NOT_VERIFIABLE",
        title=f"Bucket storage '{bucket}' non verificabile", severity=Severity.INFO,
        confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"POST /storage/v1/object/list/{bucket}: {motivo}",
        description=(f"Non è stato possibile stabilire se l'anon elenca il bucket "
                     f"'{bucket}': {motivo}. Onestà difensiva (R6): la verifica NON è "
                     "stata eseguita, l'assenza di finding non significa che il bucket "
                     "sia protetto."),
        remediation_ref=None, owasp=["A01:2021"], intrusion_used=IntrusionLevel.PROBE)


def _listable_finding(bucket, count, loc, target, sev) -> Finding:
    personal = sev is Severity.CRITICAL
    return Finding(
        finding_id=_finding_id("supabase", "STORAGE_PUBLIC_LISTABLE", loc),
        module="supabase", rule_id="STORAGE_PUBLIC_LISTABLE",
        title=f"Bucket storage '{bucket}' elencabile dall'anon"
              + (" (possibili dati personali)" if personal else ""),
        severity=sev, confidence=Confidence.FIRM, target=target, location=loc,
        evidence=f"{count} oggetti elencabili dall'anon (nomi NON inclusi, P8)",
        description=(
            f"POST /storage/v1/object/list/{bucket} con la chiave pubblica restituisce "
            f"{count} oggetti: l'anon può ENUMERARE il contenuto del bucket. La matrice "
            "§15 dichiara anon_list=false per questo bucket (violazione). "
            + ("I nomi degli oggetti suggeriscono dati personali → CRITICAL + GDPR."
               if personal else "Nessun nome riconducibile a dati personali → HIGH.")
            + " (P8: i nomi non sono inclusi nel finding.)"),
        remediation_ref="STORAGE_PUBLIC_LISTABLE", owasp=["A01:2021"],
        gdpr_relevant=personal, intrusion_used=IntrusionLevel.PROBE,
        verified_by=f"POSTURE_STORAGE_PRIVATE_{bucket}")


def _undeclared_finding(bucket, count, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "STORAGE_LISTABLE_UNDECLARED", loc),
        module="supabase", rule_id="STORAGE_LISTABLE_UNDECLARED",
        title=f"Bucket storage '{bucket}' elencabile — attesa non dichiarata",
        severity=Severity.INFO, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"{count} oggetti elencabili dall'anon (nomi NON inclusi, P8)",
        description=(
            f"L'anon può elencare gli oggetti del bucket '{bucket}', ma il TOML non "
            "dichiara se è voluto (R7). Dichiara l'attesa con "
            f"`[[expectations.bucket]] name=\"{bucket}\" anon_list=true|false`: se "
            "false, al prossimo scan diventa STORAGE_PUBLIC_LISTABLE; se true, "
            "confermerà una scelta esplicita."),
        remediation_ref="STORAGE_PUBLIC_LISTABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _posture(bucket, target, passed, sev, detail) -> PostureCheck:
    return PostureCheck(
        check_id=f"POSTURE_STORAGE_PRIVATE_{bucket}",
        title=f"Storage bucket '{bucket}' non elencabile dall'anon",
        passed=passed, severity_if_failed=sev, target=target,
        detail=detail, remediation_ref="STORAGE_PUBLIC_LISTABLE")
