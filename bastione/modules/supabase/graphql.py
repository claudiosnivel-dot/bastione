"""Supabase GraphQL introspection probe (§4.3/§11.1) — PROBE.

Conferma che l'introspezione GraphQL (`/graphql/v1`) non sia esposta all'anon: una
query di introspezione minima; se il server risponde con `data.__schema`, la
superficie è enumerabile → SUPABASE_GRAPHQL_INTROSPECTION (LOW). Solo lettura (una
query di introspezione non muta stato) ma classificata PROBE (logica applicativa).

Gate-first (§4.0.7): self-gate `max_intrusion >= PROBE ∧ ownership_verified` più
`authorize(PROBE, ctx)` come backstop. Owned-only (§7): si contatta SOLO l'host di
`base`, i redirect non si seguono. P8: dalla risposta si legge solo la PRESENZA di
`__schema`; nessun nome di tipo/tabella, body o chiave entra in un Finding o in un log.

Onestà (R6): se il server non dà una risposta conclusiva (nessuna risposta, redirect,
timeout/rate-limit, 5xx) la verifica NON è stata eseguita → INFO esplicito
`SUPABASE_GRAPHQL_NOT_VERIFIABLE` e nessuna posture (mai un "passed" non guadagnato).
"""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.graphql")
_HTTP_TIMEOUT = 15.0
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


def _post(url: str, headers: dict, json: dict):
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: graphql probe non disponibile (§11.1)")
        return None
    try:
        return httpx.post(url, headers=headers, json=json, timeout=_HTTP_TIMEOUT,
                          follow_redirects=False)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # P8: si logga solo il TIPO dell'errore, mai il messaggio (h11 ripete il valore
        # dell'header illegale, che potrebbe contenere la chiave). `InvalidURL` NON è un
        # HTTPError e `ValueError` copre i valori d'header non codificabili: il confine
        # I/O degrada sempre a None, mai un crash (§4.7).
        log.warning("graphql POST %s fallita: %s", url, type(exc).__name__)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _is_conclusive(resp) -> bool:
    """True se il server ha dato una risposta che DICE qualcosa sull'introspezione.
    Nessuna risposta (rete/httpx), redirect (non seguiti), timeout/rate-limit (408/429)
    ed errori 5xx non sono una risposta: la verifica è non determinabile (R6)."""
    status = getattr(resp, "status_code", None)
    if not isinstance(status, int):
        return False
    return 200 <= status < 300 or (400 <= status < 500 and status not in (408, 429))


def _introspection_exposed(resp) -> bool:
    if resp is None or getattr(resp, "status_code", None) != 200:
        return False
    try:
        data = resp.json()
    except (ValueError, TypeError):
        return False
    # Esposta SOLO se `__schema` è un oggetto reale: `{"__schema": null}` non enumera nulla.
    return isinstance(data, dict) and isinstance(data.get("data"), dict) \
        and isinstance(data["data"].get("__schema"), dict)


def _not_verifiable_finding(loc: Location, target: str, resp) -> Finding:
    status = getattr(resp, "status_code", None)
    motivo = (f"risposta non conclusiva (HTTP {status})" if isinstance(status, int)
              else "nessuna risposta (rete/httpx)")
    return Finding(
        finding_id=_finding_id("supabase", "SUPABASE_GRAPHQL_NOT_VERIFIABLE", loc),
        module="supabase", rule_id="SUPABASE_GRAPHQL_NOT_VERIFIABLE",
        title="Introspezione GraphQL non verificabile", severity=Severity.INFO,
        confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"POST /graphql/v1 (introspection): {motivo}",
        description=(f"L'introspezione GraphQL non è stata verificata: {motivo}. Onestà "
                     "difensiva (R6): la verifica NON è stata eseguita, quindi l'assenza "
                     "di finding non significa che l'introspezione sia disabilitata."),
        remediation_ref=None, owasp=["A05:2021"], intrusion_used=IntrusionLevel.PROBE)


def run_graphql_checks(ctx: RunContext, base: str, headers: dict[str, str],
                       target: str) -> tuple[list[Finding], list[PostureCheck]]:
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("graphql probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    loc = Location(endpoint="/graphql/v1", url=cfg.supabase_url or base)
    resp = _post(f"{base.rstrip('/')}/graphql/v1", headers, _INTROSPECTION_QUERY)
    if not _is_conclusive(resp):
        findings.append(_not_verifiable_finding(loc, target, resp))
        return findings, posture
    exposed = _introspection_exposed(resp)
    if exposed:
        findings.append(Finding(
            finding_id=_finding_id("supabase", "SUPABASE_GRAPHQL_INTROSPECTION", loc),
            module="supabase", rule_id="SUPABASE_GRAPHQL_INTROSPECTION",
            title="Introspezione GraphQL esposta all'anon", severity=Severity.LOW,
            confidence=Confidence.FIRM, target=target, location=loc,
            evidence="POST /graphql/v1 (introspection) → data.__schema presente",
            description="L'introspezione GraphQL è abilitata per l'anon: l'intera "
                        "superficie (tipi, campi, relazioni) è enumerabile, allargando "
                        "la ricognizione di un attaccante. Disabilitala in produzione.",
            remediation_ref="SUPABASE_GRAPHQL_INTROSPECTION", owasp=["A05:2021"],
            intrusion_used=IntrusionLevel.PROBE,
            verified_by="POSTURE_GRAPHQL_INTROSPECTION"))
    posture.append(PostureCheck(
        check_id="POSTURE_GRAPHQL_INTROSPECTION",
        title="Introspezione GraphQL non esposta all'anon",
        passed=not exposed, severity_if_failed=Severity.LOW, target=target,
        detail=("Introspezione non raggiungibile dall'anon." if not exposed
                else "Introspezione GraphQL esposta (vedi finding)."),
        remediation_ref="SUPABASE_GRAPHQL_INTROSPECTION"))
    return findings, posture
