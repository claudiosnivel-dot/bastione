"""Supabase RPC probe (§4.3/§11.1.4) — PROBE, GET-only (D5).

PostgREST esegue qualunque funzione chiamata in GET in transazione READ ONLY (una
scrittura → 405 / SQLSTATE 25006). Per le RPC note (bundle + TOML) verifichiamo che
quelle non dichiarate pubbliche non siano eseguibili dall'anon e non restituiscano
dati personali. Le funzioni a effetti esterni (denylist) NON sono mai invocate →
RPC_NOT_VERIFIABLE (§4.3). Mai una POST: la scrittura è fuori scope M5 (§4.0.3).

P8: mai i valori di riga nel Finding — solo nomi colonna, conteggio, esito. Owned-only
(§7): solo l'host di `base`; il nome RPC è URL-quotato come ultimo segmento del path.
"""
from __future__ import annotations

import hashlib
import logging
from urllib.parse import quote, urlencode

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.rpc")
_HTTP_TIMEOUT = 15.0

# Sottostringhe di nome che segnalano un effetto ESTERNO/di scrittura: la funzione
# NON va invocata, nemmeno in GET (la transazione read-only blocca la scrittura nel
# DB, ma non un side-effect verso l'esterno: email, pagamenti, webhook). §4.3/D5.
_RPC_SIDE_EFFECT_DENY: tuple[str, ...] = (
    "send", "email", "mail", "sms", "notify", "pay", "charge", "refund", "invoice",
    "webhook", "reset", "delete", "drop", "truncate", "insert", "update", "upsert",
    "grant", "revoke", "exec", "http", "request", "call", "invoke", "sync", "import",
    "export", "provision", "cron", "schedule", "enqueue", "publish", "broadcast",
)
_PERSONAL_HINTS = ("email", "nome", "name", "cognome", "telefono", "phone", "cf",
                   "fiscal", "codice_fiscale", "indirizzo", "address", "iban", "card",
                   "carta", "passport", "birth", "nascita", "ssn", "tax")


def _get(url: str, headers: dict):
    """GET read-only (invocazione RPC). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: rpc probe non disponibile (§11.1.4)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # P8: solo il TIPO dell'errore (il messaggio può ripetere un valore d'header,
        # cioè la chiave). `InvalidURL` non è un HTTPError: il confine degrada a None.
        log.warning("rpc GET %s fallita: %s", url, type(exc).__name__)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _is_denylisted(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in _RPC_SIDE_EFFECT_DENY)


def _looks_personal(cols: list[str]) -> bool:
    low = " ".join(cols).lower()
    return any(h in low for h in _PERSONAL_HINTS)


def _is_write_blocked(resp) -> bool:
    """La funzione ha TENTATO una scrittura (bloccata dalla tx read-only, D5):
    HTTP 405, o una risposta di ERRORE con SQLSTATE 25006 / 'read-only'. Il blocco
    si manifesta solo come errore: un 200 non è mai write-capable (anche se i suoi
    dati contengono quelle stringhe)."""
    status = getattr(resp, "status_code", None)
    if status == 405:
        return True
    if not isinstance(status, int) or status < 400:
        return False
    try:
        data = resp.json()
    except (ValueError, TypeError, AttributeError):
        return False
    if not isinstance(data, dict):
        return False
    blob = f"{data.get('code','')} {data.get('message','')}".lower()
    return "25006" in blob or "read-only" in blob or "read only" in blob


def _response_columns(resp) -> list[str] | None:
    """Nomi colonna della risposta 200 (per euristica interna, mai emessi). 200 non-write
    → lista di nomi ([] se scalare/vuoto); altrimenti None."""
    if getattr(resp, "status_code", None) != 200:
        return None
    try:
        data = resp.json()
    except (ValueError, TypeError, AttributeError):
        return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return list(data[0].keys())
    if isinstance(data, dict):
        return list(data.keys())
    return []


def run_rpc_checks(ctx: RunContext, base: str, headers: dict[str, str],
                   rpcs: list[str], target: str):
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
        return findings, posture
    try:
        authorize(IntrusionLevel.PROBE, ctx)
    except IntrusionDenied as exc:
        log.info("rpc probe negata dal gate (§7): %s", exc)
        return findings, posture

    cfg = ctx.target_cfg
    expect = {r.name: r for r in cfg.expect_rpcs}
    supa_url = cfg.supabase_url or base
    for name in rpcs:
        endpoint = f"/rest/v1/rpc/{name}"
        loc = Location(endpoint=endpoint, url=supa_url)
        if _is_denylisted(name):
            findings.append(_not_verifiable_finding(
                name, loc, target,
                "nome in denylist di funzioni a effetti esterni → esclusa prudenzialmente"))
            continue
        exp = expect.get(name)
        args = dict(exp.sample_args) if exp and exp.sample_args else {}
        # Lettura minima (D5): `limit` è un parametro riservato di PostgREST (non un
        # argomento della funzione) — basta la prima riga per leggere le colonne.
        query = {k: str(v) for k, v in args.items()}
        query.setdefault("limit", "1")
        url = f"{base}/rest/v1/rpc/{quote(name, safe='')}?{urlencode(query)}"
        resp = _get(url, headers)
        if resp is None:
            findings.append(_not_verifiable_finding(name, loc, target,
                                                    "nessuna risposta (rete/httpx)"))
            continue
        if _is_write_blocked(resp):
            findings.append(_write_capable_finding(name, loc, target))
            posture.append(_rpc_posture(name, target, False, Severity.HIGH,
                                        "anon può invocare una funzione write-capable (D5)"))
            continue
        status = getattr(resp, "status_code", None)
        if status in (401, 403):
            # rifiuto esplicito di autorizzazione → non invocabile dall'anon (gated)
            posture.append(_rpc_posture(name, target, True, Severity.MEDIUM,
                                        "anon non esegue la funzione → protetta"))
            continue
        cols = _response_columns(resp)
        if cols is None:
            # 400/404 (argomenti mancanti, funzione non trovata), 429, 5xx, body non
            # JSON: la funzione NON è stata davvero eseguita → non si afferma che sia
            # protetta (R6): INFO, nessun posture.
            findings.append(_not_verifiable_finding(
                name, loc, target, f"risposta non conclusiva (HTTP {status})"))
            continue
        # 200 → invocabile dall'anon
        if exp is not None and exp.anon_execute:
            posture.append(_rpc_posture(name, target, True, Severity.MEDIUM,
                                        "funzione pubblica ATTESA (§15)"))
        elif _looks_personal(cols):
            findings.append(_data_exposed_finding(name, cols, loc, target))
            posture.append(_rpc_posture(name, target, False, Severity.CRITICAL,
                                        "la funzione espone dati personali all'anon"))
        else:
            findings.append(_invocable_finding(name, loc, target, declared=exp is not None))
            posture.append(_rpc_posture(name, target, False, Severity.MEDIUM,
                                        "funzione invocabile dall'anon (non dichiarata pubblica)"))
    return findings, posture


def _not_verifiable_finding(name, loc, target, motivo) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_NOT_VERIFIABLE", loc),
        module="supabase", rule_id="RPC_NOT_VERIFIABLE",
        title=f"RPC '{name}' non verificabile", severity=Severity.INFO,
        confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"RPC {name}: {motivo}",
        description=(f"La funzione RPC '{name}' non è stata verificata: {motivo}. "
                     "Onestà difensiva (R6): la verifica NON è stata eseguita."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE)


def _data_exposed_finding(name, cols, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_DATA_EXPOSED", loc),
        module="supabase", rule_id="RPC_DATA_EXPOSED",
        title=f"RPC '{name}' espone dati personali all'anon",
        severity=Severity.CRITICAL, confidence=Confidence.FIRM, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → 200; colonne: {sorted(cols)} (valori NON inclusi, P8)",
        description=(f"La funzione '{name}', invocata in GET con la chiave pubblica, "
                     "restituisce righe con colonne riconducibili a dati personali. "
                     "L'anon legge dati che la RLS dovrebbe proteggere (§11.1.4). "
                     "(P8: solo i nomi colonna, mai i valori.)"),
        remediation_ref="RPC_DATA_EXPOSED", owasp=["A01:2021"],
        gdpr_relevant=True, intrusion_used=IntrusionLevel.PROBE,
        verified_by=f"POSTURE_RPC_GATED_{name}")


def _write_capable_finding(name, loc, target) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", "RPC_ANON_WRITE_CAPABLE", loc),
        module="supabase", rule_id="RPC_ANON_WRITE_CAPABLE",
        title=f"RPC '{name}' write-capable invocabile dall'anon",
        severity=Severity.HIGH, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → la tx read-only ha bloccato una scrittura (405/25006)",
        description=(f"La funzione '{name}' è invocabile dall'anon e TENTA una scrittura "
                     "(bloccata dalla transazione READ ONLY di PostgREST in GET, D5). "
                     "In un contesto non-GET potrebbe scrivere: va limitata all'anon. "
                     "TENTATIVE — nessuna scrittura è stata eseguita (§4.0.3)."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE, verified_by=f"POSTURE_RPC_GATED_{name}")


def _invocable_finding(name, loc, target, *, declared: bool) -> Finding:
    nudge = ("" if declared else
             f" Dichiara l'attesa con `[[expectations.rpc]] name=\"{name}\" "
             "anon_execute=true|false` per confermare o far emergere la violazione (R7).")
    return Finding(
        finding_id=_finding_id("supabase", "RPC_ANON_INVOCABLE", loc),
        module="supabase", rule_id="RPC_ANON_INVOCABLE",
        title=f"RPC '{name}' invocabile dall'anon",
        severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE, target=target, location=loc,
        evidence=f"GET /rest/v1/rpc/{name} → 200 (nessuna colonna personale)",
        description=(f"La funzione '{name}' è eseguibile dall'anon ma non è dichiarata "
                     f"pubblica.{nudge} TENTATIVE: potrebbe essere voluta."),
        remediation_ref="RPC_ANON_INVOCABLE", owasp=["A01:2021"],
        intrusion_used=IntrusionLevel.PROBE, verified_by=f"POSTURE_RPC_GATED_{name}")


def _rpc_posture(name, target, passed, sev, detail) -> PostureCheck:
    return PostureCheck(
        check_id=f"POSTURE_RPC_GATED_{name}",
        title=f"RPC '{name}' non eseguibile dall'anon (o pubblica per scelta)",
        passed=passed, severity_if_failed=sev, target=target,
        detail=detail, remediation_ref="RPC_ANON_INVOCABLE")
