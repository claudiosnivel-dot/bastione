"""Gate di intrusione + ownership challenge (§7, §7.1) — il cuore di sicurezza.

Questo modulo trasforma il vincolo legale/etico in **codice eseguibile**: nessuna
azione attraversa il sistema senza passare di qui. Regola cardine (§6/§7):

    Il gate NON declassa, aborta.

Il declassamento "morbido" (mutating→probe con warning) è compito
dell'orchestratore in fase PLAN (§6). Se un'azione non ammessa arriva comunque
fin qui, l'unica risposta è `IntrusionDenied`: il gate è il backstop, non un
negoziatore. Difesa in profondità — non si fida nemmeno dello schema della config.

`verify_ownership` (§7.1) è richiesto solo per intrusione > READ_ONLY: in M0
(tutto read-only) **non** viene invocato. Gli accessi di rete (httpx, dnspython)
sono importati pigramente e degradano a `False` se la libreria manca o la verifica
fallisce — mai un crash (L06).
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from bastione.enums import IntrusionLevel
from bastione.models import RunContext, TargetConfig

log = logging.getLogger("bastione.gate")

WELLKNOWN_PATH = "/.well-known/bastione-ownership.txt"
DNS_PREFIX = "_bastione."


class IntrusionDenied(Exception):
    """Azione non ammessa dal gate. Backstop: non si negozia, si aborta."""


def assert_preconditions(cfg: TargetConfig) -> None:
    """Eseguito in LOAD (§6) — hard block. Produzione e target non dichiarati
    posseduti fanno abortire la run prima di qualsiasi azione."""
    if cfg.environment == "production":
        raise IntrusionDenied(
            "Bastione non opera su 'production'. Punta lo staging. "
            "(P1/P2 — produzione è sempre bloccata.)")
    if cfg.ownership not in ("owned", "authorized-written"):
        raise IntrusionDenied(
            "Manca dichiarazione di proprietà/autorizzazione. "
            "Imposta ownership='owned' o 'authorized-written'.")


def authorize(action: IntrusionLevel, ctx: RunContext) -> None:
    """Chiamato da OGNI modulo prima di un'azione. Tre cancelli, in ordine:
    tetto della run, ownership per PROBE/MUTATING, staging-only per MUTATING."""
    if action > ctx.max_intrusion:
        raise IntrusionDenied(
            f"Azione {action.name} > tetto run {ctx.max_intrusion.name}")
    if action >= IntrusionLevel.PROBE and not ctx.ownership_verified:
        raise IntrusionDenied(
            "PROBE/MUTATING richiede ownership challenge superato (§7.1)")
    if action >= IntrusionLevel.MUTATING and ctx.target_cfg.environment != "staging":
        raise IntrusionDenied(
            "MUTATING consentito solo su environment='staging'")


def verify_ownership(cfg: TargetConfig) -> bool:
    """Prova minima ma verificabile di proprietà (§7.1). Almeno uno tra file
    well-known e record DNS TXT deve contenere `ownership_token`. Senza token
    dichiarato → `False` (non verificato). Il recon read-only (M0) non richiede
    il challenge: leggere ciò che è pubblico non è intrusione."""
    if cfg.ownership_token is None:
        return False
    return _check_wellknown(cfg) or _check_dns_txt(cfg)


def _host(cfg: TargetConfig) -> str | None:
    return urlparse(cfg.base_url).hostname


def _check_wellknown(cfg: TargetConfig) -> bool:
    """GET https://<host>/.well-known/bastione-ownership.txt; True se la risposta
    contiene il token. Degrada a False se httpx manca o la richiesta fallisce."""
    host = _host(cfg)
    if not host or not cfg.ownership_token:
        return False
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: salto il check well-known (§7.1)")
        return False
    url = f"https://{host}{WELLKNOWN_PATH}"
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("well-known non raggiungibile (%s): %s", url, exc)
        return False
    return resp.status_code == 200 and cfg.ownership_token in resp.text


def _check_dns_txt(cfg: TargetConfig) -> bool:
    """Record TXT _bastione.<host> con valore = token. Degrada a False se
    dnspython manca o il lookup fallisce."""
    host = _host(cfg)
    if not host or not cfg.ownership_token:
        return False
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        log.warning("dnspython non installato: salto il check DNS TXT (§7.1)")
        return False
    name = f"{DNS_PREFIX}{host}"
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except dns.exception.DNSException as exc:   # NXDOMAIN, NoAnswer, Timeout…
        log.warning("DNS TXT %s non risolto: %s", name, exc)
        return False
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", "ignore")
        if cfg.ownership_token in txt:
            return True
    return False
