"""Detector SECRET_SERVICE_ROLE — rileva JWT Supabase con claim role:service_role (§10).

Una service_role key esposta nel bundle JS o nelle pagine HTML è una fuga CRITICA:
bypassa ogni Row Level Security e concede accesso illimitato al database (§10/§8).

Il detector:
  1. Trova tutti i JWT (regex eyJ...) nel contenuto dell'asset.
  2. Decodifica localmente il payload base64url (senza importare funzioni private
     da recon — re-implementazione locale come da spec).
  3. Per ogni JWT con claim role=="service_role" produce un RawSecret.
  4. Ignora JWT con role=="anon" e qualunque altro ruolo (§8/§10: non confondere).

Scopo M0 (P5): rilevamento passivo (`scan`). In M1 (§10.2) il detector
implementa anche `validate_liveness` — uno Stadio 2 PROBE 🟡 (opt-in, gated)
che verifica *read-only* se la chiave è ancora attiva.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re

from bastione.enums import Severity
from bastione.models import LivenessResult, Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.service_role")

# JWT a tre segmenti base64url che inizia con l'header tipico `{"alg":...}` → "eyJ".
# Stessa regex usata in recon/fingerprint.py — ripetuta qui per autonomia del modulo.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Project ref Supabase: id di progetto alfanumerico minuscolo, una sola etichetta
# DNS (NESSUN `.` `/` `?` `#` `@`). Mirroring di recon/fingerprint.py:_SUPABASE_URL_RE
# (`https://[a-z0-9]+\.supabase\.co`): è l'invariante condiviso del codebase. Serve a
# impedire che un `ref` artefatto in un JWT scansionato (attacker-controllable) faccia
# scivolare l'authority dell'URL fuori da `*.supabase.co` (SSRF / owned-only §7).
_SUPABASE_REF_RE = re.compile(r"[a-z0-9]+")


def _decode_jwt_payload(token: str) -> dict | None:
    """Decodifica il payload (claims) di un JWT senza verifica della firma.

    Re-implementazione locale (spec §10: non importare funzioni private da recon).
    Ci interessa solo il claim `role` per distinguere anon/service_role.
    Ritorna None se il token è malformato o il payload non è un dict JSON.
    """
    try:
        body = token.split(".")[1]
        # Ripristino del padding base64url rimosso (RFC 4648 §5)
        body += "=" * (-len(body) % 4)
        claims = json.loads(base64.urlsafe_b64decode(body))
    except (IndexError, ValueError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


# ─── confine I/O della liveness (monkeypatchabile nei test, §10.2) ──────────

def _probe(url: str, token: str):
    """GET read-only privilegiata verso `url` con gli header service_role (§10.2).

    Header: `apikey: <token>` + `Authorization: Bearer <token>`, e `Range: 0-0`
    per limitare il payload al minimo (LOCKED: la liveness fa SOLO GET, mai
    operazioni mutanti, anche se la chiave lo permettesse).

    Ritorna la response (con `.status_code`) o None se httpx manca o la richiesta
    fallisce — degrada con grazia (§4.7/L06). Pattern identico a `_fetch` del
    modulo (bastione/modules/secrets/module.py)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: liveness service_role non disponibile (§10.2)")
        return None
    headers = {
        "apikey": token,
        "Authorization": f"Bearer {token}",
        "Range": "0-0",
    }
    try:
        # follow_redirects=False (LOCKED): un 3xx su /rest/v1/ NON è un esito di
        # liveness atteso (200/401/403 sono diretti). Seguire un redirect cross-host
        # inoltrerebbe l'header custom `apikey` col token a quell'host — httpx strippa
        # `Authorization` sui redirect non-same-origin ma NON gli header custom (P8/§7).
        return httpx.get(url, headers=headers, timeout=15.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("liveness GET %s fallita: %s", url, exc)
        return None


@register_detector
class ServiceRoleDetector(Detector):
    """Rileva JWT Supabase con claim role=='service_role' (§10).

    Severità CRITICAL: la service_role key bypassa RLS e concede accesso admin
    illimitato al database. Trovarla esposta in un bundle JS o in una pagina è
    una delle fughe più gravi per un'applicazione Supabase.

    gdpr_relevant=False: la chiave stessa non è un dato personale, ma la sua
    esposizione mette a rischio tutti i dati personali nel database.
    """

    detector_id = "SECRET_SERVICE_ROLE"
    title = "Supabase service_role key esposta"
    severity = Severity.CRITICAL
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        """Cerca JWT service_role nel contenuto dell'asset.

        Resiliente: ogni JWT malformato (payload non base64url, non JSON, claim
        assente) viene ignorato silenziosamente — non crasha gli altri (§4.7).
        """
        trovati: list[RawSecret] = []
        for token in _JWT_RE.findall(asset.content):
            claims = _decode_jwt_payload(token)
            if claims is None:
                # JWT malformato o payload non decodificabile: ignora
                log.debug("JWT malformato ignorato durante la scansione di %s", asset.source)
                continue
            if claims.get("role") != "service_role":
                # anon, admin, o qualunque altro ruolo: non è una fuga service_role
                continue
            trovati.append(RawSecret(
                detector_id=self.detector_id,
                value=token,
                location=Location(file=asset.source),
                entropy=None,
            ))
        return trovati

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        """Stadio 2 — Liveness PROBE 🟡 della service_role (§10.2).

        Il claim `ref` del JWT è il project ref Supabase: da lì deriva l'URL
        `https://<ref>.supabase.co/rest/v1/`. Esegue UNA GET read-only privilegiata
        (header service_role, `Range: 0-0`) e interpreta l'esito:

          - 200      → accesso privilegiato confermato → alive, mode="live".
          - 401/403  → chiave non più valida → alive=False, mode="revoked".
          - altro / errore di rete / httpx assente → None (sconosciuto: degrada
            con grazia, non si arricchisce il finding).

        Owned-only: contatta SOLO il backend Supabase del project ref derivato dal
        token trovato — nessun host di terze parti (§7). Ritorna None anche se il
        JWT è malformato o privo di `ref` (niente probe, niente crash). P8: il
        token in chiaro non compare mai nel `detail`."""
        claims = _decode_jwt_payload(secret.value)
        if claims is None:
            return None
        ref = claims.get("ref")
        if not isinstance(ref, str) or not ref:
            # Senza project ref non possiamo derivare l'URL: niente probe (§10.2).
            return None
        # Owned-only (§7): il payload del JWT è CONTENUTO scansionato e quindi
        # attacker-controllable (la firma non è verificata). Un `ref` come
        # "evil.com/" o "evil.com#" sposterebbe il netloc dell'URL fuori da
        # *.supabase.co (SSRF cieco + exfiltration del token negli header). Validiamo
        # il ref contro il formato reale del project ref Supabase (etichetta DNS
        # [a-z0-9]+, mirroring di recon/fingerprint.py:_SUPABASE_URL_RE): un ref non
        # conforme degrada a None (niente probe), preservando l'invariante owned-only.
        if not _SUPABASE_REF_RE.fullmatch(ref):
            log.info(
                "liveness service_role: ref non conforme al formato Supabase, "
                "niente probe (owned-only §7)")
            return None

        url = f"https://{ref}.supabase.co/rest/v1/"
        resp = _probe(url, secret.value)
        if resp is None:
            return None

        status = getattr(resp, "status_code", None)
        if status == 200:
            return LivenessResult(
                alive=True, mode="live",
                detail=f"GET privilegiata 200 su {url} (Range:0-0): accesso confermato.")
        if status in (401, 403):
            return LivenessResult(
                alive=False, mode="revoked",
                detail=f"GET {url} → {status}: chiave apparentemente revocata/ruotata.")
        # Esito non interpretabile → sconosciuto (degrada con grazia).
        return None
