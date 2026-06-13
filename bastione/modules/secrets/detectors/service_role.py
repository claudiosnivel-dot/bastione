"""Detector SECRET_SERVICE_ROLE — rileva JWT Supabase con claim role:service_role (§10).

Una service_role key esposta nel bundle JS o nelle pagine HTML è una fuga CRITICA:
bypassa ogni Row Level Security e concede accesso illimitato al database (§10/§8).

Il detector:
  1. Trova tutti i JWT (regex eyJ...) nel contenuto dell'asset.
  2. Decodifica localmente il payload base64url (senza importare funzioni private
     da recon — re-implementazione locale come da spec).
  3. Per ogni JWT con claim role=="service_role" produce un RawSecret.
  4. Ignora JWT con role=="anon" e qualunque altro ruolo (§8/§10: non confondere).

Scopo M0 (P5): solo rilevamento passivo. Il liveness check (validate_liveness)
è stub; M1+ potrà sovrascriverlo per verificare se la chiave è ancora attiva.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re

from bastione.enums import Severity
from bastione.models import Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.service_role")

# JWT a tre segmenti base64url che inizia con l'header tipico `{"alg":...}` → "eyJ".
# Stessa regex usata in recon/fingerprint.py — ripetuta qui per autonomia del modulo.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


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
