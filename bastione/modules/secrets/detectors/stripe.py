"""Detector SECRET_STRIPE — chiavi segrete/ristrette Stripe + webhook secret (§4.4, D4).

Severità per match (RawSecret.severity_override): live/ristretta CRITICAL, test HIGH,
webhook HIGH. Liveness (identità, PROBE): GET api.stripe.com/v1/account → 200 live,
403 viva-ma-limitata (restricted), 401 revocata. P8: il detail non contiene il token.
"""
from __future__ import annotations
import logging
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.stripe")
_STRIPE_TIMEOUT = 15.0

# (regex, severità) — ordine: le forme più specifiche/gravi prima.
_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL),
    (re.compile(r"rk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL),
    (re.compile(r"sk_test_[A-Za-z0-9]{16,}"), Severity.HIGH),
    (re.compile(r"rk_test_[A-Za-z0-9]{16,}"), Severity.HIGH),
    (re.compile(r"whsec_[A-Za-z0-9]{16,}"), Severity.HIGH),
]


def _identity_get(url: str, headers: dict):
    """GET di identità (PROBE). Ritorna resp o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_STRIPE_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("stripe liveness fallita: %s", exc)
        return None


@register_detector
class StripeDetector(Detector):
    detector_id = "SECRET_STRIPE"
    title = "Chiave Stripe segreta/ristretta esposta"
    severity = Severity.CRITICAL          # default; il match imposta severity_override
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        out: list[RawSecret] = []
        for rx, sev in _PATTERNS:
            for m in rx.findall(asset.content):
                out.append(RawSecret(detector_id=self.detector_id, value=m,
                                     location=Location(file=asset.source),
                                     severity_override=sev))
        return out

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        # I webhook secret (whsec_) non sono chiavi API: niente identity call.
        if secret.value.startswith("whsec_"):
            return None
        resp = _identity_get("https://api.stripe.com/v1/account",
                             {"Authorization": f"Bearer {secret.value}"})
        if resp is None:
            return None
        status = getattr(resp, "status_code", None)
        if status == 200:
            return LivenessResult(alive=True, mode="live",
                                  detail="GET /v1/account → 200: chiave VIVA.")
        if status == 403:
            return LivenessResult(alive=True, mode="restricted",
                                  detail="GET /v1/account → 403: chiave VIVA ma a permessi limitati.")
        if status == 401:
            return LivenessResult(alive=False, mode="revoked",
                                  detail="GET /v1/account → 401: chiave revocata/non valida.")
        return None
