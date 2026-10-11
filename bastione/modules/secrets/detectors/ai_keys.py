"""Detector chiavi AI (§4.4): OpenAI, Anthropic (HIGH), Google (LOW).

Liveness di identità (PROBE): OpenAI GET /v1/models (Bearer); Anthropic GET /v1/models
(x-api-key + anthropic-version); Google GET generativelanguage .../models (header
x-goog-api-key, mai in query string: l'URL finisce nei log di httpx) — se 200,
l'accesso alle API AI è confermato (arricchisce la description; promozione a HIGH rimandata, R6).
"""
from __future__ import annotations
import logging
import re
from bastione.enums import Severity
from bastione.models import Location, LivenessResult, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.ai_keys")
_TIMEOUT = 15.0

_OPENAI_RE = re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")
_ANTHROPIC_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")
_GOOGLE_RE = re.compile(r"AIza[0-9A-Za-z_-]{35}")


def _identity_get(url: str, headers: dict | None = None):
    try:
        import httpx
    except ImportError:
        return None
    try:
        return httpx.get(url, headers=headers or {}, timeout=_TIMEOUT, follow_redirects=False)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # P8: solo il TIPO dell'errore (il messaggio può riflettere header/URL).
        log.warning("ai_keys liveness fallita: %s", type(exc).__name__)
        return None


def _scan(rx, det_id, asset):
    return [RawSecret(detector_id=det_id, value=m, location=Location(file=asset.source))
            for m in rx.findall(asset.content)]


def _models_liveness(resp) -> LivenessResult | None:
    """Esito di un GET /v1/models di identità (OpenAI/Anthropic): 200 viva, 401
    revocata, altro / nessuna risposta → None (sconosciuto, §4.7). P8: niente chiave."""
    if resp is None:
        return None
    s = getattr(resp, "status_code", None)
    if s == 200:
        return LivenessResult(alive=True, mode="live", detail="GET /v1/models → 200: chiave VIVA.")
    if s == 401:
        return LivenessResult(alive=False, mode="revoked",
                              detail="GET /v1/models → 401: chiave revocata.")
    return None


@register_detector
class OpenAiDetector(Detector):
    detector_id = "SECRET_OPENAI"
    title = "Chiave API OpenAI esposta"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _scan(_OPENAI_RE, self.detector_id, asset)

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        return _models_liveness(_identity_get(
            "https://api.openai.com/v1/models", {"Authorization": f"Bearer {secret.value}"}))


@register_detector
class AnthropicDetector(Detector):
    detector_id = "SECRET_ANTHROPIC"
    title = "Chiave API Anthropic esposta"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _scan(_ANTHROPIC_RE, self.detector_id, asset)

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        return _models_liveness(_identity_get(
            "https://api.anthropic.com/v1/models",
            {"x-api-key": secret.value, "anthropic-version": "2023-06-01"}))


@register_detector
class GoogleApiKeyDetector(Detector):
    detector_id = "SECRET_GOOGLE_API_KEY"
    title = "Chiave API Google esposta"
    severity = Severity.LOW
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _scan(_GOOGLE_RE, self.detector_id, asset)

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        # P8: la chiave viaggia in header, MAI in query string (l'URL completo è
        # emesso nei log di httpx) né nel detail.
        resp = _identity_get("https://generativelanguage.googleapis.com/v1beta/models",
                             {"x-goog-api-key": secret.value})
        if resp is None:
            return None
        s = getattr(resp, "status_code", None)
        if s == 200:
            return LivenessResult(alive=True, mode="live",
                                  detail="GET /v1beta/models → 200: accesso alle API AI CONFERMATO.")
        if s in (400, 403):
            return LivenessResult(alive=False, mode="restricted",
                                  detail="GET /v1beta/models → 4xx: chiave ristretta/non "
                                         "valida per le API AI.")
        return None
