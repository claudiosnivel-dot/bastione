"""Detector cloud/repo (§4.4): AWS AKIA/ASIA, GitHub, npm, Upstash. HIGH.

GitHub/npm hanno liveness di identità (PROBE). AWS è flag-only (§10.2). Upstash è
ancorato all'URL REST (il token è esposto accanto); liveness rimandata (R6).

Onestà (R6/§26):
  - AWS: niente liveness — richiederebbe una richiesta firmata SigV4 (§10.2).
  - Upstash: detection ancorata all'URL REST `*.upstash.io`; la liveness serve la
    coppia URL+token, non un singolo match → rimandata (nessun probe).
  - GitHub/npm: liveness di SOLA identità (`GET /user`, `GET /-/whoami`), mai
    un'operazione, anche se il token la permetterebbe (LOCKED §10.2).

Gate (§7/§4.0.7): `validate_liveness` non vede il `RunContext`; la precondizione
`max_intrusion ≥ PROBE ∧ ownership_verified` + backstop `authorize(PROBE, ctx)` è
applicata da `SecretsModule._run_liveness` PRIMA di chiamarla (stesso schema di
`service_role.py`). Con tetto READ_ONLY o ownership non verificata: zero richieste.

P8 (§4.0.4): il token vive solo in `RawSecret.value` e nell'header della richiesta di
liveness; non compare mai nel `LivenessResult.detail` né nei log (l'eccezione di rete
viene loggata per tipo, mai per messaggio: h11/httpx possono citare il valore di un
header). Gli host contattati sono fissi (api.github.com, registry.npmjs.org): non
derivano mai dal contenuto scansionato.

Resilienza (§4.7): httpx assente o errore di rete → `None` (sconosciuto), mai un crash.
"""

from __future__ import annotations

import logging
import re

from bastione.enums import Severity
from bastione.models import LivenessResult, Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.cloud_repo")

_TIMEOUT = 15.0

_AWS_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
_GITHUB_RE = re.compile(r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}")
_NPM_RE = re.compile(r"npm_[A-Za-z0-9]{36}")
# Bordo destro: `…upstash.io.evil.com` (upstash.io come semplice etichetta di un host
# altrui) non è un host Upstash.
_UPSTASH_RE = re.compile(r"https://[a-z0-9-]+\.upstash\.io(?![a-z0-9.-])")

# Host FISSI della liveness di identità (mai derivati dal contenuto scansionato).
_GITHUB_USER_URL = "https://api.github.com/user"
_NPM_WHOAMI_URL = "https://registry.npmjs.org/-/whoami"


# ─── confine I/O della liveness (monkeypatchabile nei test, §10.2) ──────────

def _identity_get(url: str, headers: dict):
    """GET di identità verso `url` con `headers` (il token è nell'Authorization).

    Ritorna la response (con `.status_code`) o None se httpx manca o la richiesta
    fallisce — degrada con grazia (§4.7/L06). `follow_redirects=False` (LOCKED): un
    3xx non è un esito atteso e seguirlo inoltrerebbe il token a un altro host (P8/§7).
    """
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: liveness cloud/repo non disponibile (§10.2)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        # P8: solo il TIPO dell'errore, mai il messaggio (può citare il valore di un header).
        log.warning("cloud_repo liveness fallita: %s", type(exc).__name__)
        return None


# ─── scansione ──────────────────────────────────────────────────────────────

def _simple_scan(rx: re.Pattern[str], detector_id: str, asset: TextAsset) -> list[RawSecret]:
    """Un RawSecret per ogni occorrenza di `rx` nel contenuto dell'asset.

    Le regex di questo modulo non hanno gruppi di cattura: `findall` ritorna il match
    intero. Un contenuto senza match (o vuoto) dà una lista vuota — nessuna eccezione."""
    return [RawSecret(detector_id=detector_id, value=m, location=Location(file=asset.source))
            for m in rx.findall(asset.content)]


# ─── detector ───────────────────────────────────────────────────────────────

@register_detector
class AwsAkiaDetector(Detector):
    """Access key ID AWS, permanenti (AKIA) e temporanee STS (ASIA). Flag only:
    nessuna liveness (richiederebbe SigV4, §10.2) → `validate_liveness` è lo stub base."""

    detector_id = "SECRET_AWS_AKIA"
    title = "AWS access key esposta"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _simple_scan(_AWS_RE, self.detector_id, asset)


@register_detector
class GithubTokenDetector(Detector):
    """Token GitHub: classici (ghp_/gho_/ghu_/ghs_/ghr_) e fine-grained (github_pat_).
    Liveness di identità: `GET /user` → 200 vivo, 401 revocato, altro sconosciuto."""

    detector_id = "SECRET_GITHUB"
    title = "GitHub token esposto"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _simple_scan(_GITHUB_RE, self.detector_id, asset)

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        resp = _identity_get(_GITHUB_USER_URL,
                             {"Authorization": f"Bearer {secret.value}",
                              "Accept": "application/vnd.github+json"})
        if resp is None:
            return None
        s = getattr(resp, "status_code", None)
        if s == 200:
            return LivenessResult(alive=True, mode="live", detail="GET /user → 200: token VIVO.")
        if s == 401:
            return LivenessResult(alive=False, mode="revoked", detail="GET /user → 401: token revocato.")
        return None


@register_detector
class NpmTokenDetector(Detector):
    """Token npm (npm_ + 36 alfanumerici). Liveness di identità: `GET /-/whoami`
    → 200 vivo, 401 revocato, altro sconosciuto."""

    detector_id = "SECRET_NPM"
    title = "npm token esposto"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _simple_scan(_NPM_RE, self.detector_id, asset)

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        resp = _identity_get(_NPM_WHOAMI_URL,
                             {"Authorization": f"Bearer {secret.value}"})
        if resp is None:
            return None
        s = getattr(resp, "status_code", None)
        if s == 200:
            return LivenessResult(alive=True, mode="live", detail="whoami → 200: token VIVO.")
        if s == 401:
            return LivenessResult(alive=False, mode="revoked", detail="whoami → 401: token revocato.")
        return None


@register_detector
class UpstashDetector(Detector):
    """URL REST Upstash (`https://<id>.upstash.io`): il token REST è esposto accanto.
    Liveness rimandata (R6): servirebbe la coppia URL+token, non un singolo match →
    `validate_liveness` è lo stub base (nessun probe)."""

    detector_id = "SECRET_UPSTASH"
    title = "Upstash REST URL/token esposto"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return _simple_scan(_UPSTASH_RE, self.detector_id, asset)
