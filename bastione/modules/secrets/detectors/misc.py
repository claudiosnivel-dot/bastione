"""Detector misc (§4.4): Telegram bot (HIGH, liveness getMe), blocchi di chiave
privata (CRITICAL), stringhe ad alta entropia (LOW, sempre TENTATIVE).

Tre detector drop-in (§10, pattern `@register_detector`):

  - `SECRET_TELEGRAM_BOT` (HIGH): token di bot Telegram. Stadio 2 (PROBE, solo
    identità): `getMe` verso l'host FISSO `api.telegram.org`. La liveness è
    invocata dal solo `SecretsModule._run_liveness`, che fa il self-gate
    (`max_intrusion >= PROBE` ∧ `ownership_verified`) e il backstop
    `authorize(PROBE, ctx)` PRIMA di chiamare `validate_liveness`: il detector non
    riceve un `ctx`, quindi non può (e non deve) gatarsi da sé.
  - `SECRET_PRIVATE_KEY` (CRITICAL): header di un blocco di chiave privata. Nessuna
    liveness. Il `RawSecret.value` è la SOLA riga di header: il corpo della chiave
    non entra mai in un campo del Finding (P8).
  - `SECRET_HIGH_ENTROPY` (LOW): stringhe lunghe ad alta entropia di Shannon, fuori
    da cifre pure e da hash esadecimali. Nessuna liveness. È SEMPRE tentativa: il
    modulo `secrets` emette `Confidence.FIRM` per ogni detector, quindi
    l'incertezza è marcata nel titolo ("possibile segreto") e nel campo
    `RawSecret.entropy`, non nella confidence.

`scan()` è puro (nessun I/O). L'unico confine di rete è `_identity_get`,
monkeypatchabile nei test (nessun target live, §4.10). Resilienza (§4.7): httpx
assente o richiesta fallita → `None` (esito sconosciuto), mai un crash.

P8 (LOCKED): il token Telegram sta nel PATH dell'URL di `getMe`, quindi l'URL
completo e il messaggio delle eccezioni di rete non vengono MAI loggati (stesso
criterio di `bastione/notify/telegram.py`): si logga solo il tipo dell'errore.
"""

from __future__ import annotations

import logging
import math
import re

from bastione.enums import Severity
from bastione.models import LivenessResult, Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

log = logging.getLogger("bastione.modules.secrets.detectors.misc")

_TIMEOUT = 15.0

# Token bot Telegram: `<id numerico>:<segreto base64url>`. Nell'URL canonico
# dell'API Bot ("…/bot<ID>:<SEGRETO>/getMe") le cifre sono incollate a "bot": lì
# `\b` da solo non scatterebbe ('t' e '1' sono entrambi caratteri di parola) e la
# forma più comune di fuga resterebbe invisibile → ammettiamo anche il lookbehind
# "bot". Il match è sempre e solo il token (il prefisso "bot" non ne fa parte).
_TELEGRAM_RE = re.compile(r"(?:\b|(?<=bot))\d{6,12}:[A-Za-z0-9_-]{30,}")

# Header di un blocco di chiave privata PEM/OpenSSH/PGP. Gli header reali PGP e
# PKCS#8 cifrato sono "-----BEGIN PGP PRIVATE KEY BLOCK-----" e
# "-----BEGIN ENCRYPTED PRIVATE KEY-----": senza ` BLOCK` / `ENCRYPTED ` le due
# alternative non scatterebbero mai su una chiave reale.
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
)

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_ENTROPY_MIN = 4.0

# Lunghezze (in caratteri esadecimali) di md5/sha1/sha224/sha256/sha384/sha512:
# una stringa esadecimale di queste lunghezze è quasi certamente un hash.
_HASH_HEX_LENGTHS = (32, 40, 56, 64, 96, 128)


# ─── confine I/O della liveness (monkeypatchabile nei test, §10.2) ──────────

def _identity_get(url: str):
    """GET di sola identità verso `url` (Telegram `getMe`).

    Ritorna la response (con `.status_code`) o None se httpx manca o la richiesta
    fallisce — degrada con grazia (§4.7). `follow_redirects=False` (LOCKED): il
    token sta nel path dell'URL e un redirect cross-host lo inoltrerebbe a un
    terzo (P8/§7). P8: si logga SOLO il tipo dell'errore, mai l'URL né il messaggio
    dell'eccezione (potrebbe riflettere l'URL col token)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: liveness Telegram non disponibile (§10.2)")
        return None
    try:
        return httpx.get(url, timeout=_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        log.warning("telegram liveness fallita (%s): esito sconosciuto", type(exc).__name__)
        return None


def _shannon(s: str) -> float:
    """Entropia di Shannon (bit per carattere) della stringa `s`."""
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


# ─── Telegram bot ───────────────────────────────────────────────────────────

@register_detector
class TelegramBotDetector(Detector):
    """Token di bot Telegram esposto (HIGH): chi lo possiede controlla il bot."""

    detector_id = "SECRET_TELEGRAM_BOT"
    title = "Token bot Telegram esposto"
    severity = Severity.HIGH
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return [
            RawSecret(
                detector_id=self.detector_id,
                value=m,
                location=Location(file=asset.source),
            )
            for m in _TELEGRAM_RE.findall(asset.content)
        ]

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        """Stadio 2 — Liveness PROBE di sola identità (`getMe`, §10.2).

        Host FISSO `api.telegram.org` (nessun host derivato dal contenuto) e SOLO
        `getMe`: mai `sendMessage` o altre operazioni, anche se il token le
        permetterebbe. Esiti: 200 → vivo; 401/404 → revocato; altro / errore di
        rete / httpx assente → None (sconosciuto). P8: né il token né l'identità
        del bot compaiono nel `detail`."""
        resp = _identity_get(f"https://api.telegram.org/bot{secret.value}/getMe")
        if resp is None:
            return None
        s = getattr(resp, "status_code", None)
        if s == 200:
            return LivenessResult(alive=True, mode="live", detail="getMe → 200: bot VIVO.")
        if s in (401, 404):
            return LivenessResult(
                alive=False, mode="revoked", detail="getMe → 4xx: token revocato.")
        return None


# ─── Chiave privata ─────────────────────────────────────────────────────────

@register_detector
class PrivateKeyDetector(Detector):
    """Blocco di chiave privata esposto (CRITICAL). Nessuna liveness."""

    detector_id = "SECRET_PRIVATE_KEY"
    title = "Blocco di chiave privata esposto"
    severity = Severity.CRITICAL
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        # `value` è il solo header del blocco (P8): il corpo della chiave non viene
        # mai catturato.
        return [
            RawSecret(
                detector_id=self.detector_id,
                value=m,
                location=Location(file=asset.source),
            )
            for m in _PRIVATE_KEY_RE.findall(asset.content)
        ]


# ─── Alta entropia ──────────────────────────────────────────────────────────

@register_detector
class HighEntropyDetector(Detector):
    """Stringa ad alta entropia (LOW, sempre TENTATIVE). Nessuna liveness."""

    detector_id = "SECRET_HIGH_ENTROPY"
    title = "Stringa ad alta entropia (possibile segreto)"
    severity = Severity.LOW
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        out: list[RawSecret] = []
        for cand in _CANDIDATE_RE.findall(asset.content):
            if cand.isdigit():
                continue
            if _HEX_RE.match(cand) and len(cand) in _HASH_HEX_LENGTHS:
                continue  # probabile hash (md5/sha1/sha224/sha256/...), non un segreto
            ent = _shannon(cand)
            if ent >= _ENTROPY_MIN:
                out.append(
                    RawSecret(
                        detector_id=self.detector_id,
                        value=cand,
                        location=Location(file=asset.source),
                        entropy=round(ent, 2),
                    )
                )
        return out
