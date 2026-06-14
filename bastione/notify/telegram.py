"""Notifier Telegram (§19, O01) — il canale di default, il più rapido da configurare.

Setup (bot + chat): si legge il token del bot e il chat_id da variabili
d'ambiente (NON dal TOML: sono segreti, vanno in ``.env`` / repository secrets,
§19/§20):

  - ``BASTIONE_TELEGRAM_BOT_TOKEN``  : il token del bot (da @BotFather);
  - ``BASTIONE_TELEGRAM_CHAT_ID``    : l'id della chat/canale destinatario.

Se mancano → log warning + no-op (niente crash, nessuna POST): la notifica è
best-effort (§19) e una configurazione incompleta non deve interrompere nulla.

Confine I/O monkeypatchabile: tutta la rete è isolata in ``_send_message`` (un
POST all'API Bot di Telegram via ``httpx``). I test lo sostituiscono per restare
OFFLINE; in produzione degrada con grazia se ``httpx`` manca o la POST fallisce.

P8 (LOCKED): nel messaggio NON entra alcun segreto. I finding sono già redatti a
monte e qui non includiamo evidenze grezze, né — ovviamente — il bot token.
"""

from __future__ import annotations

import logging
import os

from bastione.enums import Severity
from bastione.models import RunSummary
from bastione.notify.base import Notifier, register_notifier

log = logging.getLogger("bastione.notify.telegram")

# Nomi delle variabili d'ambiente (documentati nel docstring del modulo). Tenuti
# come costanti così i test li importano invece di hard-codare le stringhe.
BOT_TOKEN_ENV = "BASTIONE_TELEGRAM_BOT_TOKEN"
CHAT_ID_ENV = "BASTIONE_TELEGRAM_CHAT_ID"

# Timeout del POST verso l'API Telegram: corto: la notifica è best-effort e non
# deve trattenere la run.
_HTTP_TIMEOUT = 10.0

# Endpoint dell'API Bot. Il token va nel path: per questo _send_message NON deve
# mai loggare l'URL completo (conterrebbe il token, P8).
_API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"

# Ordine di severità dal più grave al meno grave per il breakdown #NEW (§19).
_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


@register_notifier
class TelegramNotifier(Notifier):
    """Invia un alert compatto su Telegram (§19, O01).

    ``send`` legge le credenziali dall'ambiente; se incomplete è un no-op loggato.
    Altrimenti formatta il messaggio (``_format_message``) e lo consegna al confine
    ``_send_message`` (l'unico punto che tocca la rete, monkeypatchato nei test).
    """

    channel = "telegram"

    def send(self, summary: RunSummary) -> None:
        token = os.environ.get(BOT_TOKEN_ENV, "").strip()
        chat_id = os.environ.get(CHAT_ID_ENV, "").strip()

        if not token or not chat_id:
            # Configurazione incompleta: best-effort (§19) → no-op loggato, niente
            # crash, niente POST. Citiamo i nomi delle env per guidare il setup.
            log.warning(
                "NOTIFY telegram: credenziali assenti (%s/%s non impostate) — "
                "notifica non inviata (no-op, §19). Imposta le due variabili "
                "d'ambiente per abilitare l'alert.",
                BOT_TOKEN_ENV, CHAT_ID_ENV)
            return

        text = _format_message(summary)
        # Il confine _send_message è risolto a livello di modulo (via globals)
        # così il monkeypatch dei test lo intercetta e nessuna rete viene toccata.
        _send_message(token, chat_id, text)


def _format_message(summary: RunSummary) -> str:
    """Compone il messaggio COMPATTO (§19): target, posture score, #NEW per
    severità, #DRIFT, link al report HTML.

    P8: solo conteggi/score/path — nessuna evidenza, nessun segreto. Il bot token
    NON compare (vive solo nell'URL dell'API, mai nel testo)."""
    counts = summary.counts or {}
    new_total = int(counts.get("new", 0) or 0)
    new_by_sev = counts.get("new_by_severity", {}) or {}

    # Breakdown dei NEW per severità: includiamo solo le severità con conteggio > 0
    # (messaggio compatto), dal più grave al meno grave.
    sev_bits = []
    for sev in _SEVERITY_ORDER:
        key = sev.name.lower()
        n = int(new_by_sev.get(key, 0) or 0)
        if n:
            sev_bits.append(f"{sev.name} {n}")
    sev_line = ", ".join(sev_bits) if sev_bits else "—"

    lines = [
        "🛡️ Bastione — alert su delta (§19)",
        f"target: {summary.target}",
        f"posture: {summary.posture_score:.1f}/100",
        f"NEW: {new_total} ({sev_line})",
        f"DRIFT: {int(summary.drift_count or 0)}",
        f"report: {summary.report_path}",
    ]
    return "\n".join(lines)


def _send_message(token: str, chat_id: str, text: str) -> None:
    """Confine I/O verso l'API Bot di Telegram (§19): POST ``sendMessage``.

    Unico punto del modulo che tocca la rete — i test lo monkeypatchano per restare
    OFFLINE. Degrado grazioso (§4.7): se ``httpx`` manca o la POST fallisce, logga
    un warning e ritorna; NON solleva (la notifica è best-effort, §19).

    P8: NON logga mai l'URL completo (conterrebbe il token nel path) né il token.
    """
    try:
        import httpx
    except ImportError:
        log.warning(
            "NOTIFY telegram: 'httpx' non disponibile — notifica non inviata "
            "(degrado grazioso, §4.7). Installa httpx per abilitare l'alert.")
        return

    url = _API_URL_TEMPLATE.format(token=token)
    try:
        resp = httpx.post(
            url,
            json={"chat_id": chat_id, "text": text},
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        # Rete giù / DNS / timeout: best-effort (§19) → warning, niente crash.
        # Logghiamo solo il tipo/errore, MAI l'URL (contiene il token, P8).
        log.warning(
            "NOTIFY telegram: POST sendMessage fallita (%s) — notifica non "
            "inviata (best-effort §19).", type(exc).__name__)
        return

    # Status non-2xx: l'alert non è stato accettato, ma non è un crash. Non logghiamo
    # il body (potrebbe riflettere il token nei messaggi d'errore di Telegram, P8).
    status = getattr(resp, "status_code", None)
    if status is not None and not (200 <= status < 300):
        log.warning(
            "NOTIFY telegram: l'API ha risposto con status %s — notifica forse "
            "non recapitata (best-effort §19).", status)
