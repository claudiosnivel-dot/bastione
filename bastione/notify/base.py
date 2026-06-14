"""Contratto base dei Notifier, registry e dispatch resiliente (§19).

Stessa filosofia dei moduli (§9) e dei detector (§10): un contratto ABC, un
registry globale popolato da un decoratore, e un punto di import che scatena la
registrazione (vedi ``notify/__init__.py``).

Invariante CHIAVE (§19): la notifica è **best-effort**. Quando il dispatch viene
chiamato la run è GIÀ riuscita (REPORT/REMEDIATE sono passati); un fallimento di
NOTIFY — canale ignoto, env mancante, rete giù, notifier che solleva — va
**LOGGATO come warning** e NON deve MAI propagare. È l'orchestratore che si fida
di questo: la fase NOTIFY si completa comunque (vedi i test che assertano
"NOTIFY in phases_completed" senza alcun token Telegram reale).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from bastione.models import RunSummary, TargetConfig

log = logging.getLogger("bastione.notify")

# Registry globale: nome del canale → classe del notifier (§19).
#   NOTIFIERS = {"telegram": TelegramNotifier, "email": ..., "webhook": ...}
# In questo step è popolato col solo "telegram" (O01).
NOTIFIERS: dict[str, type["Notifier"]] = {}


class Notifier(ABC):
    """Contratto base di un notifier (§19).

    Attributo di classe obbligatorio:
      - ``channel`` : nome stabile del canale (es. "telegram"), la chiave con cui
                      il notifier si registra in ``NOTIFIERS`` e con cui
                      ``cfg.notify_channel`` lo seleziona.

    Metodo astratto:
      - ``send(summary)`` : invia l'alert costruito dal ``RunSummary``. Deve
                            essere resiliente per conto proprio (env mancanti →
                            no-op loggato), ma ANCHE se solleva il ``dispatch`` lo
                            assorbe: la run non deve mai crashare per una notifica.
    """

    channel: str

    @abstractmethod
    def send(self, summary: RunSummary) -> None:
        """Invia la notifica a partire dal ``RunSummary`` (§19).

        Il messaggio deve essere compatto (target, score, #NEW per severità,
        #DRIFT, link al report HTML) e NON contenere segreti grezzi (P8):
        l'evidence dei finding è già redatta a monte, e qui non si includono
        chiavi/token/evidenze.
        """


def register_notifier(cls: type[Notifier]) -> type[Notifier]:
    """Decoratore: registra ``cls`` in ``NOTIFIERS`` sotto ``cls.channel``.

    Ritorna la classe invariata (decoratore puro, come ``register``/
    ``register_detector``/``register_fix``). A differenza dei moduli registriamo
    la **classe**, non un'istanza: il notifier viene istanziato on-demand dal
    ``dispatch`` solo quando il canale è effettivamente selezionato (così un
    notifier con dipendenze opzionali non si costruisce se non serve).

    Un ``channel`` duplicato sovrascrive (ultima registrazione vince — utile per
    override nei test).
    """
    channel = getattr(cls, "channel", None)
    if not channel:
        raise ValueError(
            f"register_notifier: {cls.__qualname__} non dichiara l'attributo "
            "di classe 'channel' (§19).")
    if channel in NOTIFIERS:
        log.warning(
            "NOTIFIERS: il canale %r sovrascrive una registrazione precedente "
            "(§19 — ultima registrazione vince).", channel)
    NOTIFIERS[channel] = cls
    log.debug("Notifier registrato: %r → %r", channel, cls.__qualname__)
    return cls


def build_run_summary(
    *,
    target: str,
    posture_score: float,
    counts: dict,
    report_path: str,
) -> RunSummary:
    """Costruisce il ``RunSummary`` (§5) dai dati della run, input dei Notifier (§19).

    ``counts`` ha la shape di ``state.json`` (§24): ``drift_count`` è derivato da
    ``counts["drift"]`` (default 0 se assente). ``report_path`` è il path del
    report HTML (il formato single-file condivisibile, O02). Nessun segreto entra
    qui: il RunSummary porta solo conteggi/score/path, mai evidenze (P8).
    """
    return RunSummary(
        target=target,
        posture_score=posture_score,
        counts=counts,
        drift_count=int(counts.get("drift", 0) or 0),
        report_path=report_path,
    )


def dispatch(cfg: TargetConfig, summary: RunSummary) -> None:
    """Sceglie il notifier per ``cfg.notify_channel``, lo istanzia e invia (§19).

    RESILIENTE per costruzione (best-effort, invariante §19): QUALSIASI problema —
    canale "none"/ignoto, costruzione del notifier fallita, ``send`` che solleva —
    viene LOGGATO come warning e NON propaga. La fase NOTIFY dell'orchestratore si
    completa comunque: una notifica fallita non deve mai far crashare una run che
    è già riuscita.
    """
    channel = (cfg.notify_channel or "none").strip().lower()

    # "none" = nessuna notifica richiesta: silenzio totale, nemmeno un warning
    # (è la configurazione di default, non un'anomalia).
    if channel == "none":
        log.debug("NOTIFY: nessun canale configurato (notify_channel='none') — skip.")
        return

    notifier_cls = NOTIFIERS.get(channel)
    if notifier_cls is None:
        # Canale ignoto: lo segnaliamo ma NON crashiamo (best-effort §19).
        log.warning(
            "NOTIFY: canale %r sconosciuto (canali noti: %s) — notifica non inviata "
            "(best-effort §19).", channel, sorted(NOTIFIERS))
        return

    try:
        notifier = notifier_cls()
        notifier.send(summary)
    except Exception:  # noqa: BLE001 — best-effort §19: NESSUN errore deve propagare
        log.warning(
            "NOTIFY: il notifier %r ha sollevato durante l'invio — notifica "
            "non riuscita ma la run NON è compromessa (best-effort §19).",
            channel, exc_info=True)
