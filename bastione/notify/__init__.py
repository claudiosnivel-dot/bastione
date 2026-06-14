"""Package NOTIFIER (§19) — alerting best-effort sul delta della run.

Chiude il loop del monitoring (§20): quando una scansione trova qualcosa di
**NUOVO** o **REGREDITO** (≥1 finding NEW ≥ soglia, oppure ≥1 DRIFT), avvisa.
Gira nello STESSO processo della scansione: niente daemon, niente DB (§20).

Importare questo package popola il registry ``NOTIFIERS`` via il decoratore
``@register_notifier`` (stesso pattern di ``register``/``register_detector``/
``register_fix`` già nel codice): l'import di ``.telegram`` registra il canale
"telegram" (O01, l'unico canale di questo step).

API pubblica (re-export da ``base``):
- ``Notifier``           : il contratto ABC (un metodo ``send``);
- ``NOTIFIERS``          : il registry canale → classe;
- ``register_notifier``  : il decoratore di registrazione;
- ``build_run_summary``  : costruisce il ``RunSummary`` (§5) dai dati della run;
- ``dispatch``           : sceglie il notifier per ``cfg.notify_channel`` e invia,
                           in modo RESILIENTE (best-effort: un errore di NOTIFY
                           NON deve mai far crashare una run già riuscita, §19).
"""

from __future__ import annotations

from bastione.notify.base import (
    NOTIFIERS,
    Notifier,
    build_run_summary,
    dispatch,
    register_notifier,
)

# L'import del modulo concreto registra il canale "telegram" (O01) via
# @register_notifier: senza, NOTIFIERS sarebbe vuoto e dispatch non troverebbe
# il canale. È il punto di registrazione, come per i moduli (§9) e i detector (§10).
from bastione.notify import telegram as _telegram  # noqa: F401  (popola NOTIFIERS)

__all__ = [
    "NOTIFIERS",
    "Notifier",
    "register_notifier",
    "build_run_summary",
    "dispatch",
]
