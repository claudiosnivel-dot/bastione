"""Contratto base dei moduli di scansione e registry globale (§9 del blueprint).

Ogni modulo concreto:
  - estende `Module` (ABC) e dichiara gli attributi di classe `name` e
    `max_intrusion`;
  - implementa `should_run` (decide se il modulo è applicabile al target) e
    `run` (esegue la scansione e ritorna un `ModuleResult`);
  - si registra con il decoratore `@register` per essere scoperto
    dall'orchestratore in fase PLAN (§6).

Il REGISTRY è un dizionario module-name → istanza. Il caricamento effettivo
dei moduli concreti (import dei sotto-moduli) è responsabilità dell'orchestratore:
questo file non importa nulla di concreto per evitare import ciclici (P5).

Comportamento di `register` in caso di name duplicato: sovrascrive silenziosamente
— ultima registrazione vince. È utile per override nei test e per hot-reload futuro.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from bastione.enums import IntrusionLevel
from bastione.models import Fingerprint, ModuleResult, RunContext, TargetConfig

log = logging.getLogger("bastione.modules.base")

# REGISTRY globale: name → istanza del modulo (§9).
REGISTRY: dict[str, "Module"] = {}


class Module(ABC):
    """Contratto base di ogni modulo di scansione (§9).

    Attributi di classe obbligatori:
      - `name`           : identificatore univoco del modulo (es. "supabase").
      - `max_intrusion`  : livello di intrusione massimo che il modulo può
                           richiedere; il gate (§7) nega tutto ciò che supera
                           il tetto della run.

    Metodi astratti:
      - `should_run`     : ritorna True se il modulo deve girare su questo
                           target (basandosi sul Fingerprint e la TargetConfig).
      - `run`            : esegue la scansione e ritorna un ModuleResult.
    """

    name: str                       # attributo di classe — identificatore univoco
    max_intrusion: IntrusionLevel   # la più alta intrusione che il modulo può richiedere

    @abstractmethod
    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Decide se il modulo deve girare su questo target.

        Deve essere una valutazione leggera (senza I/O): si basa sul Fingerprint
        già disponibile e sulla TargetConfig. L'orchestratore chiama questo metodo
        in fase PLAN (§6) prima di schedulare la run.
        """

    @abstractmethod
    def run(self, ctx: RunContext) -> ModuleResult:
        """Esegue la scansione sul target descritto da `ctx`.

        Ogni azione che supera READ_ONLY deve chiamare `gate.authorize` prima di
        procedere (§7). Deve essere resiliente: eccezioni interne vengono catturate
        dall'orchestratore (P8 — un modulo che fallisce non crasha gli altri).
        """


def register(cls: type[Module]) -> type[Module]:
    """Decoratore: istanzia `cls` e la registra in REGISTRY sotto `cls.name`.

    Ritorna la classe invariata (pattern decoratore puro), così il nome della
    classe rimane accessibile nel modulo dove è definita.

    Esempio d'uso::

        @register
        class SupabaseModule(Module):
            name = "supabase"
            max_intrusion = IntrusionLevel.READ_ONLY
            ...

    Se `cls.name` è già presente in REGISTRY, la precedente istanza viene
    sovrascritta silenziosamente (ultima registrazione vince — comportamento
    documentato, utile per override nei test).
    """
    istanza = cls()
    if istanza.name in REGISTRY:
        log.warning(
            "REGISTRY: il modulo %r sovrascrive una registrazione precedente "
            "(§9 — ultima registrazione vince).", istanza.name
        )
    REGISTRY[istanza.name] = istanza
    log.debug("Modulo registrato: %r → %r", istanza.name, cls.__qualname__)
    return cls
