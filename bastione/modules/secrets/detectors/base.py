"""Contratto base dei detector di segreti e registry DETECTORS (§10 del blueprint).

Ogni detector concreto:
  - estende `Detector` (ABC) e dichiara gli attributi di classe `detector_id`,
    `title`, `severity`, `gdpr_relevant`;
  - implementa `scan(asset) -> list[RawSecret]`: cerca segreti nel TextAsset;
  - può sovrascrivere `validate_liveness(secret) -> LivenessResult | None`
    per verificare se il segreto trovato è ancora valido (M1+);
  - si registra con @register_detector per essere scoperto da SecretsModule.

DETECTORS è una lista di istanze (stessa filosofia di REGISTRY per i moduli).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from bastione.enums import Severity
from bastione.models import LivenessResult, RawSecret, TextAsset

log = logging.getLogger("bastione.modules.secrets.detectors.base")

# Lista globale dei detector registrati (§10).
DETECTORS: list[Detector] = []


class Detector(ABC):
    """Contratto base di un detector di segreti (§10).

    Attributi di classe obbligatori:
      - `detector_id`    : identificatore univoco del detector (es. "SECRET_SERVICE_ROLE").
      - `title`          : titolo leggibile del finding prodotto.
      - `severity`       : gravità del segreto rilevato.
      - `gdpr_relevant`  : True se la fuga espone dati personali (default False).

    Metodi:
      - `scan(asset)`    : cerca segreti nel TextAsset, ritorna lista di RawSecret.
      - `validate_liveness(secret)` : stub (ritorna None); override in M1+ per
                           testare se il segreto è ancora attivo.
    """

    detector_id: str
    title: str
    severity: Severity
    gdpr_relevant: bool = False

    @abstractmethod
    def scan(self, asset: TextAsset) -> list[RawSecret]:
        """Cerca segreti nel TextAsset. Deve essere resiliente: non solleva eccezioni
        per contenuti malformati — li ignora silenziosamente (§4.7)."""

    def validate_liveness(self, secret: RawSecret) -> LivenessResult | None:
        """Verifica se il segreto trovato è ancora attivo (liveness check, M1+).
        Stub: ritorna None. Override nei detector che supportano il check."""
        return None


def register_detector(cls: type[Detector]) -> type[Detector]:
    """Decoratore: istanzia `cls` e la appende a DETECTORS.

    Ritorna la classe invariata (pattern decoratore puro), così il nome della
    classe rimane accessibile nel modulo dove è definita.

    Esempio::

        @register_detector
        class ServiceRoleDetector(Detector):
            detector_id = "SECRET_SERVICE_ROLE"
            ...
    """
    istanza = cls()
    DETECTORS.append(istanza)
    log.debug("Detector registrato: %r → %r", istanza.detector_id, cls.__qualname__)
    return cls
