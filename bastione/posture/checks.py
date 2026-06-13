"""Aggregazione PostureCheck e calcolo del posture score pesato (§17).

Il posture score è un numero da 0 a 100 che rappresenta la "salute" del target
rispetto ai controlli di postura: 100 = tutti i check passati, 0 = tutti falliti.

Il peso di ogni check dipende da `severity_if_failed`, che indica quanto grave
sarebbe il fallimento di quel controllo:
  - INFO     → peso 1
  - LOW      → peso 2
  - MEDIUM   → peso 3
  - HIGH     → peso 5
  - CRITICAL → peso 8

Formula (§17):
  score = 100 * somma(pesi dei check passed) / somma(pesi di tutti i check)

Convenzione lista vuota:
  Se non ci sono check, lo score è 100.0 — nessuna verifica fallita equivale
  a postura perfetta. Questa scelta evita divisioni per zero e segue il principio
  del minimo impatto: l'assenza di dati non deve degradare il punteggio
  (il degradamento avviene solo quando un check esiste ed è failed).

Arrotondamento: 1 decimale (round(..., 1)) per compatibilità con i report HTML.
"""

from __future__ import annotations

import logging

from bastione.enums import Severity
from bastione.models import PostureCheck

log = logging.getLogger("bastione.posture.checks")

# Mappa severity_if_failed → peso nel calcolo del posture score (§17).
_PESI: dict[Severity, int] = {
    Severity.INFO:     1,
    Severity.LOW:      2,
    Severity.MEDIUM:   3,
    Severity.HIGH:     5,
    Severity.CRITICAL: 8,
}


def _peso(check: PostureCheck) -> int:
    """Ritorna il peso di un check in base alla sua severity_if_failed (§17).

    Se la severity non è mappata (caso improbabile con enum chiuso), usa peso 1
    e logga un warning per resilienza (P8 — un check anomalo non crasha il calcolo).
    """
    peso = _PESI.get(check.severity_if_failed)
    if peso is None:
        log.warning(
            "severity_if_failed sconosciuta %r per check %r — uso peso 1 (fallback).",
            check.severity_if_failed,
            check.check_id,
        )
        return 1
    return peso


def posture_score(posture_checks: list[PostureCheck]) -> float:
    """Calcola il posture score pesato nell'intervallo [0.0, 100.0] (§17).

    Parametri:
        posture_checks: lista di PostureCheck prodotti dai moduli di scansione.

    Ritorna:
        float arrotondato a 1 decimale.
        100.0 se la lista è vuota (convenzione: nessun check fallito = postura perfetta).
        100.0 se tutti i check sono passed.
        0.0   se tutti i check sono failed.

    Formula:
        score = 100 * somma(pesi dei passed) / somma(pesi di tutti)
    """
    if not posture_checks:
        # Convenzione: lista vuota → 100.0 (nessuna verifica fallita = postura perfetta, §17).
        return 100.0

    somma_totale = sum(_peso(c) for c in posture_checks)
    somma_passed = sum(_peso(c) for c in posture_checks if c.passed)

    score = 100.0 * somma_passed / somma_totale
    return round(score, 1)


# ─── Helper opzionali di aggregazione ─────────────────────────────────────────

def checks_passed(posture_checks: list[PostureCheck]) -> list[PostureCheck]:
    """Ritorna solo i PostureCheck che hanno passed=True."""
    return [c for c in posture_checks if c.passed]


def checks_failed(posture_checks: list[PostureCheck]) -> list[PostureCheck]:
    """Ritorna solo i PostureCheck che hanno passed=False."""
    return [c for c in posture_checks if not c.passed]
