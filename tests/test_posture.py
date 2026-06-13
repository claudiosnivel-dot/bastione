"""Test dell'aggregazione posture score (§17).

Verifica la funzione `posture_score` di bastione.posture.checks.
I pesi per severity_if_failed sono: INFO=1, LOW=2, MEDIUM=3, HIGH=5, CRITICAL=8.
score = 100 * somma(pesi dei passed) / somma(pesi di tutti), arrotondato a 1 decimale.
Lista vuota → 100.0 per convenzione (nessuna verifica fallita = postura perfetta).

Tutti i test sono OFFLINE: nessuna rete reale, solo costruzione di oggetti pydantic.
"""

from __future__ import annotations

import pytest

from bastione.enums import Severity
from bastione.models import PostureCheck
from bastione.posture.checks import posture_score


# ─── Helper per costruire PostureCheck in modo compatto ───────────────────────

def make_check(
    check_id: str,
    passed: bool,
    severity_if_failed: Severity,
    target: str = "https://example.com",
) -> PostureCheck:
    return PostureCheck(
        check_id=check_id,
        title=f"Check {check_id}",
        passed=passed,
        severity_if_failed=severity_if_failed,
        target=target,
        detail="Dettaglio di test",
    )


# ─── Lista vuota → 100.0 ──────────────────────────────────────────────────────

def test_lista_vuota_restituisce_100():
    """Lista vuota → 100.0: nessuna verifica fallita equivale a postura perfetta."""
    assert posture_score([]) == 100.0


# ─── Tutti passed → 100.0 ─────────────────────────────────────────────────────

def test_tutti_passed_restituisce_100():
    checks = [
        make_check("C1", passed=True, severity_if_failed=Severity.HIGH),
        make_check("C2", passed=True, severity_if_failed=Severity.CRITICAL),
        make_check("C3", passed=True, severity_if_failed=Severity.INFO),
    ]
    assert posture_score(checks) == 100.0


# ─── Tutti failed → 0.0 ───────────────────────────────────────────────────────

def test_tutti_failed_restituisce_0():
    checks = [
        make_check("C1", passed=False, severity_if_failed=Severity.MEDIUM),
        make_check("C2", passed=False, severity_if_failed=Severity.LOW),
        make_check("C3", passed=False, severity_if_failed=Severity.HIGH),
    ]
    assert posture_score(checks) == 0.0


# ─── Mix: verifica del calcolo pesato ─────────────────────────────────────────

def test_mix_pesato_corretto():
    """Calcolo manuale:
    - C1: passed=True,  severity_if_failed=HIGH     → peso 5 (conta in numeratore e denominatore)
    - C2: passed=False, severity_if_failed=CRITICAL → peso 8 (solo denominatore)
    - C3: passed=True,  severity_if_failed=INFO     → peso 1 (conta in numeratore e denominatore)

    somma passed   = 5 + 1 = 6
    somma totale   = 5 + 8 + 1 = 14
    score = 100 * 6 / 14 = 42.857... → arrotondato a 1 decimale = 42.9
    """
    checks = [
        make_check("C1", passed=True,  severity_if_failed=Severity.HIGH),
        make_check("C2", passed=False, severity_if_failed=Severity.CRITICAL),
        make_check("C3", passed=True,  severity_if_failed=Severity.INFO),
    ]
    assert posture_score(checks) == 42.9


def test_mix_due_severity_uguali():
    """Due check identici di tipo MEDIUM (peso 3): uno passed, uno failed.

    somma passed = 3
    somma totale = 6
    score = 100 * 3 / 6 = 50.0
    """
    checks = [
        make_check("C1", passed=True,  severity_if_failed=Severity.MEDIUM),
        make_check("C2", passed=False, severity_if_failed=Severity.MEDIUM),
    ]
    assert posture_score(checks) == 50.0


def test_pesi_corretti_per_ogni_severity():
    """Verifica che i pesi assegnati siano esattamente INFO=1, LOW=2, MEDIUM=3, HIGH=5, CRITICAL=8.

    Costruiamo: un check passed per ogni severity + un check failed LOW (peso 2).
    passed_weight = 1+2+3+5+8 = 19
    total_weight  = 19 + 2 = 21
    score = 100 * 19 / 21 = 90.476... → 90.5
    """
    checks = [
        make_check("INFO",     passed=True,  severity_if_failed=Severity.INFO),
        make_check("LOW",      passed=True,  severity_if_failed=Severity.LOW),
        make_check("MEDIUM",   passed=True,  severity_if_failed=Severity.MEDIUM),
        make_check("HIGH",     passed=True,  severity_if_failed=Severity.HIGH),
        make_check("CRITICAL", passed=True,  severity_if_failed=Severity.CRITICAL),
        make_check("FAILED",   passed=False, severity_if_failed=Severity.LOW),
    ]
    assert posture_score(checks) == 90.5


def test_arrotondamento_a_1_decimale():
    """Score che produce molte cifre decimali: verifica il round a 1 decimale.

    Tre check passed HIGH (peso 5 ciascuno) + due check failed MEDIUM (peso 3 ciascuno).
    passed_weight = 15
    total_weight  = 15 + 6 = 21
    score = 100 * 15 / 21 = 71.428... → 71.4
    """
    checks = [
        make_check("H1", passed=True,  severity_if_failed=Severity.HIGH),
        make_check("H2", passed=True,  severity_if_failed=Severity.HIGH),
        make_check("H3", passed=True,  severity_if_failed=Severity.HIGH),
        make_check("M1", passed=False, severity_if_failed=Severity.MEDIUM),
        make_check("M2", passed=False, severity_if_failed=Severity.MEDIUM),
    ]
    assert posture_score(checks) == 71.4
