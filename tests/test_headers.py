"""Test del modulo headers (§12) — OFFLINE.

Verifica che HeadersModule:
- should_run ritorni True solo se fp.resolved_urls è non vuoto.
- run produca un PostureCheck per ogni header di sicurezza: passed=True se
  l'header è presente (con il valore corretto dove richiesto), passed=False se
  assente, con la severity_if_failed giusta.
- Il check X-Frame-Options sia passed anche se è presente solo CSP frame-ancestors.
- Nessun crash se response_headers è vuoto.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, ModuleResult, RunContext, TargetConfig
from bastione.modules.headers.module import HeadersModule


# ─── helper ──────────────────────────────────────────────────────────────────

def _make_cfg(name: str = "test-target") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
    )


def _make_fp(resolved_urls: list[str], headers: dict[str, str]) -> Fingerprint:
    return Fingerprint(
        target="test-target",
        resolved_urls=resolved_urls,
        response_headers=headers,
    )


def _make_ctx(headers: dict[str, str], resolved_urls: list[str] | None = None) -> RunContext:
    if resolved_urls is None:
        resolved_urls = ["https://staging.example.com/"]
    return RunContext(
        target_cfg=_make_cfg(),
        fingerprint=_make_fp(resolved_urls, headers),
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=Path("."),
        ownership_verified=False,
    )


def _find_check(result: ModuleResult, check_id: str):
    """Restituisce il PostureCheck con check_id dato, o None."""
    for pc in result.posture_checks:
        if pc.check_id == check_id:
            return pc
    return None


MODULE = HeadersModule()


# ─── should_run ──────────────────────────────────────────────────────────────

def test_should_run_true_con_resolved_urls():
    fp = _make_fp(["https://staging.example.com/"], {})
    assert MODULE.should_run(fp, _make_cfg()) is True


def test_should_run_false_senza_resolved_urls():
    fp = _make_fp([], {})
    assert MODULE.should_run(fp, _make_cfg()) is False


# ─── attributi di classe ─────────────────────────────────────────────────────

def test_module_name():
    assert MODULE.name == "headers"


def test_max_intrusion_read_only():
    assert MODULE.max_intrusion == IntrusionLevel.READ_ONLY


# ─── POSTURE_HSTS ─────────────────────────────────────────────────────────────

def test_hsts_passed_quando_presente():
    ctx = _make_ctx({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_HSTS")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.HIGH


def test_hsts_failed_quando_assente():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_HSTS")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.HIGH


def test_hsts_check_case_insensitive():
    # L'header HTTP è case-insensitive per convenzione
    ctx = _make_ctx({"strict-transport-security": "max-age=31536000"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_HSTS")
    assert pc is not None
    assert pc.passed is True


# ─── POSTURE_CSP ─────────────────────────────────────────────────────────────

def test_csp_passed_quando_presente():
    ctx = _make_ctx({"Content-Security-Policy": "default-src 'self'"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CSP")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.HIGH


def test_csp_failed_quando_assente():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CSP")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.HIGH


# ─── POSTURE_XCTO (X-Content-Type-Options) ────────────────────────────────────

def test_xcto_passed_quando_nosniff():
    ctx = _make_ctx({"X-Content-Type-Options": "nosniff"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XCTO")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.MEDIUM


def test_xcto_failed_quando_assente():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XCTO")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.MEDIUM


def test_xcto_failed_se_valore_non_nosniff():
    # Il check richiede specificamente il valore "nosniff"
    ctx = _make_ctx({"X-Content-Type-Options": "invalid-value"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XCTO")
    assert pc is not None
    assert pc.passed is False


# ─── POSTURE_XFO (X-Frame-Options o CSP frame-ancestors) ─────────────────────

def test_xfo_passed_quando_xframe_options_presente():
    ctx = _make_ctx({"X-Frame-Options": "DENY"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XFO")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.MEDIUM


def test_xfo_passed_quando_csp_frame_ancestors():
    # CSP con frame-ancestors è equivalente a X-Frame-Options (§12)
    ctx = _make_ctx({"Content-Security-Policy": "frame-ancestors 'none'"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XFO")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.MEDIUM


def test_xfo_failed_quando_nessuno_dei_due():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_XFO")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.MEDIUM


# ─── POSTURE_REFERRER (Referrer-Policy) ──────────────────────────────────────

def test_referrer_passed_quando_presente():
    ctx = _make_ctx({"Referrer-Policy": "strict-origin-when-cross-origin"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_REFERRER")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.LOW


def test_referrer_failed_quando_assente():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_REFERRER")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.LOW


# ─── POSTURE_PERMISSIONS (Permissions-Policy) ────────────────────────────────

def test_permissions_passed_quando_presente():
    ctx = _make_ctx({"Permissions-Policy": "geolocation=(), microphone=()"})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_PERMISSIONS")
    assert pc is not None
    assert pc.passed is True
    assert pc.severity_if_failed == Severity.LOW


def test_permissions_failed_quando_assente():
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_PERMISSIONS")
    assert pc is not None
    assert pc.passed is False
    assert pc.severity_if_failed == Severity.LOW


# ─── struttura risultato ─────────────────────────────────────────────────────

def test_run_non_produce_findings():
    """Il modulo headers produce solo PostureCheck, mai Finding (§12)."""
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    assert isinstance(result, ModuleResult)
    assert result.findings == []


def test_run_produce_sei_posture_checks():
    """Devono essere esattamente 6 PostureCheck (uno per header/regola)."""
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    assert len(result.posture_checks) == 6


def test_target_nei_posture_checks():
    """Ogni PostureCheck deve avere target=ctx.target_cfg.name."""
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    for pc in result.posture_checks:
        assert pc.target == "test-target"


def test_tutti_gli_header_presenti_tutti_passed():
    """Se tutti gli header sono presenti, tutti i check devono essere passed."""
    ctx = _make_ctx({
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })
    result = MODULE.run(ctx)
    for pc in result.posture_checks:
        assert pc.passed is True, f"{pc.check_id} dovrebbe essere passed"


def test_headers_assenti_tutti_failed():
    """Con headers vuoti, tutti i check devono essere failed."""
    ctx = _make_ctx({})
    result = MODULE.run(ctx)
    for pc in result.posture_checks:
        assert pc.passed is False, f"{pc.check_id} dovrebbe essere failed"
