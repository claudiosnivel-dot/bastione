"""Test del modulo cloudflare (§12) — OFFLINE.

Verifica che CloudflareModule:
- should_run ritorni True solo se fp.cloudflare_fronted è True.
- run produca POSTURE_CLOUDFLARE_FRONTED con passed=True e severity_if_failed INFO
  (peso 1, §17/§26: il check non può fallire in M0 e non deve gonfiare lo score).
- Non produca Finding.
- ORIGIN_BYPASSABLE sia un TODO M1: il modulo non emette quel check in M0.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, ModuleResult, RunContext, TargetConfig
from bastione.modules.cloudflare.module import CloudflareModule


# ─── helper ──────────────────────────────────────────────────────────────────

def _make_cfg(name: str = "test-cf-target") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
    )


def _make_fp(cloudflare_fronted: bool, resolved_urls: list[str] | None = None) -> Fingerprint:
    return Fingerprint(
        target="test-cf-target",
        resolved_urls=resolved_urls if resolved_urls is not None else ["https://staging.example.com/"],
        cloudflare_fronted=cloudflare_fronted,
    )


def _make_ctx(cloudflare_fronted: bool = True) -> RunContext:
    return RunContext(
        target_cfg=_make_cfg(),
        fingerprint=_make_fp(cloudflare_fronted),
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=Path("."),
        ownership_verified=False,
    )


def _find_check(result: ModuleResult, check_id: str):
    for pc in result.posture_checks:
        if pc.check_id == check_id:
            return pc
    return None


MODULE = CloudflareModule()


# ─── attributi di classe ─────────────────────────────────────────────────────

def test_module_name():
    assert MODULE.name == "cloudflare"


def test_max_intrusion_read_only():
    assert MODULE.max_intrusion == IntrusionLevel.READ_ONLY


# ─── should_run ──────────────────────────────────────────────────────────────

def test_should_run_true_se_cloudflare_fronted():
    fp = _make_fp(cloudflare_fronted=True)
    assert MODULE.should_run(fp, _make_cfg()) is True


def test_should_run_false_se_non_cloudflare_fronted():
    fp = _make_fp(cloudflare_fronted=False)
    assert MODULE.should_run(fp, _make_cfg()) is False


# ─── POSTURE_CLOUDFLARE_FRONTED ───────────────────────────────────────────────

def test_fronted_check_presente():
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CLOUDFLARE_FRONTED")
    assert pc is not None


def test_fronted_check_passed_true():
    """Il check fronted è sempre passed=True quando il modulo gira (§12)."""
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CLOUDFLARE_FRONTED")
    assert pc.passed is True


def test_fronted_check_severity_info():
    """severity_if_failed=INFO (peso 1, §17): il check non può mai fallire in M0
    (gira solo se cloudflare_fronted=True), quindi un peso alto gonfierebbe il
    posture score (§26 'lo score non gonfia')."""
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CLOUDFLARE_FRONTED")
    assert pc.severity_if_failed == Severity.INFO


def test_fronted_check_target():
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_CLOUDFLARE_FRONTED")
    assert pc.target == "test-cf-target"


# ─── ORIGIN_BYPASSABLE: deve essere ASSENTE in M0 (TODO M1) ──────────────────

def test_origin_bypassable_assente_in_m0():
    """In M0 non si implementano euristiche DNS per bypassare l'origin (§12).
    Il check ORIGIN_BYPASSABLE NON deve essere emesso."""
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    pc = _find_check(result, "POSTURE_ORIGIN_BYPASSABLE")
    assert pc is None, "ORIGIN_BYPASSABLE non deve essere emesso in M0"


# ─── struttura risultato ─────────────────────────────────────────────────────

def test_run_non_produce_findings():
    """Il modulo cloudflare produce solo PostureCheck, mai Finding (§12)."""
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    assert isinstance(result, ModuleResult)
    assert result.findings == []


def test_run_produce_esattamente_un_posture_check():
    """In M0 deve esserci esattamente 1 PostureCheck (il fronted check)."""
    ctx = _make_ctx(cloudflare_fronted=True)
    result = MODULE.run(ctx)
    assert len(result.posture_checks) == 1
