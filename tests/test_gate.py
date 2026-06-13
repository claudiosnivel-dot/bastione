"""Test del gate di intrusione (§7, §7.1) — il cuore di sicurezza.

Il gate trasforma il vincolo legale/etico in codice: nessuna azione lo attraversa
senza i requisiti. Qui copriamo ogni ramo, inclusa la difesa in profondità (un
input non ammesso che arriva comunque al gate → IntrusionDenied, mai un
declassamento silenzioso). Per i casi che la validazione pydantic renderebbe
incostruibili (ownership non dichiarata) usiamo `model_construct` apposta, per
provare che il gate è un backstop reale e non si fida del solo schema.
"""

from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel
from bastione.gate import (
    IntrusionDenied,
    assert_preconditions,
    authorize,
    verify_ownership,
)
from bastione.models import Fingerprint, RunContext, TargetConfig


def make_cfg(*, environment="staging", ownership="owned", ownership_token=None,
             base_url="https://staging.example"):
    return TargetConfig(name="g", base_url=base_url, environment=environment,
                        ownership=ownership, ownership_token=ownership_token)


def make_ctx(*, max_intrusion, ownership_verified=False, cfg=None):
    cfg = cfg or make_cfg()
    return RunContext(
        target_cfg=cfg,
        fingerprint=Fingerprint(target="g", resolved_urls=[]),
        max_intrusion=max_intrusion,
        run_dir=Path("."),
        ownership_verified=ownership_verified,
    )


# ─── assert_preconditions (§7) — hard block in LOAD ───

def test_preconditions_block_production():
    with pytest.raises(IntrusionDenied, match="production"):
        assert_preconditions(make_cfg(environment="production"))


def test_preconditions_block_undeclared_ownership():
    # Difesa in profondità: bypassiamo lo schema (Literal) con model_construct
    # per simulare una ownership non valida che arriva comunque al gate.
    bad = TargetConfig.model_construct(
        name="g", base_url="https://x", environment="staging",
        ownership="unknown", ownership_token=None,
    )
    with pytest.raises(IntrusionDenied):
        assert_preconditions(bad)


def test_preconditions_pass_for_staging_owned():
    assert_preconditions(make_cfg(environment="staging", ownership="owned"))  # no raise


def test_preconditions_pass_for_authorized_written():
    assert_preconditions(make_cfg(ownership="authorized-written"))  # no raise


# ─── authorize (§7) — chiamato da ogni modulo prima di un'azione ───

def test_authorize_allows_readonly_within_ceiling():
    authorize(IntrusionLevel.READ_ONLY,
              make_ctx(max_intrusion=IntrusionLevel.READ_ONLY))  # no raise


def test_authorize_denies_action_above_ceiling():
    ctx = make_ctx(max_intrusion=IntrusionLevel.READ_ONLY)
    with pytest.raises(IntrusionDenied, match="tetto"):
        authorize(IntrusionLevel.PROBE, ctx)


def test_authorize_probe_requires_ownership_verified():
    ctx = make_ctx(max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)
    with pytest.raises(IntrusionDenied, match="ownership"):
        authorize(IntrusionLevel.PROBE, ctx)


def test_authorize_probe_allowed_with_ownership():
    ctx = make_ctx(max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    authorize(IntrusionLevel.PROBE, ctx)  # no raise


def test_authorize_mutating_allowed_on_staging_with_ownership():
    ctx = make_ctx(max_intrusion=IntrusionLevel.MUTATING, ownership_verified=True,
                   cfg=make_cfg(environment="staging"))
    authorize(IntrusionLevel.MUTATING, ctx)  # no raise


def test_authorize_mutating_denied_off_staging():
    # environment="production" è un Literal valido: il gate deve comunque negare
    # MUTATING (in produzione non ci si arriva, ma il gate non si fida).
    ctx = make_ctx(max_intrusion=IntrusionLevel.MUTATING, ownership_verified=True,
                   cfg=make_cfg(environment="production"))
    with pytest.raises(IntrusionDenied, match="staging"):
        authorize(IntrusionLevel.MUTATING, ctx)


def test_authorize_mutating_denied_without_ownership():
    ctx = make_ctx(max_intrusion=IntrusionLevel.MUTATING, ownership_verified=False)
    with pytest.raises(IntrusionDenied, match="ownership"):
        authorize(IntrusionLevel.MUTATING, ctx)


# ─── verify_ownership (§7.1) — mai chiamato in M0 read-only, ma deve esistere ───

def test_verify_ownership_false_without_token():
    # Nessuna rete: token assente → False immediato.
    assert verify_ownership(make_cfg(ownership_token=None)) is False


def test_verify_ownership_true_when_wellknown_matches(monkeypatch):
    monkeypatch.setattr("bastione.gate._check_wellknown", lambda cfg: True)
    monkeypatch.setattr("bastione.gate._check_dns_txt",
                        lambda cfg: pytest.fail("dns non deve essere interrogato"))
    assert verify_ownership(make_cfg(ownership_token="tok")) is True


def test_verify_ownership_true_when_dns_matches(monkeypatch):
    monkeypatch.setattr("bastione.gate._check_wellknown", lambda cfg: False)
    monkeypatch.setattr("bastione.gate._check_dns_txt", lambda cfg: True)
    assert verify_ownership(make_cfg(ownership_token="tok")) is True


def test_verify_ownership_false_when_both_fail(monkeypatch):
    monkeypatch.setattr("bastione.gate._check_wellknown", lambda cfg: False)
    monkeypatch.setattr("bastione.gate._check_dns_txt", lambda cfg: False)
    assert verify_ownership(make_cfg(ownership_token="tok")) is False
