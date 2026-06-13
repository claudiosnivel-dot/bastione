"""Test del contratto base dei moduli e del REGISTRY (§9 del blueprint).

Test OFFLINE: nessuna rete, nessun I/O reale. I dummy module usano i tipi reali
(Fingerprint, RunContext, ModuleResult) costruiti col minimo necessario — stesso
pattern di test_gate.py (make_ctx / make_cfg).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel
from bastione.models import (
    Fingerprint,
    ModuleResult,
    RunContext,
    TargetConfig,
)
from bastione.modules.base import Module, REGISTRY, register


# ─── helper di costruzione ───────────────────────────────────────────────────

def _make_cfg(name: str = "t") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example",
        environment="staging",
        ownership="owned",
    )


def _make_ctx(cfg: TargetConfig | None = None) -> RunContext:
    cfg = cfg or _make_cfg()
    return RunContext(
        target_cfg=cfg,
        fingerprint=Fingerprint(target="t", resolved_urls=[]),
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=Path("."),
        ownership_verified=False,
    )


def _empty_result() -> ModuleResult:
    return ModuleResult(findings=[], posture_checks=[])


# ─── fixture: REGISTRY pulito per ogni test ──────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_registry():
    """Isola ogni test: svuota il REGISTRY prima e dopo l'esecuzione."""
    REGISTRY.clear()
    yield
    REGISTRY.clear()


# ─── (a) @register iscrive un'istanza nel REGISTRY sotto il name del modulo ──

def test_register_aggiunge_al_registry():
    """Un modulo decorato con @register deve essere presente in REGISTRY
    sotto il proprio `name` come *istanza* (§9)."""

    @register
    class PrimoModulo(Module):
        name = "primo"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    assert "primo" in REGISTRY
    assert isinstance(REGISTRY["primo"], PrimoModulo)


# ─── (b) should_run e run dispatchano sull'istanza ───────────────────────────

def test_should_run_dispatched_sull_istanza():
    """should_run sull'istanza registrata deve ritornare il valore definito."""

    @register
    class ShouldRunModulo(Module):
        name = "should_run_test"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True  # sempre attivo

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    istanza = REGISTRY["should_run_test"]
    fp = Fingerprint(target="t", resolved_urls=[])
    assert istanza.should_run(fp, _make_cfg()) is True


def test_run_dispatched_sull_istanza():
    """run sull'istanza registrata deve ritornare un ModuleResult valido."""

    @register
    class RunModulo(Module):
        name = "run_test"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True

        def run(self, ctx: RunContext) -> ModuleResult:
            return ModuleResult(findings=[], posture_checks=[])

    istanza = REGISTRY["run_test"]
    ctx = _make_ctx()
    result = istanza.run(ctx)
    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.posture_checks == []


# ─── (c) due moduli con name diversi coesistono nel REGISTRY ─────────────────

def test_due_moduli_distinti_coesistono():
    """Due moduli con nomi distinti devono essere entrambi presenti in REGISTRY
    e le loro istanze devono essere separate (§9 — registry multi-modulo)."""

    @register
    class Alpha(Module):
        name = "alpha"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    @register
    class Beta(Module):
        name = "beta"
        max_intrusion = IntrusionLevel.PROBE

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return False

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    assert "alpha" in REGISTRY
    assert "beta" in REGISTRY
    assert REGISTRY["alpha"] is not REGISTRY["beta"]
    assert isinstance(REGISTRY["alpha"], Alpha)
    assert isinstance(REGISTRY["beta"], Beta)


# ─── (d) ri-registrare lo stesso name sovrascrive (comportamento documentato) ─

def test_ri_registrare_stesso_name_sovrascrive():
    """Ri-registrare un name già presente sovrascrive silenziosamente l'istanza
    precedente. Comportamento scelto: ultima registrazione vince (utile per
    override nei test e per hot-reload futuro). Non è un errore."""

    @register
    class V1(Module):
        name = "duplicato"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return False

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    @register
    class V2(Module):
        name = "duplicato"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True  # distingue V2 da V1

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    assert len([k for k in REGISTRY if k == "duplicato"]) == 1
    assert isinstance(REGISTRY["duplicato"], V2)
    # Verifica che sia davvero V2 (should_run=True distingue le due versioni)
    fp = Fingerprint(target="t", resolved_urls=[])
    assert REGISTRY["duplicato"].should_run(fp, _make_cfg()) is True


# ─── (e) Module è astratta: non può essere istanziata direttamente ───────────

def test_module_e_astratta():
    """Module è ABC: tentare di istanziarla direttamente deve sollevare
    TypeError, garantendo che ogni modulo concreto implementi l'interfaccia."""
    with pytest.raises(TypeError):
        Module()  # type: ignore[abstract]


# ─── (f) @register ritorna la classe (uso come decoratore puro) ──────────────

def test_register_ritorna_la_classe():
    """register deve restituire la classe decorata invariata, così che si possa
    usare come `@register` senza perdere il riferimento alla classe stessa."""

    @register
    class Restituito(Module):
        name = "restituito"
        max_intrusion = IntrusionLevel.READ_ONLY

        def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
            return True

        def run(self, ctx: RunContext) -> ModuleResult:
            return _empty_result()

    assert Restituito is not None
    # La classe è ancora il tipo originale (non un wrapper)
    assert issubclass(Restituito, Module)
