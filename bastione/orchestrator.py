"""Macchina a stati delle 12 fasi (§6).

In M0 step 5 questo è uno **shell**: le fasi le cui dipendenze esistono già sono
cablate — `LOAD` (config + gate `assert_preconditions`), `OWNERSHIP` (§7.1,
condizionale), `PERSIST` (scrive `state.json`, §24) — mentre quelle i cui moduli
arrivano agli step 6–15 (`RECON`…`NOTIFY`) sono stub no-op. Le precondizioni e
l'ordine sono quelli di §6.

Regole motore rispettate fin da ora:
- Il **gate non declassa, aborta** (§6/§7): una run su `production` solleva
  `IntrusionDenied` in LOAD, prima di scrivere alcunché su disco.
- Le fasi condizionali non eseguite finiscono in `phases_skipped`, non omesse
  (§24) — così `--resume` non rientra in una fase mai dovuta.
- Lo stato viene salvato dopo ogni fase: un crash lascia una run ripartibile.

Il *declassamento morbido* dei moduli mutanti (§6, fase PLAN) arriverà con i
moduli reali (step 7+): qui PLAN è ancora uno stub.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from bastione.config import DEFAULT_TARGETS_DIR, load_target
from bastione.enums import IntrusionLevel, Phase
from bastione.gate import IntrusionDenied, assert_preconditions, verify_ownership
from bastione.models import TargetConfig
from bastione.state import RunState, intrusion_to_cli

log = logging.getLogger("bastione.orchestrator")

DEFAULT_RUNS_ROOT = Path("runs")

# Ordine deterministico delle 12 fasi (§6).
PHASE_ORDER: list[Phase] = [
    Phase.LOAD, Phase.OWNERSHIP, Phase.RECON, Phase.PLAN, Phase.SCAN,
    Phase.NORMALIZE, Phase.BASELINE, Phase.POSTURE, Phase.REPORT,
    Phase.REMEDIATE, Phase.NOTIFY, Phase.PERSIST,
]

# Fasi non ancora implementate: eseguite nello shell sono no-op loggati (i moduli
# reali arrivano agli step 6–15 per le fasi M0, a M1/M2 per REMEDIATE/NOTIFY).
# Le condizionali REMEDIATE/NOTIFY restano QUI di proposito: se la loro
# precondizione (§6) scatta — p.es. `counts` non nulli riletti al `--resume`
# (§24) — l'esecuzione dev'essere un no-op, non un crash. La decisione skip/esegui
# resta in `_should_run`; questo set garantisce solo che l'esecuzione non aborti.
_SHELL_STUB = {
    Phase.RECON, Phase.PLAN, Phase.SCAN, Phase.NORMALIZE,
    Phase.BASELINE, Phase.POSTURE, Phase.REPORT,
    Phase.REMEDIATE, Phase.NOTIFY,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Orchestrator:
    def __init__(
        self,
        *,
        targets_dir: Path = DEFAULT_TARGETS_DIR,
        runs_root: Path = DEFAULT_RUNS_ROOT,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.targets_dir = Path(targets_dir)
        self.runs_root = Path(runs_root)
        self._now = now
        # stato di lavoro per-run (ripopolato a ogni run())
        self._target: str = ""
        self._cfg: TargetConfig | None = None

    # ── driver ────────────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        *,
        max_intrusion: IntrusionLevel = IntrusionLevel.READ_ONLY,
        resume: bool = False,
    ) -> RunState:
        self._target = target
        self._cfg = None

        run_dir = self._resolve_run_dir(target, resume)
        state = self._init_or_load_state(target, run_dir, max_intrusion, resume)

        progressed = False
        try:
            for phase in PHASE_ORDER:
                seen = set(state.phases_completed) | set(state.phases_skipped)
                if phase.name in seen:
                    # già fatto in una run precedente (resume): se è LOAD,
                    # riacquisisci la config in memoria (idempotente).
                    if phase is Phase.LOAD and self._cfg is None:
                        self._load()
                    continue

                if not self._should_run(phase, state, max_intrusion):
                    state.phases_skipped.append(phase.name)
                    log.info("fase %s: saltata (precondizione non soddisfatta)", phase.name)
                else:
                    self._execute(phase, state)
                    state.phases_completed.append(phase.name)

                progressed = True
                state.save(run_dir)
            return state
        except Exception:
            # persisti il progresso per la ripartibilità, poi propaga.
            if progressed:
                state.save(run_dir)
            raise

    # ── precondizioni (§6) ────────────────────────────────────────────────

    def _should_run(self, phase: Phase, state: RunState, max_intrusion: IntrusionLevel) -> bool:
        if phase is Phase.OWNERSHIP:
            return max_intrusion > IntrusionLevel.READ_ONLY
        if phase is Phase.REMEDIATE:
            # ≥1 finding aperto (NEW/KNOWN). Nello shell non ci sono finding.
            return state.counts.get("new", 0) + state.counts.get("known", 0) > 0
        if phase is Phase.NOTIFY:
            # notifier configurato E (≥1 NEW ≥ soglia OPPURE ≥1 DRIFT).
            channel = self._cfg.notify_channel if self._cfg else "none"
            has_signal = state.counts.get("new", 0) > 0 or state.counts.get("drift", 0) > 0
            return channel != "none" and has_signal
        return True

    # ── azioni di fase ────────────────────────────────────────────────────

    def _execute(self, phase: Phase, state: RunState) -> None:
        if phase is Phase.LOAD:
            self._load()
        elif phase is Phase.OWNERSHIP:
            self._ownership(state)
        elif phase is Phase.PERSIST:
            self._persist(state)
        elif phase in _SHELL_STUB:
            log.debug("fase %s: shell stub (no-op) — implementata a uno step successivo", phase.name)
        else:  # difesa: ogni fase deve avere un trattamento esplicito
            raise RuntimeError(f"fase senza handler: {phase.name}")

    def _load(self) -> None:
        cfg = load_target(self._target, self.targets_dir)
        assert_preconditions(cfg)   # gate: hard block su produzione / ownership non dichiarata
        self._cfg = cfg

    def _ownership(self, state: RunState) -> None:
        # Gira solo se max_intrusion > READ_ONLY (vedi _should_run).
        assert self._cfg is not None
        if verify_ownership(self._cfg):
            state.ownership_verified = True
        else:
            raise IntrusionDenied(
                "Ownership challenge fallito (§7.1): pubblica il token su "
                "/.well-known/bastione-ownership.txt o nel record DNS TXT _bastione.<host>.")

    def _persist(self, state: RunState) -> None:
        state.finished_at = self._now()
        # L'aggiornamento baseline con --accept-baseline arriva con BASELINE (step 13).

    # ── run_dir / stato ───────────────────────────────────────────────────

    def _resolve_run_dir(self, target: str, resume: bool) -> Path:
        target_root = self.runs_root / target
        if resume and target_root.exists():
            existing = sorted(p for p in target_root.iterdir() if p.is_dir())
            if existing:
                return existing[-1]   # la più recente (i timestamp ordinano)
            log.warning("resume richiesto ma nessuna run precedente per %s: parto da zero", target)
        elif resume:
            log.warning("resume richiesto ma nessuna run precedente per %s: parto da zero", target)
        ts = self._now().strftime("%Y%m%dT%H%M%S_%fZ")
        return target_root / ts

    def _init_or_load_state(
        self, target: str, run_dir: Path, max_intrusion: IntrusionLevel, resume: bool
    ) -> RunState:
        state_path = run_dir / "state.json"
        if resume and state_path.exists():
            state = RunState.load(state_path)
            log.info("resume: stato ripreso da %s (fatte: %s)", state_path, state.phases_completed)
            return state
        return RunState(
            target=target,
            started_at=self._now(),
            max_intrusion=intrusion_to_cli(max_intrusion),
        )
