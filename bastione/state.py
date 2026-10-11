"""Stato runtime per-scan (§24) — schema `bastione-state/1`.

`runs/<target>/<timestamp>/state.json` abilita `--resume` e lo storico dello
score. **Attenzione al nome:** è lo stato *di una singola scansione*, NON il
`BASTIONE-SESSION-STATE.md` di progetto (`bastione-devstate/1`): schemi distinti
apposta. La fase completata viene salvata qui, così un re-run con `--resume`
riparte dalla prima fase non ancora vista (§6).

Le fasi condizionali (OWNERSHIP, REMEDIATE, NOTIFY) quando la precondizione non
scatta vengono registrate in `phases_skipped`, **non** omesse: altrimenti un
resume di una run completata rientrerebbe in una fase mai dovuta.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from bastione.enums import IntrusionLevel, Phase

SCHEMA = "bastione-state/1"
STATE_FILENAME = "state.json"

# Mapping IntrusionLevel → stringa CLI (§25: read-only|probe|mutating).
_INTRUSION_TO_CLI = {
    IntrusionLevel.READ_ONLY: "read-only",
    IntrusionLevel.PROBE: "probe",
    IntrusionLevel.MUTATING: "mutating",
}


def intrusion_to_cli(level: IntrusionLevel) -> str:
    return _INTRUSION_TO_CLI[level]


def empty_counts() -> dict:
    """Shape di `counts` (§24): by_severity conta i finding, non i posture check.

    `new_by_severity` è lo specchio NEW-only di `by_severity`: il gate CI (§22)
    fallisce SOLO sui finding NEW ≥ soglia (i KNOWN/ACCEPTED sono lo scenario
    normale in CI, con baseline committata), quindi serve il breakdown dei soli
    NEW separato dal totale degli emessi."""
    return {
        "new": 0, "known": 0, "fixed": 0, "drift": 0,
        # S16 (R6): in baseline ma NON ri-verificabili da questa run (tetto
        # d'intrusione più basso o modulo non eseguito) → né FIXED né visti.
        "not_reverified": 0,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "new_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }


class RunState(BaseModel):
    # populate_by_name: accetta sia la chiave alias "schema" sia il nome python.
    model_config = ConfigDict(populate_by_name=True)

    # 'schema' come nome di campo collide con BaseModel: usiamo alias.
    schema_name: str = Field(default=SCHEMA, alias="schema")
    target: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    max_intrusion: str = "read-only"
    ownership_verified: bool = False
    phases_completed: list[str] = Field(default_factory=list)
    phases_skipped: list[str] = Field(default_factory=list)
    posture_score: float | None = None
    counts: dict = Field(default_factory=empty_counts)
    tools_available: dict = Field(default_factory=dict)

    def next_phase(self, order: list[Phase]) -> Phase | None:
        """Prima fase dell'ordine che non compare né in completed né in skipped
        (§24, logica di `--resume`). `None` se la run è completa."""
        seen = set(self.phases_completed) | set(self.phases_skipped)
        for phase in order:
            if phase.name not in seen:
                return phase
        return None

    def save(self, run_dir: Path) -> Path:
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / STATE_FILENAME
        path.write_text(self.model_dump_json(by_alias=True, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "RunState":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)
