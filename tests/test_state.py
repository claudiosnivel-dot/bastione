"""Test per lo stato runtime per-scan (§24) — `bastione-state/1`.

NB: questo è lo stato di UNA singola scansione (resumability, storico score),
da non confondere col `BASTIONE-SESSION-STATE.md` di progetto. Qui verifichiamo
la chiave JSON `schema`, il round-trip su disco e la logica di `next_phase`
(da cui dipende `--resume`): la prima fase né completata né saltata.
"""

import json
from pathlib import Path

from bastione.enums import Phase
from bastione.state import RunState


def test_json_uses_schema_key():
    s = RunState(target="g")
    data = json.loads(s.model_dump_json(by_alias=True))
    assert data["schema"] == "bastione-state/1"


def test_save_and_load_roundtrip(tmp_path: Path):
    s = RunState(target="g", max_intrusion="read-only",
                 phases_completed=["LOAD"], phases_skipped=["OWNERSHIP"])
    path = s.save(tmp_path)
    assert path.name == "state.json"
    loaded = RunState.load(path)
    assert loaded.target == "g"
    assert loaded.phases_completed == ["LOAD"]
    assert loaded.phases_skipped == ["OWNERSHIP"]
    assert loaded.schema_name == "bastione-state/1"


def test_load_accepts_schema_alias(tmp_path: Path):
    (tmp_path / "state.json").write_text(
        json.dumps({"schema": "bastione-state/1", "target": "g"}), encoding="utf-8")
    loaded = RunState.load(tmp_path / "state.json")
    assert loaded.schema_name == "bastione-state/1"
    assert loaded.target == "g"


def test_next_phase_returns_first_unseen():
    order = [Phase.LOAD, Phase.OWNERSHIP, Phase.RECON, Phase.PLAN]
    s = RunState(target="g", phases_completed=["LOAD"], phases_skipped=["OWNERSHIP"])
    assert s.next_phase(order) is Phase.RECON


def test_next_phase_none_when_all_seen():
    order = [Phase.LOAD, Phase.OWNERSHIP]
    s = RunState(target="g", phases_completed=["LOAD"], phases_skipped=["OWNERSHIP"])
    assert s.next_phase(order) is None


def test_counts_default_shape():
    # by_severity conta i finding (non i posture check) — qui tutto a zero.
    s = RunState(target="g")
    assert s.counts["new"] == 0
    assert s.counts["by_severity"]["critical"] == 0
    assert s.posture_score is None
