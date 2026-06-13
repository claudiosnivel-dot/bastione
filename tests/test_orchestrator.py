"""Test della macchina a stati shell (§6).

Verifica l'ordine delle 12 fasi, la registrazione completed/skipped (le
condizionali OWNERSHIP/REMEDIATE/NOTIFY saltate in una run read-only senza
finding), che il **gate sia cablato in LOAD** (produzione → abort, nessuna
run_dir scritta), la scrittura di `state.json` (§24) e la logica `--resume`.
Tutto offline: nessuna fase reale tocca la rete in M0 step 5.
"""

import json
from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel
from bastione.gate import IntrusionDenied
from bastione.orchestrator import Orchestrator
from bastione.state import RunState

STAGING = (
    'name = "g"\n'
    'base_url = "https://staging.example"\n'
    'environment = "staging"\n'
    'ownership = "owned"\n'
)
PRODUCTION = STAGING.replace('environment = "staging"', 'environment = "production"')
STAGING_NOTIFY = STAGING + '\n[notify]\nchannel = "telegram"\n'

MANDATORY = ["LOAD", "RECON", "PLAN", "SCAN", "NORMALIZE",
             "BASELINE", "POSTURE", "REPORT", "PERSIST"]


def _targets(tmp_path: Path, body: str, name: str = "g") -> Path:
    d = tmp_path / "targets"
    d.mkdir(exist_ok=True)
    (d / f"{name}.toml").write_text(body, encoding="utf-8")
    return d


def test_readonly_run_walks_all_phases(tmp_path: Path):
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=tmp_path / "runs")
    state = orch.run("g", max_intrusion=IntrusionLevel.READ_ONLY)
    for ph in MANDATORY:
        assert ph in state.phases_completed, f"{ph} non completata"
    # condizionali: nessun ownership (read-only), nessun finding → niente remediate/notify
    assert set(state.phases_skipped) == {"OWNERSHIP", "REMEDIATE", "NOTIFY"}
    assert state.finished_at is not None
    assert state.max_intrusion == "read-only"
    assert state.ownership_verified is False


def test_run_writes_state_json(tmp_path: Path):
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs)
    orch.run("g")
    state_files = list((runs / "g").glob("*/state.json"))
    assert len(state_files) == 1
    data = json.loads(state_files[0].read_text(encoding="utf-8"))
    assert data["schema"] == "bastione-state/1"
    assert data["target"] == "g"
    assert "PERSIST" in data["phases_completed"]


def test_production_aborts_in_load_and_writes_nothing(tmp_path: Path):
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, PRODUCTION), runs_root=runs)
    with pytest.raises(IntrusionDenied, match="production"):
        orch.run("g")
    # il gate blocca in LOAD prima di qualsiasi scrittura su disco
    assert not (runs / "g").exists()


def test_probe_run_aborts_without_ownership_token(tmp_path: Path):
    # max_intrusion=PROBE → OWNERSHIP gira; senza token verify_ownership=False → abort.
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=tmp_path / "runs")
    with pytest.raises(IntrusionDenied, match="[Oo]wnership"):
        orch.run("g", max_intrusion=IntrusionLevel.PROBE)


def test_resume_continues_from_partial_state(tmp_path: Path):
    runs = tmp_path / "runs"
    targets = _targets(tmp_path, STAGING)
    # run_dir preesistente con solo LOAD completata
    run_dir = runs / "g" / "20260613T000000_000000Z"
    run_dir.mkdir(parents=True)
    RunState(target="g", max_intrusion="read-only", phases_completed=["LOAD"]).save(run_dir)

    orch = Orchestrator(targets_dir=targets, runs_root=runs)
    state = orch.run("g", resume=True)

    assert "RECON" in state.phases_completed
    assert "PERSIST" in state.phases_completed
    # ha riusato la stessa run_dir, non ne ha creata una nuova
    assert len(list((runs / "g").glob("*/"))) == 1


def test_resume_with_findings_does_not_crash_on_conditional_phases(tmp_path: Path):
    # Regressione (§6/§24): al resume `counts` viene riletto da state.json; con
    # counts non nulli le precondizioni di REMEDIATE/NOTIFY scattano. Nello shell
    # devono essere no-op (come le altre fasi non implementate), NON un crash.
    runs = tmp_path / "runs"
    targets = _targets(tmp_path, STAGING_NOTIFY)
    run_dir = runs / "g" / "20260613T000000_000000Z"
    run_dir.mkdir(parents=True)
    st = RunState(target="g", max_intrusion="read-only", phases_completed=["LOAD"])
    st.counts["new"] = 1      # → precondizione REMEDIATE vera
    st.counts["drift"] = 1    # → con [notify].channel, precondizione NOTIFY vera
    st.save(run_dir)

    orch = Orchestrator(targets_dir=targets, runs_root=runs)
    state = orch.run("g", resume=True)   # NON deve sollevare

    assert "REMEDIATE" in state.phases_completed
    assert "NOTIFY" in state.phases_completed
    assert "PERSIST" in state.phases_completed


def test_resume_on_completed_run_is_noop(tmp_path: Path):
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs)
    first = orch.run("g")
    dirs_before = len(list((runs / "g").glob("*/")))
    again = orch.run("g", resume=True)
    assert len(list((runs / "g").glob("*/"))) == dirs_before   # nessuna nuova run
    assert again.started_at == first.started_at               # stessa run ripresa
