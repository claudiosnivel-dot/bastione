"""Test della macchina a stati a 12 fasi (§6) — ora con le fasi RECON→PERSIST
cablate ai componenti reali (recon §8, moduli §9–§12, baseline §16, posture §17,
SARIF/report §23). Tutto OFFLINE: il recon e i moduli sono monkeypatchati, nessuna
fase tocca la rete (M0 read-only).

Copre:
- l'ordine delle 12 fasi e la registrazione completed/skipped (le condizionali
  OWNERSHIP/REMEDIATE/NOTIFY saltate in una run read-only senza finding);
- il **gate cablato in LOAD** (produzione → abort, nessuna run_dir scritta);
- la scrittura di `state.json` (§24) e la logica `--resume`;
- una run completa che produce `bastione.sarif` + `report.md` + `state.json`
  con phases_completed RECON..PERSIST;
- la **resilienza** (§6): un modulo che solleva un'eccezione produce un
  meta-finding MODULE_ERROR senza interrompere gli altri moduli.
"""

import json
from pathlib import Path

import pytest

import bastione.orchestrator as orch_mod
from bastione.enums import IntrusionLevel, Severity
from bastione.gate import IntrusionDenied
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    PostureCheck,
)
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


# ─── stub OFFLINE di recon + moduli (nessuna rete) ──────────────────────────

def _fake_fingerprint_factory(**fp_kwargs):
    """Crea un fake `fingerprint(target, run_dir=None)` che NON tocca la rete:
    ritorna un Fingerprint sintetico e (come l'originale) scrive fingerprint.json
    nella run_dir, così il `--resume` può ricaricarlo."""
    def _fake(target, run_dir=None):
        fp = Fingerprint(
            target=target,
            resolved_urls=fp_kwargs.get("resolved_urls", ["https://staging.example/"]),
            response_headers=fp_kwargs.get("response_headers", {}),
            is_supabase=fp_kwargs.get("is_supabase", False),
            supabase_url=fp_kwargs.get("supabase_url"),
            anon_key=fp_kwargs.get("anon_key"),
            cloudflare_fronted=fp_kwargs.get("cloudflare_fronted", False),
        )
        if run_dir is not None:
            run_dir = Path(run_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "fingerprint.json").write_text(
                fp.model_dump_json(indent=2), encoding="utf-8")
        return fp
    return _fake


def _patch_offline(monkeypatch, *, fingerprint=None, plan_modules=None):
    """Rende l'orchestratore interamente OFFLINE:
    - sostituisce `bastione.orchestrator.fingerprint` con un fake locale;
    - sostituisce la selezione del piano con `plan_modules` (default: nessun modulo)
      così nessun modulo reale parta e tocchi la rete.
    """
    monkeypatch.setattr(
        orch_mod, "fingerprint",
        fingerprint or _fake_fingerprint_factory())

    modules = list(plan_modules or [])

    def _fake_plan(self):
        self._plan = list(modules)

    monkeypatch.setattr(Orchestrator, "_plan_phase", _fake_plan, raising=True)


class _StubModule:
    """Modulo finto per i test: ritorna findings/posture predefiniti, oppure
    solleva un'eccezione (per testare la resilienza/MODULE_ERROR)."""

    max_intrusion = IntrusionLevel.READ_ONLY

    def __init__(self, name, *, findings=None, posture=None, boom=False):
        self.name = name
        self._findings = findings or []
        self._posture = posture or []
        self._boom = boom

    def should_run(self, fp, cfg):
        return True

    def run(self, ctx):
        if self._boom:
            raise RuntimeError(f"boom da {self.name}")
        return ModuleResult(findings=list(self._findings),
                            posture_checks=list(self._posture))


def _finding(*, module="m", rule_id="R", target="g", endpoint="/x"):
    return Finding(
        finding_id="",
        module=module,
        rule_id=rule_id,
        title=f"{rule_id} su {endpoint}",
        severity=Severity.HIGH,
        confidence="firm",
        target=target,
        location=Location(endpoint=endpoint, url="https://staging.example"),
        evidence="red...act",
        description="finding di test",
    )


# ─── test esistenti (resi OFFLINE) ──────────────────────────────────────────

def test_readonly_run_walks_all_phases(tmp_path: Path, monkeypatch):
    _patch_offline(monkeypatch)
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=tmp_path / "runs",
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g", max_intrusion=IntrusionLevel.READ_ONLY)
    for ph in MANDATORY:
        assert ph in state.phases_completed, f"{ph} non completata"
    # condizionali: nessun ownership (read-only), nessun finding → niente remediate/notify
    assert set(state.phases_skipped) == {"OWNERSHIP", "REMEDIATE", "NOTIFY"}
    assert state.finished_at is not None
    assert state.max_intrusion == "read-only"
    assert state.ownership_verified is False


def test_run_writes_state_json(tmp_path: Path, monkeypatch):
    _patch_offline(monkeypatch)
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    orch.run("g")
    state_files = list((runs / "g").glob("*/state.json"))
    assert len(state_files) == 1
    data = json.loads(state_files[0].read_text(encoding="utf-8"))
    assert data["schema"] == "bastione-state/1"
    assert data["target"] == "g"
    assert "PERSIST" in data["phases_completed"]


def test_production_aborts_in_load_and_writes_nothing(tmp_path: Path, monkeypatch):
    _patch_offline(monkeypatch)
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, PRODUCTION), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    with pytest.raises(IntrusionDenied, match="production"):
        orch.run("g")
    # il gate blocca in LOAD prima di qualsiasi scrittura su disco
    assert not (runs / "g").exists()


def test_probe_run_aborts_without_ownership_token(tmp_path: Path, monkeypatch):
    # max_intrusion=PROBE → OWNERSHIP gira; senza token verify_ownership=False → abort.
    _patch_offline(monkeypatch)
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=tmp_path / "runs",
                        baselines_root=tmp_path / "baselines")
    with pytest.raises(IntrusionDenied, match="[Oo]wnership"):
        orch.run("g", max_intrusion=IntrusionLevel.PROBE)


def test_resume_continues_from_partial_state(tmp_path: Path, monkeypatch):
    _patch_offline(monkeypatch)
    runs = tmp_path / "runs"
    targets = _targets(tmp_path, STAGING)
    # run_dir preesistente con solo LOAD completata
    run_dir = runs / "g" / "20260613T000000_000000Z"
    run_dir.mkdir(parents=True)
    RunState(target="g", max_intrusion="read-only", phases_completed=["LOAD"]).save(run_dir)

    orch = Orchestrator(targets_dir=targets, runs_root=runs, baselines_root=tmp_path / "baselines")
    state = orch.run("g", resume=True)

    assert "RECON" in state.phases_completed
    assert "PERSIST" in state.phases_completed
    # ha riusato la stessa run_dir, non ne ha creata una nuova
    assert len(list((runs / "g").glob("*/"))) == 1


def test_resume_with_findings_does_not_crash_on_conditional_phases(tmp_path: Path, monkeypatch):
    # Regressione (§6/§24): al resume da uno stato parziale, BASELINE viene
    # rieseguita e ricalcola i counts dalla scansione corrente; con ≥1 finding
    # NEW (e [notify].channel) le precondizioni di REMEDIATE/NOTIFY scattano sui
    # counts freschi (self._result.counts). REMEDIATE/NOTIFY sono stub (M1/M2):
    # devono essere no-op, NON un crash.
    finding = _finding(module="supabase", rule_id="RLS_DISABLED", endpoint="/rest/v1/clienti")
    stub = _StubModule("supabase", findings=[finding])
    _patch_offline(monkeypatch, plan_modules=[stub])
    runs = tmp_path / "runs"
    targets = _targets(tmp_path, STAGING_NOTIFY)
    run_dir = runs / "g" / "20260613T000000_000000Z"
    run_dir.mkdir(parents=True)
    RunState(target="g", max_intrusion="read-only", phases_completed=["LOAD"]).save(run_dir)

    orch = Orchestrator(targets_dir=targets, runs_root=runs, baselines_root=tmp_path / "baselines")
    state = orch.run("g", resume=True)   # NON deve sollevare

    assert state.counts["new"] == 1
    assert "REMEDIATE" in state.phases_completed
    assert "NOTIFY" in state.phases_completed
    assert "PERSIST" in state.phases_completed


def test_fresh_run_with_findings_runs_conditional_phases(tmp_path: Path, monkeypatch):
    # Regressione (§6): su una run FRESCA (non resume) le precondizioni di
    # REMEDIATE/NOTIFY vanno valutate sui counts appena calcolati in BASELINE
    # (self._result.counts), NON su state.counts (popolato solo in PERSIST, dopo).
    # Con 1 finding NEW HIGH e [notify].channel configurato, REMEDIATE e NOTIFY
    # DEVONO essere eseguite, non finire in phases_skipped.
    finding = _finding(module="supabase", rule_id="RLS_DISABLED", endpoint="/rest/v1/clienti")
    stub = _StubModule("supabase", findings=[finding])
    _patch_offline(monkeypatch, plan_modules=[stub])

    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING_NOTIFY), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g")

    assert state.counts["new"] == 1
    assert "REMEDIATE" in state.phases_completed, "REMEDIATE saltata su run fresca con finding"
    assert "NOTIFY" in state.phases_completed, "NOTIFY saltata su run fresca con finding+channel"
    assert "REMEDIATE" not in state.phases_skipped
    assert "NOTIFY" not in state.phases_skipped


def test_fresh_run_without_findings_skips_conditional_phases(tmp_path: Path, monkeypatch):
    # Contropartita del test sopra: su una run fresca SENZA finding (e quindi
    # counts a zero), REMEDIATE e NOTIFY restano correttamente saltate (§6).
    _patch_offline(monkeypatch)
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING_NOTIFY), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g")

    assert state.counts["new"] == 0
    assert "REMEDIATE" in state.phases_skipped
    assert "NOTIFY" in state.phases_skipped


def test_resume_on_completed_run_is_noop(tmp_path: Path, monkeypatch):
    _patch_offline(monkeypatch)
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    first = orch.run("g")
    dirs_before = len(list((runs / "g").glob("*/")))
    again = orch.run("g", resume=True)
    assert len(list((runs / "g").glob("*/"))) == dirs_before   # nessuna nuova run
    assert again.started_at == first.started_at               # stessa run ripresa


# ─── nuovi test: pipeline reale cablata (OFFLINE) ───────────────────────────

def test_full_run_produces_sarif_report_and_state(tmp_path: Path, monkeypatch):
    """Una run completa con recon+moduli MONKEYPATCHATI produce bastione.sarif +
    report.md + state.json; phases_completed include RECON..PERSIST; i finding e i
    posture check dei moduli finiscono nei file generati (§6/§23)."""
    finding = _finding(module="supabase", rule_id="RLS_DISABLED", endpoint="/rest/v1/clienti")
    posture = PostureCheck(
        check_id="POSTURE_HSTS", title="HSTS presente", passed=True,
        severity_if_failed=Severity.HIGH, target="g", detail="ok")
    stub = _StubModule("supabase", findings=[finding], posture=[posture])
    _patch_offline(monkeypatch, plan_modules=[stub])

    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g")

    for ph in MANDATORY:
        assert ph in state.phases_completed, f"{ph} non completata"

    run_dir = next((runs / "g").glob("*/"))
    sarif_path = run_dir / "bastione.sarif"
    report_path = run_dir / "report.md"
    state_path = run_dir / "state.json"
    fp_path = run_dir / "fingerprint.json"
    assert sarif_path.exists(), "bastione.sarif non scritto"
    assert report_path.exists(), "report.md non scritto"
    assert state_path.exists(), "state.json non scritto"
    assert fp_path.exists(), "fingerprint.json non scritto dal RECON"

    # SARIF valido e contenente la rule del finding emesso
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "RLS_DISABLED" in rule_ids

    # Il report cita il finding NEW
    report = report_path.read_text(encoding="utf-8")
    assert "RLS_DISABLED" in report

    # counts dello state: 1 finding NEW HIGH
    assert state.counts["new"] == 1
    assert state.counts["by_severity"]["high"] == 1
    # POSTURE: score calcolato e salvato
    assert state.posture_score is not None


def test_module_error_does_not_crash_others_and_emits_meta_finding(tmp_path: Path, monkeypatch):
    """Resilienza (§6): un modulo che solleva un'eccezione produce un MODULE_ERROR
    (severity INFO) e NON interrompe gli altri moduli, i cui finding restano emessi."""
    good = _StubModule(
        "headers",
        posture=[PostureCheck(
            check_id="POSTURE_CSP", title="CSP presente", passed=True,
            severity_if_failed=Severity.HIGH, target="g", detail="ok")],
        findings=[_finding(module="secrets", rule_id="SECRET_KEY", endpoint="/app.js")],
    )
    bad = _StubModule("supabase", boom=True)
    # ordine misto per assicurare che il crash non dipenda dalla posizione
    _patch_offline(monkeypatch, plan_modules=[bad, good])

    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g")   # NON deve sollevare

    assert "SCAN" in state.phases_completed
    assert "PERSIST" in state.phases_completed

    run_dir = next((runs / "g").glob("*/"))
    sarif = json.loads((run_dir / "bastione.sarif").read_text(encoding="utf-8"))
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    # il modulo buono ha prodotto il suo finding
    assert "SECRET_KEY" in rule_ids
    # il modulo fallito ha prodotto il meta-finding MODULE_ERROR
    assert "MODULE_ERROR" in rule_ids


def test_service_role_hidden_posture_added_in_normalize(tmp_path: Path, monkeypatch):
    """Cross-check §11.1.6: NORMALIZE aggiunge sempre POSTURE_SERVICE_ROLE_HIDDEN.
    passed=False se è presente un finding SECRET_SERVICE_ROLE, altrimenti passed=True."""
    leak = _finding(module="secrets", rule_id="SECRET_SERVICE_ROLE", endpoint="/app.js")
    stub = _StubModule("secrets", findings=[leak])
    _patch_offline(monkeypatch, plan_modules=[stub])

    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    orch.run("g")

    run_dir = next((runs / "g").glob("*/"))
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "POSTURE_SERVICE_ROLE_HIDDEN" in report


def test_accept_baseline_saves_baseline_promoting_new_to_known(tmp_path: Path, monkeypatch):
    """Con accept_baseline=True, PERSIST salva la baseline (§16) promuovendo i NEW
    a KNOWN: una run successiva NON li conta più come NEW."""
    finding = _finding(module="supabase", rule_id="RLS_DISABLED", endpoint="/rest/v1/ordini")
    stub = _StubModule("supabase", findings=[finding])
    _patch_offline(monkeypatch, plan_modules=[stub])

    runs = tmp_path / "runs"
    baselines = tmp_path / "baselines"
    orch = Orchestrator(targets_dir=_targets(tmp_path, STAGING), runs_root=runs,
                        baselines_root=baselines)
    first = orch.run("g", accept_baseline=True)
    assert first.counts["new"] == 1

    baseline_file = baselines / "g.baseline.json"
    assert baseline_file.exists(), "baseline non salvata con accept_baseline"
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert data["findings"], "baseline senza finding"
    assert all(v["status"] == "known" for v in data["findings"].values())

    # seconda run (senza accept): lo stesso finding ora è KNOWN, non NEW
    finding2 = _finding(module="supabase", rule_id="RLS_DISABLED", endpoint="/rest/v1/ordini")
    stub2 = _StubModule("supabase", findings=[finding2])
    _patch_offline(monkeypatch, plan_modules=[stub2])
    second = orch.run("g")
    assert second.counts["new"] == 0
    assert second.counts["known"] == 1


def test_plan_excludes_disabled_modules(tmp_path: Path, monkeypatch):
    """PLAN reale (non monkeypatchato): un modulo in [modules].disabled viene escluso;
    i moduli applicabili a un fingerprint minimale producono comunque un report."""
    # qui NON patchiamo _plan_phase: usiamo la selezione reale dei moduli concreti.
    # Garantiamo che il REGISTRY sia popolato a prescindere dall'ordine dei test
    # (test_modules_base.py lo svuota nel teardown): forziamo la registrazione.
    import importlib

    from bastione.modules.base import REGISTRY
    for mod in ("bastione.modules.cloudflare.module",
                "bastione.modules.headers.module",
                "bastione.modules.secrets.module",
                "bastione.modules.supabase.module"):
        importlib.reload(importlib.import_module(mod))
    assert {"cloudflare", "headers", "secrets", "supabase"} <= set(REGISTRY)

    monkeypatch.setattr(orch_mod, "fingerprint", _fake_fingerprint_factory(
        resolved_urls=["https://staging.example/"],
        response_headers={"server": "nginx"},
        cloudflare_fronted=True,
    ))
    # neutralizziamo i confini di rete dei moduli concreti che potrebbero girare
    import bastione.modules.secrets.module as secrets_mod
    monkeypatch.setattr(secrets_mod, "_fetch", lambda url: None)

    body = STAGING + '\n[modules]\ndisabled = ["cloudflare"]\n'
    runs = tmp_path / "runs"
    orch = Orchestrator(targets_dir=_targets(tmp_path, body), runs_root=runs,
                        baselines_root=tmp_path / "baselines")
    state = orch.run("g")

    assert "PLAN" in state.phases_completed
    assert "REPORT" in state.phases_completed
    run_dir = next((runs / "g").glob("*/"))
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    # cloudflare disabilitato → il suo posture check NON deve comparire
    assert "POSTURE_CLOUDFLARE_FRONTED" not in report
    # headers gira (resolved_urls presenti) → i suoi check compaiono
    assert "POSTURE_HSTS" in report
