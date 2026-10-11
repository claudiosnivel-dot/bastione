"""Macchina a stati delle 12 fasi (§6).

Le fasi RECON→PERSIST sono ora **cablate** ai componenti già costruiti
(recon §8, moduli §9–§12, baseline §16, posture §17, normalizzazione §23,
report §23): l'orchestratore non orchestra più degli stub, ma esegue la
pipeline reale, restando però interamente **READ_ONLY** in M0 (solo GET).

Ordine e precondizioni sono quelli di §6 (righe 335-356). Le fasi condizionali
non eseguite finiscono in `phases_skipped`, **non** omesse (§24): un `--resume`
non rientra in una fase mai dovuta. Lo stato viene salvato dopo ogni fase, così
un crash lascia una run ripartibile.

Regole motore (LOCKED):
- Il **gate non declassa, aborta** (§6/§7): una run su `production` solleva
  `IntrusionDenied` in LOAD, prima di scrivere alcunché su disco.
- **Resilienza** (§6/§4.7): un modulo che fallisce in SCAN NON crasha gli altri;
  produce un meta-finding `MODULE_ERROR` (severity INFO) e la run prosegue.
- READ_ONLY (M0): nessuna fase supera la sola GET; la verifica di ownership
  (§7.1) gira solo se max_intrusion > READ_ONLY.

REMEDIATE è cablata a M1 (§18-bis.2): con ≥1 finding aperto (NEW/KNOWN) e salvo
`--no-fix`, genera il bundle `fix/` (FIX-PLAN.md + fix-plan.json + migrations/)
in `runs/<target>/<ts>/fix/`. È READ_ONLY rispetto al target: scrive solo
artefatti locali, nessuna azione sul target, nessuna rete (O05 LOCKED).

NOTIFY è cablata a M2 (§19): con ≥1 finding NEW ≥ soglia OPPURE ≥1 DRIFT e un
canale configurato (`[notify].channel`), costruisce il `RunSummary` e chiama
`notify.dispatch`. La soglia effettiva è UNA sola per run (§19 LOCKED): il flag
`--fail-on` vince sul TOML (`notify_min_severity`, default HIGH). È **resiliente**:
una notifica fallita (env mancante, rete giù) NON fa crashare la run — la fase
NOTIFY si completa comunque.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from bastione.baseline.diff import (
    ReverifyScope,
    endpoint_keys,
    observation_level,
    proof_keys,
    reverify_scope_from_run,
    BaselineResult,
    apply_baseline,
    finding_id,
    load_baseline,
    save_baseline,
)
from bastione.config import DEFAULT_TARGETS_DIR, load_target
from bastione.enums import Confidence, IntrusionLevel, Phase, Severity, Status
from bastione.gate import IntrusionDenied, assert_preconditions, verify_ownership
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    PostureCheck,
    RunContext,
    TargetConfig,
)
from bastione.normalize.sarif import to_sarif
from bastione import notify   # §19: il package popola NOTIFIERS al primo import
from bastione.posture.checks import posture_score
from bastione.recon.fingerprint import fingerprint
from bastione.remediation.agent_bundle import build_fix_plan, write_fix_bundle
from bastione.report.html import to_html
from bastione.report.markdown import to_markdown
from bastione.state import RunState, intrusion_to_cli

log = logging.getLogger("bastione.orchestrator")

DEFAULT_RUNS_ROOT = Path("runs")
DEFAULT_BASELINES_ROOT = Path("baselines")

FINGERPRINT_FILENAME = "fingerprint.json"
SARIF_FILENAME = "bastione.sarif"
REPORT_FILENAME = "report.md"
REPORT_HTML_FILENAME = "report.html"   # single-file condivisibile (§23, O02)

# Ordine deterministico delle 12 fasi (§6).
PHASE_ORDER: list[Phase] = [
    Phase.LOAD, Phase.OWNERSHIP, Phase.RECON, Phase.PLAN, Phase.SCAN,
    Phase.NORMALIZE, Phase.BASELINE, Phase.POSTURE, Phase.REPORT,
    Phase.REMEDIATE, Phase.NOTIFY, Phase.PERSIST,
]

# Fasi ancora stub (no-op loggato in `_execute`). VUOTO a M2 step 3: NOTIFY è ora
# cablata (vedi `_notify`), come REMEDIATE lo era da M1. Il set resta come hook
# difensivo: una futura fase non-ancora-implementata può finire qui per essere un
# no-op invece di sollevare "fase senza handler". La decisione skip/esegui resta
# sempre in `_should_run`.
_SHELL_STUB: set[Phase] = set()

# Lunghezza massima dell'evidence nel meta-finding MODULE_ERROR (§6): tronchiamo
# il testo dell'eccezione per non gonfiare il report con stack/messaggi enormi.
_MODULE_ERROR_EVIDENCE_MAX = 500


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_modules_loaded() -> None:
    """Importa (idempotentemente) i moduli concreti e i detector di segreti, così
    che i decoratori @register / @register_detector popolino REGISTRY e DETECTORS
    (§9/§10). L'import è il punto di registrazione: senza, in PLAN il REGISTRY è
    vuoto. Ripetere l'import è un no-op (il modulo è già in sys.modules)."""
    import bastione.modules.cloudflare.module  # noqa: F401
    import bastione.modules.headers.module  # noqa: F401
    import bastione.modules.idor.module  # noqa: F401  (M4.1 IDOR autenticato)
    import bastione.modules.login_hardening.module  # noqa: F401  (M4.2)
    import bastione.modules.nuclei.module  # noqa: F401  (§14 black-box esterno)
    import bastione.modules.secrets.detectors  # noqa: F401  (popola DETECTORS)
    import bastione.modules.secrets.module  # noqa: F401
    import bastione.modules.semgrep.module  # noqa: F401  (§14 white-box SAST, gated su source_path)
    import bastione.modules.server_exposure.module  # noqa: F401  (M4.4)
    import bastione.modules.supabase.module  # noqa: F401
    import bastione.modules.trivy.module  # noqa: F401  (§14 white-box SCA, gated su source_path)
    import bastione.modules.zap.module  # noqa: F401  (§14 black-box esterno)
    import bastione.modules.zap_active.module  # noqa: F401  (M4.3)


class Orchestrator:
    def __init__(
        self,
        *,
        targets_dir: Path = DEFAULT_TARGETS_DIR,
        runs_root: Path = DEFAULT_RUNS_ROOT,
        baselines_root: Path = DEFAULT_BASELINES_ROOT,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.targets_dir = Path(targets_dir)
        self.runs_root = Path(runs_root)
        self.baselines_root = Path(baselines_root)
        self._now = now
        # stato di lavoro per-run (ripopolato a ogni run())
        self._target: str = ""
        self._cfg: TargetConfig | None = None
        self._run_dir: Path = Path(".")
        self._max_intrusion: IntrusionLevel = IntrusionLevel.READ_ONLY
        self._accept_baseline: bool = False
        self._no_fix: bool = False
        # NOTIFY abilitata? (contratto outward-facing, §7/§19): le ri-scansioni di
        # sola verifica (verify / export-defectdojo, via _rescan_read_only) passano
        # notify=False per sopprimere la fase NOTIFY — nessuna azione outward-facing
        # (POST Telegram) in un comando dichiarato READ_ONLY e di sola lettura.
        self._notify_enabled: bool = True
        # Soglia effettiva del trigger NOTIFY (§19): se passata da --fail-on vince
        # sul TOML (notify_min_severity). None → si usa cfg.notify_min_severity.
        self._fail_on: Severity | None = None
        self._fp: Fingerprint | None = None
        self._plan: list = []
        self._raw_findings: list[Finding] = []
        self._raw_posture: list[PostureCheck] = []
        self._result: BaselineResult | None = None
        self._score: float = 100.0

    # ── driver ────────────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        *,
        max_intrusion: IntrusionLevel = IntrusionLevel.READ_ONLY,
        resume: bool = False,
        accept_baseline: bool = False,
        no_fix: bool = False,
        notify: bool = True,
        fail_on: Severity | None = None,
    ) -> RunState:
        self._target = target
        self._cfg = None
        self._max_intrusion = max_intrusion
        self._accept_baseline = accept_baseline
        self._no_fix = no_fix
        # NOTIFY abilitata? (§7/§19, contratto outward-facing): di default sì (la
        # `scan` può avvisare). Le ri-scansioni di sola verifica passano notify=False
        # per sopprimere la fase NOTIFY — un comando READ_ONLY/di sola lettura non
        # deve mai compiere un'azione outward-facing (es. POST Telegram).
        self._notify_enabled = notify
        # Soglia del trigger NOTIFY (§19 LOCKED): --fail-on vince sul TOML. La CLI
        # passa qui la severità già risolta da --fail-on (o None se assente).
        self._fail_on = fail_on
        self._fp = None
        self._plan = []
        self._raw_findings = []
        self._raw_posture = []
        self._result = None
        self._score = 100.0

        run_dir = self._resolve_run_dir(target, resume)
        self._run_dir = run_dir
        state = self._init_or_load_state(target, run_dir, max_intrusion, resume)

        progressed = False
        try:
            for phase in PHASE_ORDER:
                seen = set(state.phases_completed) | set(state.phases_skipped)
                if phase.name in seen:
                    # già fatto in una run precedente (resume): riacquisisci in
                    # memoria ciò che le fasi successive presuppongono (idempotente).
                    self._rehydrate(phase, state, run_dir)
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

    # ── reidratazione su --resume (§24) ──────────────────────────────────────

    def _rehydrate(self, phase: Phase, state: RunState, run_dir: Path) -> None:
        """Al resume, una fase già vista non viene rieseguita; ma le fasi
        successive presuppongono dei valori in memoria (cfg, fingerprint, piano,
        finding/posture). Li riacquisiamo qui in modo idempotente, come LOAD
        ri-carica la config.

        LOAD/RECON sono side-effect-free e ricaricano cfg/fingerprint dal disco.
        PLAN/SCAN/NORMALIZE, invece, ripopolano self._plan/_raw_findings/
        _raw_posture che BASELINE (§16) presuppone: senza, un crash DOPO NORMALIZE
        lascerebbe self._raw_findings=[] e BASELINE marcherebbe FIXED ogni finding
        già in baseline (counts corrotti, falsi FIXED — viola P7 "solo delta", §16).
        Le ri-eseguiamo in memoria (read-only: il SCAN è solo GET) **una volta
        sola**, e solo finché BASELINE non è ancora stata vista — è idempotente e
        non ri-salva lo stato delle fasi già contate (run() non le riconta)."""
        if phase is Phase.LOAD and self._cfg is None:
            self._load()
        elif phase is Phase.RECON and self._fp is None:
            self._fp = self._load_fingerprint(run_dir)
        elif phase in (Phase.PLAN, Phase.SCAN, Phase.NORMALIZE):
            self._rehydrate_scan_chain(state)

    def _rehydrate_scan_chain(self, state: RunState) -> None:
        """Ricostruisce in memoria la catena PLAN→SCAN→NORMALIZE al --resume (§24),
        così BASELINE gira sulla scansione reale e non su liste vuote (§16).

        Idempotente e a costo zero se BASELINE è già stata vista (run completata
        ripresa: niente da ricostruire) o se la catena è già stata ricostruita in
        questo resume (le fasi PLAN/SCAN/NORMALIZE chiamano tutte qui). Presuppone
        cfg e fingerprint già reidratati da LOAD/RECON, che precedono PLAN (§6)."""
        # Se BASELINE è già stata vista, le fasi a valle non rieseguono: nessuna
        # ricostruzione necessaria (resume di una run completata).
        seen = set(state.phases_completed) | set(state.phases_skipped)
        if Phase.BASELINE.name in seen:
            return
        # Ricostruisci una volta sola: i raw_findings popolati segnalano fatto.
        if self._plan or self._raw_findings or self._raw_posture:
            return
        self._plan_phase()
        self._scan(state)
        self._normalize()

    # ── precondizioni (§6) ────────────────────────────────────────────────

    def _should_run(self, phase: Phase, state: RunState, max_intrusion: IntrusionLevel) -> bool:
        if phase is Phase.OWNERSHIP:
            return max_intrusion > IntrusionLevel.READ_ONLY
        # REMEDIATE/NOTIFY (§6): la precondizione si valuta sui counts della run
        # corrente. Su una run fresca state.counts è ancora lo zero-default
        # (è popolato solo in PERSIST, fase 12, DOPO REMEDIATE/NOTIFY): usiamo
        # self._result.counts, già calcolato in BASELINE (fase 7). Solo al
        # --resume, dove _result è None ma state.counts è stato riletto da
        # state.json (§24), ricadiamo su state.counts.
        if phase is Phase.REMEDIATE or phase is Phase.NOTIFY:
            counts = self._result.counts if self._result is not None else state.counts
            if phase is Phase.REMEDIATE:
                # O05 (LOCKED): genera il bundle SEMPRE che ci sia ≥1 finding aperto
                # (NEW/KNOWN), SALVO --no-fix che salta la fase del tutto.
                if self._no_fix:
                    return False
                return counts.get("new", 0) + counts.get("known", 0) > 0
            # NOTIFY (§19): notifier configurato E (≥1 NEW ≥ soglia OPPURE ≥1 DRIFT).
            # Sopravvento del contratto outward-facing (§7): una ri-scansione di sola
            # verifica (verify / export-defectdojo) passa notify=False — la fase
            # NOTIFY è soppressa del tutto, nessun POST Telegram da un comando
            # dichiarato READ_ONLY e di sola lettura, a prescindere dai counts.
            if not self._notify_enabled:
                return False
            channel = self._cfg.notify_channel if self._cfg else "none"
            if channel == "none":
                return False
            return self._notify_signal(counts)
        return True

    def _notify_threshold(self) -> Severity:
        """Soglia effettiva del trigger NOTIFY (§19 LOCKED): UNA sola per run.

        Il flag `--fail-on` (self._fail_on, passato a run()) vince sul TOML; in sua
        assenza il default è `cfg.notify_min_severity` (a sua volta HIGH di default,
        §5.6). È la stessa soglia usata dal gate CI (§22): un'unica nozione di
        "abbastanza grave da avvisare/far fallire"."""
        if self._fail_on is not None:
            return self._fail_on
        if self._cfg is not None:
            return self._cfg.notify_min_severity
        return Severity.HIGH

    def _notify_signal(self, counts: dict) -> bool:
        """True se la run ha un segnale da notificare (§19): ≥1 finding NEW con
        severity ≥ soglia OPPURE ≥1 DRIFT. Legge `new_by_severity` (prodotto dalla
        baseline §16) e il contatore `drift`."""
        if counts.get("drift", 0) > 0:
            return True
        threshold = self._notify_threshold()
        new_by_sev = counts.get("new_by_severity", {}) or {}
        for sev in Severity:
            if sev >= threshold and new_by_sev.get(sev.name.lower(), 0) > 0:
                return True
        return False

    # ── azioni di fase ────────────────────────────────────────────────────

    def _execute(self, phase: Phase, state: RunState) -> None:
        if phase is Phase.LOAD:
            self._load()
        elif phase is Phase.OWNERSHIP:
            self._ownership(state)
        elif phase is Phase.RECON:
            self._recon()
        elif phase is Phase.PLAN:
            self._plan_phase()
        elif phase is Phase.SCAN:
            self._scan(state)
        elif phase is Phase.NORMALIZE:
            self._normalize()
        elif phase is Phase.BASELINE:
            self._baseline(state)
        elif phase is Phase.POSTURE:
            self._posture(state)
        elif phase is Phase.REPORT:
            self._report()
        elif phase is Phase.REMEDIATE:
            self._remediate()
        elif phase is Phase.NOTIFY:
            self._notify()
        elif phase is Phase.PERSIST:
            self._persist(state)
        elif phase in _SHELL_STUB:
            log.debug("fase %s: stub (no-op) — implementata a M1/M2", phase.name)
        else:  # difesa: ogni fase deve avere un trattamento esplicito
            raise RuntimeError(f"fase senza handler: {phase.name}")

    # ── LOAD / OWNERSHIP ──────────────────────────────────────────────────

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

    # ── RECON (§8) ─────────────────────────────────────────────────────────

    def _recon(self) -> None:
        """Fingerprint read-only del target (§8): scrive run_dir/fingerprint.json.
        Resiliente: se il fingerprint non è disponibile, prosegue con None — le
        fasi a valle degradano (PLAN selezionerà solo i moduli applicabili)."""
        assert self._cfg is not None
        try:
            self._fp = fingerprint(self._cfg.base_url, self._run_dir)
        except Exception:
            # Resilienza (§6/§4.7): il recon che esplode non interrompe la run.
            log.warning("RECON fallito: proseguo senza fingerprint (§8)", exc_info=True)
            self._fp = None

    def _load_fingerprint(self, run_dir: Path) -> Fingerprint | None:
        """Ricarica il fingerprint da run_dir/fingerprint.json al `--resume` (§24).
        Resiliente: file assente/corrotto → None (le fasi a valle degradano)."""
        path = run_dir / FINGERPRINT_FILENAME
        if not path.exists():
            log.warning("RECON già completata ma %s assente: fp non disponibile", path)
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Fingerprint.model_validate(data)
        except Exception:
            log.warning("fingerprint.json illeggibile (%s): fp non disponibile", path,
                        exc_info=True)
            return None

    # ── PLAN (§6/§9) ───────────────────────────────────────────────────────

    def _plan_phase(self) -> None:
        """Seleziona i moduli applicabili (§6 PLAN). Importa i moduli concreti
        (registrazione idempotente), poi tiene quelli con should_run(fp,cfg)==True
        e name NON in cfg.modules_disabled. Senza fingerprint il piano è vuoto."""
        from bastione.modules.base import REGISTRY

        _ensure_modules_loaded()
        self._plan = []
        if self._fp is None or self._cfg is None:
            log.warning("PLAN: fingerprint assente, nessun modulo selezionato (§6)")
            return

        disabled = set(self._cfg.modules_disabled)
        for name, module in REGISTRY.items():
            if name in disabled:
                log.info("PLAN: modulo %r disabilitato in config (§6)", name)
                continue
            try:
                applicabile = module.should_run(self._fp, self._cfg)
            except Exception:
                # Resilienza: uno should_run che esplode non blocca il piano.
                log.warning("PLAN: should_run di %r ha sollevato — modulo escluso",
                            name, exc_info=True)
                continue
            if applicabile:
                self._plan.append(module)
        log.info("PLAN: %d moduli selezionati (%s)",
                 len(self._plan), [m.name for m in self._plan])

    # ── SCAN (§6/§9) ───────────────────────────────────────────────────────

    def _scan(self, state: RunState) -> None:
        """Esegue i moduli del piano in PARALLELO (ThreadPoolExecutor, O04 —
        read-only). Ogni module.run gira in try/except (vedi `_run_module`): una
        eccezione GENERICA NON propaga, viene loggata e tradotta in un meta-finding
        MODULE_ERROR (INFO, §6) — un modulo che fallisce non interrompe gli altri
        (resilienza). ECCEZIONE alla resilienza: una `IntrusionDenied` del gate
        (§7/§22) NON viene declassata: `_run_module` la rilancia, `future.result()`
        la ripropaga qui e ABORTA la run (il gate aborta, non declassa)."""
        assert self._cfg is not None
        self._raw_findings = []
        self._raw_posture = []

        if self._fp is None:
            log.warning("SCAN: fingerprint assente, nessun modulo da eseguire (§6)")
            return
        if not self._plan:
            log.info("SCAN: piano vuoto, nessun modulo da eseguire")
            return

        # ownership_verified riflette lo stato corrente della run, preso da state
        # (§7.1): in M0 read-only OWNERSHIP non gira e resta False; dopo un
        # challenge superato (PROBE/MUTATING, M1/M2) i moduli vedono il valore vero.
        ctx = RunContext(
            target_cfg=self._cfg,
            fingerprint=self._fp,
            max_intrusion=self._max_intrusion,
            run_dir=self._run_dir,
            ownership_verified=state.ownership_verified,
        )

        with ThreadPoolExecutor(max_workers=max(1, len(self._plan))) as pool:
            futures = {pool.submit(self._run_module, module, ctx): module
                       for module in self._plan}
            for future, module in futures.items():
                # _run_module rilancia SOLO le negazioni del gate (IntrusionDenied):
                # qui propagano e abortiscono la run (§7/§22). Ogni altra eccezione è
                # già stata declassata a MODULE_ERROR dentro _run_module.
                findings, posture = future.result()
                self._raw_findings.extend(findings)
                self._raw_posture.extend(posture)

    def _run_module(self, module, ctx: RunContext) -> ModuleResult:
        """Esegue un singolo modulo in modo resiliente (§6) — MA il gate aborta,
        non declassa (§7/§22 LOCKED).

        Ordine dei catch (cruciale):
        1. `IntrusionDenied` (e la sua sottoclasse `PreconditionDenied`) NON va
           declassata a MODULE_ERROR: una negazione del gate — es. il canary
           §11.2 che chiama `authorize(MUTATING, ctx)` su un target non staging,
           o ownership non superata — DEVE abortire la run. La RILANCIAMO: propaga
           da qui → `future.result()` in `_scan` → `run()`, che salva lo stato e
           la ripropaga, e la CLI la mappa all'exit code §22 (2/3). Declassarla a
           MODULE_ERROR INFO violerebbe "il gate aborta, non declassa" e la tabella
           exit-code LOCKED.
        2. ogni ALTRA `Exception` → meta-finding MODULE_ERROR (INFO): resilienza,
           il modulo che esplode non interrompe gli altri. Mai un crash generico
           dal modulo."""
        try:
            result = module.run(ctx)
            return ModuleResult(
                findings=list(result.findings),
                posture_checks=list(result.posture_checks),
            )
        except IntrusionDenied:
            # Il gate aborta, non declassa (§7/§22): NON un MODULE_ERROR — propaga.
            # PreconditionDenied è sottoclasse di IntrusionDenied → coperta qui.
            log.error("SCAN: modulo %r negato dal gate — la run ABORTA (§7/§22)",
                      getattr(module, "name", "?"), exc_info=True)
            raise
        except Exception as err:  # noqa: BLE001 — resilienza (§6): isola il fallimento
            log.warning("SCAN: modulo %r ha sollevato — MODULE_ERROR emesso (§6)",
                        getattr(module, "name", "?"), exc_info=True)
            return ModuleResult(
                findings=[self._module_error_finding(module, err)],
                posture_checks=[],
            )

    def _module_error_finding(self, module, err: Exception) -> Finding:
        """Costruisce il meta-finding MODULE_ERROR (severity INFO, §6) per un modulo
        che ha sollevato un'eccezione: rende il fallimento visibile nel report senza
        interrompere la run."""
        assert self._cfg is not None
        name = getattr(module, "name", "?")
        evidence = str(err)[:_MODULE_ERROR_EVIDENCE_MAX]
        location = Location()
        finding = Finding(
            finding_id="",  # calcolato sotto con la formula LOCKED §16 (finding_id())
            module=name,
            rule_id="MODULE_ERROR",
            title=f"Modulo '{name}' fallito durante la scansione",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=self._cfg.name,
            location=location,
            evidence=evidence,
            description=(
                f"Il modulo '{name}' ha sollevato un'eccezione durante SCAN e non ha "
                "prodotto risultati. Gli altri moduli proseguono (resilienza §6). "
                f"Errore: {evidence}"
            ),
            intrusion_used=IntrusionLevel.READ_ONLY,
        )
        # finding_id stabile con la formula LOCKED §16
        # (sha256(module:rule_id:location.canonical())[:16]). BASELINE lo ricalcola
        # in modo identico (apply_baseline), quindi resta coerente lungo la pipeline.
        finding.finding_id = finding_id(finding)
        return finding

    # ── NORMALIZE (§23/§11.1.6) ─────────────────────────────────────────────

    def _normalize(self) -> None:
        """Dedup dei finding per finding_id stabile (§16): l'evidence è già redatta
        a monte (P8) — qui non si de-redatta. Cross-check §11.1.6: aggiunge il
        PostureCheck POSTURE_SERVICE_ROLE_HIDDEN (la service_role NON deve mai
        comparire come finding esposto)."""
        assert self._cfg is not None
        deduped: dict[str, Finding] = {}
        for finding in self._raw_findings:
            fid = finding.finding_id or finding_id(finding)
            finding.finding_id = fid
            # Primo vince: stesso id → stesso problema, evidence già redatta.
            deduped.setdefault(fid, finding)
        self._raw_findings = list(deduped.values())

        # Cross-check §11.1.6: la service_role key non deve essere esposta.
        service_role_exposed = any(
            f.rule_id == "SECRET_SERVICE_ROLE" for f in self._raw_findings)
        self._raw_posture.append(PostureCheck(
            check_id="POSTURE_SERVICE_ROLE_HIDDEN",
            title="Service_role key non esposta nel client",
            passed=not service_role_exposed,
            severity_if_failed=Severity.CRITICAL,
            target=self._cfg.name,
            detail=(
                "Nessun finding SECRET_SERVICE_ROLE: la service_role key non è "
                "esposta nel bundle/HTML (§11.1.6)."
                if not service_role_exposed else
                "Rilevato un finding SECRET_SERVICE_ROLE: la service_role key è "
                "esposta nel client — fuga CRITICA che bypassa ogni RLS (§11.1.6)."
            ),
            remediation_ref="SECRET_SERVICE_ROLE",
        ))

    # ── BASELINE (§16) ───────────────────────────────────────────────────────

    def _baseline(self, state: RunState) -> None:
        """Diff dei finding e dei posture check contro la baseline (§16):
        arricchisce gli status (NEW/KNOWN/FIXED), marca il DRIFT e calcola i counts.

        Persiste subito ``state.counts`` (anche se PERSIST li ri-salverà in fase 12):
        così, su un ``--resume`` entrato in REMEDIATE/NOTIFY dopo BASELINE ma prima di
        PERSIST — dove ``self._result`` è ``None`` e la precondizione di ``_should_run``
        ricade su ``state.counts`` (§24) — i counts reali sono già su disco e il bundle
        viene rigenerato invece di essere saltato per counts a zero (§6/O05)."""
        baseline = load_baseline(self._baseline_path())
        self._result = apply_baseline(
            self._raw_findings, self._raw_posture, baseline, now=self._now(),
            scope=self._reverify_scope())
        state.counts = self._result.counts

    def _reverify_scope(self) -> ReverifyScope:
        """Cosa questa run ha davvero potuto RI-VERIFICARE (S16, R6): il tetto
        d'intrusione, i moduli del piano che hanno completato il lavoro (non in
        `MODULE_ERROR`, `*_SKIPPED`, `*_NOT_FOUND`) e i limiti dichiarati sui singoli
        asset (`*_NOT_VERIFIABLE`…). I finding in baseline coperti da questi limiti
        non possono diventare FIXED in questa run."""
        return reverify_scope_from_run(
            self._max_intrusion, [m.name for m in self._plan], self._raw_findings,
            posture_checks=self._raw_posture)

    def _baseline_path(self) -> Path:
        assert self._cfg is not None
        return self.baselines_root / f"{self._target}.baseline.json"

    # ── POSTURE (§17) ─────────────────────────────────────────────────────────

    def _posture(self, state: RunState) -> None:
        """Calcola il posture score pesato dai posture check (§17) e lo salva."""
        checks = self._result.posture_checks if self._result else self._raw_posture
        self._score = posture_score(checks)
        state.posture_score = self._score

    # ── REPORT (§23) ───────────────────────────────────────────────────────────

    def _report(self) -> None:
        """Scrive run_dir/bastione.sarif (SARIF 2.1.0), run_dir/report.md e
        run_dir/report.html (§23). Il report HTML è il formato single-file
        condivisibile (O02): stesso contenuto del MD, autocontenuto (CSS/JS inline),
        tema dark con posture gauge e filtri. L'evidence è già redatta a monte (P8):
        nessuna de-redazione qui."""
        assert self._cfg is not None
        result = self._result or BaselineResult()
        self._run_dir.mkdir(parents=True, exist_ok=True)

        sarif = to_sarif(result.findings, target=self._cfg.name)
        (self._run_dir / SARIF_FILENAME).write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

        # Stessi argomenti per MD e HTML: stesso contenuto, due rese (§23).
        report_args = dict(
            target=self._cfg.name,
            posture_score=self._score,
            findings=result.findings,
            fixed=result.fixed,
            posture_checks=result.posture_checks,
            counts=result.counts,
            not_reverified=result.not_reverified,
        )
        report = to_markdown(**report_args)
        (self._run_dir / REPORT_FILENAME).write_text(report, encoding="utf-8")

        report_html = to_html(**report_args)
        (self._run_dir / REPORT_HTML_FILENAME).write_text(report_html, encoding="utf-8")

    # ── REMEDIATE (§18-bis.2 / O05) ──────────────────────────────────────────

    def _remediate(self) -> None:
        """Genera l'Agent Remediation Bundle (§18-bis.2) in run_dir/fix/.

        O05 (LOCKED): la fase scatta SEMPRE che ci sia ≥1 finding aperto (NEW/KNOWN)
        e NON sia attivo --no-fix (vedi `_should_run`). Costruisce il `FixPlan` dai
        finding emessi nella run — `self._result.findings`, che esclude già i FIXED
        (§16) — e scrive il bundle. È READ_ONLY rispetto al target: solo scrittura di
        artefatti locali sotto run_dir/fix/, nessuna azione sul target, nessuna rete.

        Resiliente (§4.7): se per qualunque ragione i finding non sono disponibili in
        memoria (es. `self._result is None` a un --resume entrato qui senza la catena
        BASELINE ricostruita), logga e non scrive — non crasha la run."""
        assert self._cfg is not None
        if self._result is None:
            log.warning(
                "REMEDIATE: nessun risultato di baseline in memoria — bundle non "
                "generato (resilienza §4.7).")
            return
        plan = build_fix_plan(
            self._result.findings,
            self._cfg,
            now=self._now(),
            run_dir=str(self._run_dir),
            # M5 (§4.8): anche i posture FALLITI diventano fix verificabili.
            posture_checks=self._result.posture_checks,
        )
        write_fix_bundle(plan, self._run_dir)
        log.info("REMEDIATE: bundle fix/ generato (%d fix) in %s",
                 len(plan.fixes), self._run_dir / "fix")

    # ── NOTIFY (§19) ───────────────────────────────────────────────────────────

    def _notify(self) -> None:
        """Invia l'alert sul delta della run (§19): costruisce il `RunSummary` dai
        dati in memoria e chiama `notify.dispatch`.

        La precondizione (canale configurato + ≥1 NEW ≥ soglia OPPURE ≥1 DRIFT) è
        già stata valutata in `_should_run`: qui si è certi che valga la pena
        avvisare. Il `report_path` è il path del report HTML (single-file, O02).

        RESILIENTE (invariante §19): NOTIFY è best-effort. `notify.dispatch` assorbe
        già ogni errore di invio (canale ignoto, env mancante, rete giù); in più
        avvolgiamo qui la *costruzione* del summary in un try/except, così nemmeno un
        dato mancante in memoria (es. counts/result assenti a un --resume entrato qui)
        può far fallire la fase. NOTIFY si completa comunque — la run è già riuscita."""
        assert self._cfg is not None
        try:
            counts = self._result.counts if self._result is not None else {}
            report_path = str(self._run_dir / REPORT_HTML_FILENAME)
            summary = notify.build_run_summary(
                target=self._cfg.name,
                posture_score=self._score,
                counts=counts,
                report_path=report_path,
            )
            notify.dispatch(self._cfg, summary)
        except Exception:  # noqa: BLE001 — best-effort §19: NOTIFY non crasha la run
            log.warning(
                "NOTIFY: errore nella costruzione/invio dell'alert — notifica non "
                "riuscita ma la run NON è compromessa (best-effort §19).",
                exc_info=True)

    # ── PERSIST (§24) ──────────────────────────────────────────────────────────

    def _persist(self, state: RunState) -> None:
        """Persiste i risultati nello state (§24): counts, posture_score; se
        --accept-baseline è attivo, promuove i NEW a KNOWN salvando la baseline."""
        assert self._cfg is not None
        if self._result is not None:
            state.counts = self._result.counts
        state.posture_score = self._score
        state.tools_available = self._detect_tools()

        if self._accept_baseline and self._result is not None:
            self._save_accepted_baseline()

        state.finished_at = self._now()

    def _detect_tools(self) -> dict:
        """Best-effort: quali tool opzionali sono disponibili (§24). Non blocca mai
        la run; l'assenza di un tool degrada il recon (§8), non lo interrompe."""
        import shutil
        return {
            "whatweb": shutil.which("whatweb") is not None,
            "katana": shutil.which("katana") is not None,
        }

    def _save_accepted_baseline(self) -> None:
        """Salva la baseline accettata (§16): tutti i finding emessi diventano noti
        (NEW→KNOWN, KNOWN/ACCEPTED preservati), così la prossima run li tratta come
        già visti. Il file contiene SOLO id/status/date — mai evidenze (L05)."""
        assert self._cfg is not None and self._result is not None
        findings_baseline: dict = {}
        for f in self._result.findings:
            # NEW promosso a KNOWN; gli altri status (KNOWN/ACCEPTED) preservati.
            status = Status.KNOWN if f.status is Status.NEW else f.status
            findings_baseline[f.finding_id] = {
                "status": status.value,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
                "rule_id": f.rule_id,
                "module": f.module,
                # S16 (R6): livello con cui si ri-osserva → una run più bassa (es.
                # `verify` READ_ONLY) non potrà darlo per FIXED. Le chiavi d'endpoint
                # (famiglia + hash, niente nomi in chiaro) lo legano ai limiti futuri.
                "intrusion_used": intrusion_to_cli(observation_level(f)),
                **endpoint_keys(f.module, f.location.endpoint),
                **proof_keys(f.verified_by),
            }
        # S16: i finding che questa run NON ha potuto ri-controllare restano in
        # baseline così com'erano (toglierli equivarrebbe a un FIXED silenzioso).
        prior_baseline = load_baseline(self._baseline_path())
        if self._result.not_reverified:
            prior = prior_baseline.get("findings", {})
            for f in self._result.not_reverified:
                if f.finding_id in prior and f.finding_id not in findings_baseline:
                    findings_baseline[f.finding_id] = prior[f.finding_id]
        posture_baseline: dict = {
            c.check_id: {"passed": c.passed}
            for c in self._result.posture_checks
        }
        # S16: i posture check non rieseguiti (run a livello più basso, modulo non
        # eseguito) restano in baseline, così un DRIFT futuro resta rilevabile.
        for check_id, entry in prior_baseline.get("posture", {}).items():
            posture_baseline.setdefault(check_id, entry)
        save_baseline(
            self._baseline_path(),
            target=self._cfg.name,
            findings=findings_baseline,
            posture=posture_baseline,
            updated_at=self._now(),
        )

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
