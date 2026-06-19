"""SemgrepModule — colla sottile attorno a semgrep (§14 del blueprint). PROBE 🟡.

semgrep è uno scanner statico white-box (SAST). Bastione NON reimplementa la
detection: gli mette intorno la colla canonica (§14):

  1. **self-gate + which** — il modulo gira SOLO se il tetto della run è ≥ PROBE
     E l'ownership è verificata; in più chiama `gate.authorize(PROBE, ctx)` come
     backstop (difesa in profondità §7). Sotto read-only → Finding INFO `SKIPPED`
     e prosegue, NESSUN authorize, NESSUN subprocess (comportamento M0 invariato).
     Se il binario manca (`shutil.which("semgrep") is None`) → Finding INFO
     `SKIPPED` ONESTO: il report DICHIARA lo skip, non lo nasconde (§4.7/§26).
  2. **invocazione** — argv-list (mai shell=True, niente interpolazione di shell
     → niente command injection §14), `--json --quiet --config auto` sulla
     source_path locale. Output JSON in `ctx.run_dir/raw/semgrep.json` per
     l'artefatto raw/ (struttura repo normativa §4).
  3. **parse + normalize** — ogni risultato JSON → Finding (rule_id = check_id;
     severity mappata ERROR/WARNING/INFO → Severity; location = path + start.line;
     confidence FIRM; intrusion_used=PROBE). Evidence REDATTA (P8): mai snippet
     di codice. Dedup via finding_id (§16).

Resilienza (§4.7): binario assente → SKIPPED; sorgente assente → SKIPPED; un
confine I/O che fallisce → degrada a [] (nessun finding) senza propagare.

Il confine di I/O è la funzione modulo-livello `_run_semgrep(source_path, out_path)`:
l'unica cosa monkeypatchata nei test (offline) — come per nuclei (§14).
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from pathlib import Path

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    RunContext,
    TargetConfig,
)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.semgrep")

_SEMGREP_TIMEOUT = 300  # secondi: scansione statica su sorgente locale (§14)

# Mapping severità semgrep → Severity (§14). Case-insensitive; valore sconosciuto
# → INFO prudenziale (non gonfiamo lo score per una severità che non sappiamo
# mappare). semgrep usa ERROR/WARNING/INFO nei suoi risultati JSON.
_SEVERITY_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.INFO,
}


# ─── confine I/O (monkeypatchato nei test) ──────────────────────────────────

def _run_semgrep(source_path: str, out_path: str) -> list[dict]:
    """Invoca semgrep in modalità auto e ritorna i 'results' del JSON (§14).

    Subprocess SICURO: argv-list, mai shell=True — nessuna interpolazione di shell
    (niente command injection §14). Scrive il JSON anche su disco in `out_path`
    per l'artefatto raw/ (§4).

    Degrado grazioso (§4.7/L06): se il binario è sparito a runtime o l'esecuzione
    fallisce → [] (nessun risultato), mai un crash. Il chiamante ha già verificato
    `shutil.which`, ma qui restiamo difensivi."""
    argv = [
        "semgrep",
        "--json",
        "--quiet",
        "--config", "auto",
        source_path,
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=_SEMGREP_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("semgrep: esecuzione fallita, degrado a nessun risultato: %s", exc)
        return []
    # Scrivi l'output raw su disco come artefatto (§4)
    try:
        Path(out_path).write_text(proc.stdout, encoding="utf-8")
    except OSError as exc:
        log.warning("semgrep: impossibile scrivere artefatto raw: %s", exc)
    try:
        data = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        log.warning("semgrep: output non JSON, degrado a []: %s", exc)
        return []
    # Valida il tipo al confine I/O (§4.7): `results` DEVE essere una lista. semgrep
    # può emettere `{"results": null}` o `{"results": 42}` (o `data` non-dict): in
    # tutti questi casi il valore non è iterabile come una lista di result → degrada
    # a [] invece di propagare un TypeError in _parse (resilienza §4.7/L06).
    if not isinstance(data, dict):
        return []
    results = data.get("results", [])
    if not isinstance(results, list):
        log.warning("semgrep: 'results' non è una lista (%s), degrado a []",
                    type(results).__name__)
        return []
    return results


# ─── helper: finding_id stabile (§16) ────────────────────────────────────────

def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, formula LOCKED):

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    Esclude `target` ed evidenza (allineato a baseline/diff.py:finding_id): stesso
    problema → stesso id tra run, abilitando dedup (§16) e drift."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_severity(raw: object) -> Severity:
    """Severità semgrep → Severity (§14). Case-insensitive; ignoto → INFO."""
    if isinstance(raw, str):
        return _SEVERITY_MAP.get(raw.strip().lower(), Severity.INFO)
    return Severity.INFO


# ─── il modulo (§9/§14) ──────────────────────────────────────────────────────

@register
class SemgrepModule(Module):
    """Colla attorno a semgrep (§14): analisi statica white-box su sorgente locale, PROBE 🟡.

    should_run = True se la cfg ha source_path valorizzato (§14): senza sorgente
    locale non c'è nulla da scansionare. Il `which` NON si controlla qui
    (valutazione leggera, senza I/O): si controlla in run, così il report può
    DICHIARARE lo SKIPPED (§26). semgrep è white-box: NON tocca il target live."""

    name = "semgrep"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """True se la cfg ha source_path valorizzato (§14). Valutazione leggera,
        nessun I/O: il which e l'esistenza della directory restano per run (§26)."""
        return bool(getattr(cfg, "source_path", None))

    def run(self, ctx: RunContext) -> ModuleResult:
        """Esegue semgrep white-box (§14): self-gate → sorgente → which →
        authorize backstop → invocazione argv-list → parse+normalize → Finding[] dedupati.

        Sotto read-only o senza ownership/sorgente/binario, emette un singolo Finding
        INFO SKIPPED e prosegue (nessun authorize, nessun subprocess)."""
        target = ctx.target_cfg.name

        # (a) self-gate: niente PROBE sotto read-only o senza ownership (M0 identico).
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "semgrep richiede --max-intrusion >= probe e ownership verificata "
                "(§14): scansione saltata, run read-only invariata.",
            )

        # (b) sorgente: source_path assente o non esiste come directory → SKIPPED.
        source_path = getattr(ctx.target_cfg, "source_path", None)
        if not source_path or not Path(source_path).is_dir():
            return self._skipped(
                target,
                "sorgente non disponibile: source_path assente o non è una directory "
                "(§14): semgrep richiede il sorgente locale, scansione saltata.",
            )

        # (c) which: binario assente → SKIPPED onesto (il report dichiara lo skip §26).
        if shutil.which("semgrep") is None:
            return self._skipped(
                target,
                "binario semgrep assente sul PATH (§14): scansione saltata. "
                "Installa semgrep per abilitare l'analisi statica white-box.",
            )

        # (d) backstop del gate (§7): se nega, SKIPPED, niente crash, niente subprocess.
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            log.info("semgrep: PROBE negata dal gate, salto (§7): %s", exc)
            return self._skipped(
                target, f"PROBE negata dal gate (§7): {exc}")

        # (e) invocazione su confine I/O monkeypatchabile → JSON in raw/.
        raw_dir = Path(ctx.run_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / "semgrep.json"
        try:
            results = _run_semgrep(str(source_path), str(out_path))
        except Exception as exc:  # noqa: BLE001 — resilienza (§4.7): isola il fallimento
            log.warning("semgrep: invocazione fallita, nessun finding (§4.7): %s", exc)
            return ModuleResult(findings=[], posture_checks=[])

        # Normalizza il confine I/O (§4.7): `results` DEVE essere una lista prima di
        # `_parse` e del `len()` nel log. Un confine che ritorna None/scalare (es. da
        # `{"results": null}`) degrada a [] qui, senza propagare un TypeError.
        if not isinstance(results, list):
            log.warning("semgrep: _run_semgrep ha ritornato un non-list (%s), "
                        "degrado a [] (§4.7)", type(results).__name__)
            results = []

        # (f) parse + normalize → Finding[] dedupati per finding_id (§16).
        findings = self._parse(results, target)
        log.info("semgrep: %d result → %d finding (dedupati) per %s",
                 len(results), len(findings), target)
        return ModuleResult(findings=findings, posture_checks=[])

    # ── parse + normalize ───────────────────────────────────────────────────

    def _parse(self, results: list[dict], target: str) -> list[Finding]:
        """Parsa i results JSON di semgrep → Finding[] dedupati (§14/§16). Un result
        malformato o senza check_id viene SALTATO, non crasha gli altri (§4.7)."""
        # Difesa in profondità (§4.7): se `results` non è una lista (None/scalare,
        # es. da un confine I/O monkeypatchato o futuro), degrada a [] invece di
        # crashare nel `for` con TypeError: 'NoneType' object is not iterable.
        if not isinstance(results, list):
            log.warning("semgrep: _parse ha ricevuto un non-list (%s), degrado a []",
                        type(results).__name__)
            return []
        deduped: dict[str, Finding] = {}
        for result in results:
            finding = self._result_to_finding(result, target)
            if finding is None:
                continue
            # Primo vince (§16): stesso finding_id → stesso problema, niente duplicati.
            deduped.setdefault(finding.finding_id, finding)
        return list(deduped.values())

    def _result_to_finding(self, result: object, target: str) -> Finding | None:
        """Un result JSON di semgrep → Finding, o None se non interpretabile (§14).

        rule_id = `check_id`; severity da `extra.severity`; location = path + start.line.
        Evidence REDATTA (P8): solo rule_id + path:line, MAI snippet di codice."""
        if not isinstance(result, dict):
            return None
        check_id = result.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            log.debug("semgrep: result senza check_id, saltato")
            return None

        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        severity = _map_severity(extra.get("severity"))
        message = extra.get("message") if isinstance(extra.get("message"), str) else check_id

        path = result.get("path") if isinstance(result.get("path"), str) else ""
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        line = start.get("line") if isinstance(start.get("line"), int) else None

        location = Location(file=path or None, line=line)
        fid = _finding_id("semgrep", check_id, location)
        # Evidence REDATTA (P8): solo rule_id + path:line, MAI snippet di codice.
        line_str = str(line) if line is not None else "?"
        evidence = f"semgrep rule '{check_id}' @ {path}:{line_str}"

        return Finding(
            finding_id=fid,
            module="semgrep",
            rule_id=check_id,
            title=f"semgrep: {check_id}",
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=(
                f"La regola semgrep '{check_id}' ha prodotto un match "
                f"in {path or 'sorgente'}:{line_str} (severità {severity.name}). "
                f"{message} "
                "Rilevato da analisi statica white-box (PROBE §14). "
                "Verifica il dettaglio nel report raw/semgrep.json."
            ),
            remediation_ref=check_id,
            intrusion_used=IntrusionLevel.PROBE,
        )

    # ── helper: Finding INFO SKIPPED (§14/§26) ──────────────────────────────

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Costruisce il Finding INFO `SEMGREP_SKIPPED` (§14/§26): rende lo skip
        ESPLICITO nel report (onestà §4.7), invece di tacere. Severità INFO,
        confidence FIRM, intrusion READ_ONLY (nessuna azione eseguita)."""
        location = Location(endpoint="semgrep")
        fid = _finding_id("semgrep", "SEMGREP_SKIPPED", location)
        finding = Finding(
            finding_id=fid,
            module="semgrep",
            rule_id="SEMGREP_SKIPPED",
            title="Scansione semgrep saltata",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=motivo,
            description=(
                f"La scansione semgrep (§14) è stata saltata: {motivo} "
                "Lo skip è dichiarato esplicitamente (non nascosto, §4.7/§26): "
                "questa verifica NON è stata eseguita."
            ),
            intrusion_used=IntrusionLevel.READ_ONLY,
        )
        return ModuleResult(findings=[finding], posture_checks=[])
