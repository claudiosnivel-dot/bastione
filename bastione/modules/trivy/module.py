"""TrivyModule — colla sottile attorno a trivy (§14 del blueprint). PROBE 🟡.

trivy (aquasecurity) è uno scanner white-box maturo per vulnerabilità nei
sorgenti/container. Bastione NON reimplementa la detection: gli mette intorno
la colla canonica (§14):

  1. **self-gate + which** — il modulo gira SOLO se il tetto della run è ≥ PROBE
     E l'ownership è verificata; in più chiama `gate.authorize(PROBE, ctx)` come
     backstop (difesa in profondità §7). Sotto read-only → Finding INFO `SKIPPED`
     e prosegue, NESSUN authorize, NESSUN subprocess (comportamento M0 invariato).
     Se il binario manca (`shutil.which("trivy") is None`) → Finding INFO
     `SKIPPED` ONESTO: il report DICHIARA lo skip, non lo nasconde (§4.7/§26).
  2. **invocazione** — argv-list (mai shell=True, niente interpolazione di shell
     → niente command injection §14). Output JSON in `ctx.run_dir/raw/trivy.json`
     (struttura repo normativa §4).
  3. **parse + normalize** — report JSON di trivy → Finding (rule_id =
     VulnerabilityID o ID; severity mappata CRITICAL/HIGH/MEDIUM/LOW,
     UNKNOWN/ignoto→INFO; location = Target/PkgName; evidence redatta P8;
     confidence FIRM; intrusion_used=PROBE). Dedup via finding_id (§16).

Resilienza (§4.7): binario assente → SKIPPED; source_path assente/non-dir →
SKIPPED; un confine I/O che fallisce → degrada a None (nessun finding) senza
propagare.

Il confine di I/O è la funzione modulo-livello `_run_trivy(source_path, out_path)`:
l'unica cosa monkeypatchata nei test (offline) — come per nuclei (§14) e recon (§8).
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

log = logging.getLogger("bastione.modules.trivy")

_TRIVY_TIMEOUT = 600  # secondi: una scansione FS può richiedere tempo (§14)

# Mapping severità trivy → Severity (§14). Case-insensitive; valore sconosciuto
# (UNKNOWN o altro) → INFO prudenziale.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


# ─── confine I/O (monkeypatchato nei test) ──────────────────────────────────

def _run_trivy(source_path: str, out_path: str) -> dict | None:
    """Invoca trivy fs sul sorgente locale e ritorna il report JSON (§14).

    Subprocess SICURO: argv-list, mai shell=True — nessuna interpolazione di shell
    (niente command injection §14). Scrive il JSON anche su disco in `out_path`
    per l'artefatto raw/ (struttura repo §4).

    Degrado grazioso (§4.7/L06): se il binario è sparito a runtime o l'esecuzione
    fallisce → None (nessun finding), mai un crash. Il chiamante ha già verificato
    `shutil.which`, ma qui restiamo difensivi."""
    argv = [
        "trivy",
        "fs",
        # O07: di default `trivy fs` esegue solo vuln,secret → il parser
        # _misconf_to_finding non verrebbe mai esercitato su dati reali. Forziamo
        # esplicitamente i tre scanner (vuln,secret,misconfig) così che il report
        # includa anche le Misconfigurations (§14). Resta argv-list, mai shell=True.
        "--scanners", "vuln,secret,misconfig",
        "--format", "json",
        "--quiet",
        source_path,
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=_TRIVY_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("trivy: esecuzione fallita, degrado a nessun risultato: %s", exc)
        return None
    try:
        report = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        log.warning("trivy: output non-JSON, degrado a nessun risultato: %s", exc)
        return None
    # JSON valido ma non-oggetto (lista/stringa/numero): trivy emette sempre un
    # oggetto top-level; qualsiasi altra shape è degenere → None così il guard
    # `if report is None` in run() la intercetta (come semgrep §14, isinstance dict).
    if not isinstance(report, dict):
        log.warning("trivy: report JSON non-oggetto (%s), degrado a nessun "
                    "risultato", type(report).__name__)
        return None
    # Persiste il raw su disco per l'artefatto raw/ (§4)
    try:
        Path(out_path).write_text(proc.stdout, encoding="utf-8")
    except OSError as exc:
        log.warning("trivy: impossibile scrivere raw output %s: %s", out_path, exc)
    return report


# ─── helper: finding_id stabile (§16) ────────────────────────────────────────

def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, formula LOCKED):

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    Esclude `target` ed evidenza (allineato a baseline/diff.py:finding_id): stesso
    problema → stesso id tra run, abilitando dedup (§16) e drift."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_severity(raw: object) -> Severity:
    """Severità trivy → Severity (§14). Case-insensitive; UNKNOWN/ignoto → INFO."""
    if isinstance(raw, str):
        return _SEVERITY_MAP.get(raw.strip().lower(), Severity.INFO)
    return Severity.INFO


def _as_list(value: object) -> list:
    """Coalesce difensivo (§4.7): ritorna `value` SOLO se è davvero una lista,
    altrimenti `[]`. Protegge i `for … in …` di `_parse` dai casi degeneri di
    trivy reale o malformato — `Results`/`Vulnerabilities`/`Misconfigurations`/
    `Secrets` esplicitamente null (None → []) ma anche scalari (es. 42, 3.14) che
    con il vecchio `x or []` restavano truthy e facevano esplodere il `for`
    (`TypeError: 'int' object is not iterable`). Una stringa NON è una lista →
    [] (non iteriamo i char). trivy emette sempre liste o assenza per questi
    campi: qualsiasi altra shape è degenere → nessun finding, nessun crash."""
    return value if isinstance(value, list) else []


# ─── il modulo (§9/§14) ──────────────────────────────────────────────────────

@register
class TrivyModule(Module):
    """Colla attorno a trivy (§14): scansione FS white-box, PROBE 🟡.

    should_run = True se cfg.source_path è valorizzato (§14): senza un percorso
    sorgente non c'è nulla da scansionare. Il `which` NON si controlla qui
    (valutazione leggera, senza I/O): si controlla in run, così il report può
    DICHIARARE lo SKIPPED (§26)."""

    name = "trivy"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """True se cfg.source_path è valorizzato (§14). Valutazione leggera,
        nessun I/O: il which resta per la fase run (report onesto, §26)."""
        return bool(cfg.source_path)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Esegue trivy fs (§14): self-gate → source_path → which → authorize
        backstop → invocazione argv-list → parse+normalize → Finding[] dedupati.

        Sotto read-only o senza ownership/source_path/binario, emette un singolo
        Finding INFO SKIPPED e prosegue (nessun authorize, nessun subprocess)."""
        target = ctx.target_cfg.name

        # (a) self-gate: niente PROBE sotto read-only o senza ownership (M0 identico).
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "trivy richiede --max-intrusion >= probe e ownership verificata "
                "(§14): scansione saltata, run read-only invariata.",
            )

        # (b) source_path: assente o non-directory → SKIPPED onesto (§26).
        source_path = ctx.target_cfg.source_path
        if not source_path or not Path(source_path).is_dir():
            return self._skipped(
                target,
                "sorgente non disponibile: source_path assente o non è una directory "
                "(§14): scansione trivy saltata.",
            )

        # (c) which: binario assente → SKIPPED onesto (il report dichiara lo skip §26).
        if shutil.which("trivy") is None:
            return self._skipped(
                target,
                "binario trivy assente sul PATH (§14): scansione saltata. "
                "Installa trivy (aquasecurity) per abilitare la scansione FS.",
            )

        # (d) backstop del gate (§7): se nega, SKIPPED, niente crash, niente subprocess.
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            log.info("trivy: PROBE negata dal gate, salto (§7): %s", exc)
            return self._skipped(
                target, f"PROBE negata dal gate (§7): {exc}")

        # (e) invocazione su confine I/O monkeypatchabile → JSON in raw/.
        raw_dir = Path(ctx.run_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / "trivy.json"
        try:
            report = _run_trivy(source_path, str(out_path))
        except Exception as exc:  # noqa: BLE001 — resilienza (§4.7): isola il fallimento
            log.warning("trivy: invocazione fallita, nessun finding (§4.7): %s", exc)
            return ModuleResult(findings=[], posture_checks=[])

        if report is None:
            log.info("trivy: nessun report disponibile per %s", target)
            return ModuleResult(findings=[], posture_checks=[])

        # (f) parse + normalize → Finding[] dedupati per finding_id (§16).
        findings = self._parse(report, target)
        log.info("trivy: %d finding (dedupati) per %s", len(findings), target)
        return ModuleResult(findings=findings, posture_checks=[])

    # ── parse + normalize ───────────────────────────────────────────────────

    def _parse(self, report: dict, target: str) -> list[Finding]:
        """Parsa il report JSON di trivy → Finding[] dedupati (§14/§16).

        Itera report.get("Results",[]) e per ciascun Result le "Vulnerabilities",
        le "Misconfigurations" e i "Secrets" (se presenti). Un record senza ID
        (VulnerabilityID/ID/RuleID) viene SALTATO, non crasha gli altri (§4.7).
        I Secrets diventano Finding PER-SECRET a severità INFO (design LOCKED)."""
        deduped: dict[str, Finding] = {}
        # `report` può non essere un dict (difesa in profondità §4.7) e "Results"
        # può essere esplicitamente null (output reale di trivy: chiave presente con
        # valore None). `.get("Results", [])` da solo NON copre il caso null →
        # coalesciamo via `_as_list` (lista solo se davvero lista, altrimenti []).
        for result in _as_list(report.get("Results")) if isinstance(report, dict) else []:
            if not isinstance(result, dict):
                continue
            result_target = result.get("Target", "") or ""

            # Vulnerabilità
            for vuln in _as_list(result.get("Vulnerabilities")):
                finding = self._vuln_to_finding(vuln, result_target, target)
                if finding is None:
                    continue
                # Primo vince (§16): stesso finding_id → stesso problema.
                deduped.setdefault(finding.finding_id, finding)

            # Misconfigurations (se presenti nel risultato)
            for misconf in _as_list(result.get("Misconfigurations")):
                finding = self._misconf_to_finding(misconf, result_target, target)
                if finding is None:
                    continue
                deduped.setdefault(finding.finding_id, finding)

            # Secrets (O06): un Finding PER-SECRET a severità INFO (design LOCKED).
            for secret in _as_list(result.get("Secrets")):
                finding = self._secret_to_finding(secret, result_target, target)
                if finding is None:
                    continue
                deduped.setdefault(finding.finding_id, finding)

        return list(deduped.values())

    def _vuln_to_finding(
        self, vuln: object, result_target: str, target: str
    ) -> Finding | None:
        """Una voce Vulnerabilities del report trivy → Finding, o None (§14).

        rule_id = VulnerabilityID; location.file = PkgName (package affetto).
        Evidence NON segreta (P8): solo id + package, mai corpo di risposta."""
        if not isinstance(vuln, dict):
            return None
        rule_id = vuln.get("VulnerabilityID")
        if not isinstance(rule_id, str) or not rule_id:
            log.debug("trivy: vulnerabilità senza VulnerabilityID, saltata")
            return None

        severity = _map_severity(vuln.get("Severity"))
        pkg_name = vuln.get("PkgName") or result_target or ""
        # Fallback al bare rule_id (come nuclei): il prefisso "trivy: " è applicato
        # una sola volta sotto, costruendo il Finding. Prefissare anche qui
        # produrrebbe "trivy: trivy: <id>" quando il campo Title è assente.
        title = vuln.get("Title") or rule_id

        location = Location(file=pkg_name or None, endpoint=None)
        fid = _finding_id("trivy", rule_id, location)
        # Evidence redatta (P8): solo id + package, mai dettagli di exploit.
        evidence = f"trivy {rule_id} in {pkg_name}".rstrip()

        return Finding(
            finding_id=fid,
            module="trivy",
            rule_id=rule_id,
            title=f"trivy: {title}",
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=(
                f"trivy ha rilevato la vulnerabilità '{rule_id}' nel pacchetto "
                f"'{pkg_name}' (severità {severity.name}). "
                "Rilevato da una scansione FS white-box (PROBE §14). "
                "Verifica il dettaglio nel report raw/trivy.json."
            ),
            remediation_ref=rule_id,
            intrusion_used=IntrusionLevel.PROBE,
        )

    def _misconf_to_finding(
        self, misconf: object, result_target: str, target: str
    ) -> Finding | None:
        """Una voce Misconfigurations del report trivy → Finding, o None (§14).

        rule_id = ID (misconfig id); location.file = result_target (file/package).
        Evidence NON segreta (P8): solo id + file."""
        if not isinstance(misconf, dict):
            return None
        rule_id = misconf.get("ID")
        if not isinstance(rule_id, str) or not rule_id:
            log.debug("trivy: misconfiguration senza ID, saltata")
            return None

        severity = _map_severity(misconf.get("Severity"))
        # Fallback al bare rule_id (come nuclei): il prefisso "trivy: " è applicato
        # una sola volta sotto. Prefissare anche qui produrrebbe "trivy: trivy: <id>"
        # quando il campo Title è assente.
        title = misconf.get("Title") or rule_id

        location = Location(file=result_target or None, endpoint=None)
        fid = _finding_id("trivy", rule_id, location)
        # Evidence redatta (P8): solo id + file, mai dettagli di configurazione.
        evidence = f"trivy {rule_id} in {result_target}".rstrip()

        return Finding(
            finding_id=fid,
            module="trivy",
            rule_id=rule_id,
            title=f"trivy: {title}",
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=(
                f"trivy ha rilevato la misconfiguration '{rule_id}' in "
                f"'{result_target}' (severità {severity.name}). "
                "Rilevato da una scansione FS white-box (PROBE §14). "
                "Verifica il dettaglio nel report raw/trivy.json."
            ),
            remediation_ref=rule_id,
            intrusion_used=IntrusionLevel.PROBE,
        )

    def _secret_to_finding(
        self, secret: object, result_target: str, target: str
    ) -> Finding | None:
        """Una voce Secrets del report trivy → Finding, o None (O06, design LOCKED).

        Finding PER-SECRET a severità SEMPRE INFO (non la severità di trivy): i
        secret di trivy includono falsi positivi by-design (es. anon key pubblica
        nel bundle); a INFO sono visibili ma non gonfiano il posture score, e il
        triage autorevole dei secret pericolosi resta il detector §10
        (SECRET_SERVICE_ROLE).

        rule_id = RuleID; location.file = result_target, location.line = StartLine
        (così due secret della stessa RuleID su righe diverse dello STESSO file
        danno finding_id distinti §16; identici dedupano).

        P8 (segreti redatti §7): il valore del secret (Match/Code) NON compare MAI
        in evidence/title/description/remediation_ref — solo metadati di regola
        (RuleID, Category, Title, file:line). Il Title di trivy è il nome-regola
        umano (es. "AWS Access Key ID"), NON il segreto → P8-safe."""
        if not isinstance(secret, dict):
            return None
        rule_id = secret.get("RuleID")
        if not isinstance(rule_id, str) or not rule_id:
            log.debug("trivy: secret senza RuleID, saltato")
            return None

        # Severità SEMPRE INFO (design LOCKED): la severità di trivy è ignorata.
        severity = Severity.INFO
        start_line = secret.get("StartLine")
        line = start_line if isinstance(start_line, int) else None
        category = secret.get("Category") or ""
        # Fallback al bare rule_id (come vuln/misconf): il prefisso "trivy: " è
        # applicato una sola volta sotto. Il Title di trivy è il nome-regola umano,
        # mai il segreto (P8-safe).
        title = secret.get("Title") or rule_id

        location = Location(file=result_target or None, line=line)
        fid = _finding_id("trivy", rule_id, location)
        # Evidence redatta (P8): SOLO metadati di regola — mai il Match né il Code.
        line_str = str(line) if line is not None else ""
        evidence = f"trivy secret {rule_id} ({category}) in {result_target}:{line_str}"

        return Finding(
            finding_id=fid,
            module="trivy",
            rule_id=rule_id,
            title=f"trivy: {title}",
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=(
                f"trivy ha rilevato un potenziale secret '{rule_id}' "
                f"(categoria '{category}') in '{result_target}' (severità INFO). "
                "Il triage autorevole dei secret pericolosi è il detector §10 "
                "(SECRET_SERVICE_ROLE): i secret di trivy includono falsi positivi "
                "by-design, perciò qui restano a INFO (non gonfiano il posture score). "
                "Il dettaglio completo (incluso il match) è SOLO nel report locale "
                "raw/trivy.json (gitignored) — il valore del secret NON è incluso qui (P8)."
            ),
            remediation_ref=rule_id,
            intrusion_used=IntrusionLevel.PROBE,
        )

    # ── helper: Finding INFO SKIPPED (§14/§26) ──────────────────────────────

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Costruisce il Finding INFO `TRIVY_SKIPPED` (§14/§26): rende lo skip
        ESPLICITO nel report (onestà §4.7), invece di tacere. Severità INFO,
        confidence FIRM, intrusion READ_ONLY (nessuna azione eseguita)."""
        location = Location(endpoint="trivy")
        fid = _finding_id("trivy", "TRIVY_SKIPPED", location)
        finding = Finding(
            finding_id=fid,
            module="trivy",
            rule_id="TRIVY_SKIPPED",
            title="Scansione trivy saltata",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=motivo,
            description=(
                f"La scansione trivy (§14) è stata saltata: {motivo} "
                "Lo skip è dichiarato esplicitamente (non nascosto, §4.7/§26): "
                "questa verifica NON è stata eseguita."
            ),
            intrusion_used=IntrusionLevel.READ_ONLY,
        )
        return ModuleResult(findings=[finding], posture_checks=[])
