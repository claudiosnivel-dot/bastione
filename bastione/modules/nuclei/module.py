"""NucleiModule — colla sottile attorno a nuclei (§14 del blueprint). PROBE 🟡.

nuclei (projectdiscovery) è uno scanner template-based maturo. Bastione NON
reimplementa la detection: gli mette intorno la colla canonica (§14):

  1. **self-gate + which** — il modulo gira SOLO se il tetto della run è ≥ PROBE
     E l'ownership è verificata; in più chiama `gate.authorize(PROBE, ctx)` come
     backstop (difesa in profondità §7). Sotto read-only → Finding INFO `SKIPPED`
     e prosegue, NESSUN authorize, NESSUN subprocess (comportamento M0 invariato).
     Se il binario manca (`shutil.which("nuclei") is None`) → Finding INFO
     `SKIPPED` ONESTO: il report DICHIARA lo skip, non lo nasconde (§4.7/§26).
  2. **invocazione** — argv-list (mai shell=True, niente interpolazione di shell
     dell'URL → niente command injection §14), template passive/safe selezionati
     con filtri RESTRITTIVI (`-exclude-tags intrusive,dos,fuzz,attack,...` +
     `-severity info,low,medium`, non il solo `-include-tags safe` che è additivo).
     Gli active templates sono MUTATING e NON girano qui (restano M2/gated §14).
     Output JSONL in `ctx.run_dir/raw/nuclei.jsonl` (struttura repo normativa §4).
  3. **parse + normalize** — ogni record JSONL → Finding (rule_id = template-id;
     severity mappata info/low/medium/high/critical → Severity; location = URL
     matchato; confidence FIRM; intrusion_used=PROBE). Dedup via finding_id (§16).

Resilienza (§4.7): binario assente → SKIPPED; riga malformata → saltata, niente
crash; un confine I/O che fallisce → degrada a [] (nessun finding) senza propagare.

Il confine di I/O è la funzione modulo-livello `_run_nuclei(urls, out_path)`:
l'unica cosa monkeypatchata nei test (offline) — come per recon (§8) e gate (§7).
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

log = logging.getLogger("bastione.modules.nuclei")

_NUCLEI_TIMEOUT = 600  # secondi: una passive scan può richiedere tempo (§14)

# Mapping severità nuclei → Severity (§14). Case-insensitive; valore sconosciuto
# → INFO prudenziale (non gonfiamo lo score per una severità che non sappiamo
# mappare). nuclei usa esattamente questi cinque livelli nei suoi template.
_SEVERITY_MAP: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


# ─── confine I/O (monkeypatchato nei test) ──────────────────────────────────

def _run_nuclei(urls: list[str], out_path: str) -> list[str]:
    """Invoca nuclei in modalità passive/safe e ritorna le righe JSONL (§14).

    Subprocess SICURO: argv-list, mai shell=True — nessuna interpolazione di shell
    dell'URL (niente command injection §14). Scrive il JSONL anche su disco in
    `out_path` (`-jsonl-export`) per l'artefatto raw/, e lo legge da stdout.

    Template policy (§14): SOLO passive/safe. ATTENZIONE: `-include-tags` in nuclei
    è ADDITIVO (esegue ANCHE i template con quei tag, non SOLO quelli) → da solo NON
    è un guardrail anti-MUTATING. Il filtro RESTRITTIVO reale combina più flag:
      • `-exclude-tags intrusive,dos,fuzz,attack,sqli,xss,ssrf,rce,lfi` esclude i
        template che inviano payload crafted/attivi (la categoria MUTATING §14);
      • `-severity info,low,medium` mette un cap (gli exploit gravi sono high/critical);
      • `-include-tags safe` lascia comunque passare i template marcati safe.
    Così i template active/exploit NON girano qui (restano M2/gated §14). Niente
    `-headless` né exploit.

    Degrado grazioso (§4.7/L06): se il binario è sparito a runtime o l'esecuzione
    fallisce → [] (nessuna riga), mai un crash. Il chiamante ha già verificato
    `shutil.which`, ma qui restiamo difensivi."""
    argv = [
        "nuclei",
        "-jsonl",                    # output JSON-lines su stdout
        "-jsonl-export", out_path,   # artefatto raw/ su disco (§4)
        # Guardrail anti-MUTATING (§14): filtri RESTRITTIVI, non solo additivi.
        "-exclude-tags", "intrusive,dos,fuzz,attack,sqli,xss,ssrf,rce,lfi",
        "-severity", "info,low,medium",  # cap: niente exploit gravi (high/critical)
        "-include-tags", "safe",     # ammette i template marcati safe (additivo)
        "-disable-update-check",
        "-silent",
        "-no-color",
    ]
    for url in urls:
        argv += ["-target", url]     # URL come ARGOMENTO, mai concatenato in shell
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=_NUCLEI_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("nuclei: esecuzione fallita, degrado a nessun risultato: %s", exc)
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


# ─── helper: finding_id stabile (§16) ────────────────────────────────────────

def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, formula LOCKED):

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    Esclude `target` ed evidenza (allineato a baseline/diff.py:finding_id): stesso
    problema → stesso id tra run, abilitando dedup (§16) e drift."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_severity(raw: object) -> Severity:
    """Severità nuclei → Severity (§14). Case-insensitive; ignoto → INFO."""
    if isinstance(raw, str):
        return _SEVERITY_MAP.get(raw.strip().lower(), Severity.INFO)
    return Severity.INFO


# ─── il modulo (§9/§14) ──────────────────────────────────────────────────────

@register
class NucleiModule(Module):
    """Colla attorno a nuclei (§14): passive/safe templates, PROBE 🟡.

    should_run = True se il recon ha raggiunto almeno un URL (§14): senza
    resolved_urls non c'è nulla da scansionare. Il `which` NON si controlla qui
    (valutazione leggera, senza I/O): si controlla in run, così il report può
    DICHIARARE lo SKIPPED (§26)."""

    name = "nuclei"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """True se il fingerprint ha resolved_urls (§14). Valutazione leggera,
        nessun I/O: il which resta per la fase run (report onesto, §26)."""
        return bool(fp.resolved_urls)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Esegue nuclei passive (§14): self-gate → which → authorize backstop →
        invocazione argv-list → parse+normalize → Finding[] dedupati.

        Sotto read-only o senza ownership/binario, emette un singolo Finding INFO
        SKIPPED e prosegue (nessun authorize, nessun subprocess)."""
        target = ctx.target_cfg.name

        # (a) self-gate: niente PROBE sotto read-only o senza ownership (M0 identico).
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "nuclei richiede --max-intrusion >= probe e ownership verificata "
                "(§14): scansione saltata, run read-only invariata.",
            )

        # (b) which: binario assente → SKIPPED onesto (il report dichiara lo skip §26).
        if shutil.which("nuclei") is None:
            return self._skipped(
                target,
                "binario nuclei assente sul PATH (§14): scansione saltata. "
                "Installa nuclei (projectdiscovery) per abilitare i template passive.",
            )

        # (c) backstop del gate (§7): se nega, SKIPPED, niente crash, niente subprocess.
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            log.info("nuclei: PROBE negata dal gate, salto (§7): %s", exc)
            return self._skipped(
                target, f"PROBE negata dal gate (§7): {exc}")

        # (d) invocazione su confine I/O monkeypatchabile → JSONL in raw/.
        raw_dir = Path(ctx.run_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / "nuclei.jsonl"
        try:
            lines = _run_nuclei(list(ctx.fingerprint.resolved_urls), str(out_path))
        except Exception as exc:  # noqa: BLE001 — resilienza (§4.7): isola il fallimento
            log.warning("nuclei: invocazione fallita, nessun finding (§4.7): %s", exc)
            return ModuleResult(findings=[], posture_checks=[])

        # (e) parse + normalize → Finding[] dedupati per finding_id (§16).
        findings = self._parse(lines, target)
        log.info("nuclei: %d record → %d finding (dedupati) per %s",
                 len(lines), len(findings), target)
        return ModuleResult(findings=findings, posture_checks=[])

    # ── parse + normalize ───────────────────────────────────────────────────

    def _parse(self, lines: list[str], target: str) -> list[Finding]:
        """Parsa il JSONL di nuclei → Finding[] dedupati (§14/§16). Una riga
        malformata o senza template-id viene SALTATA, non crasha le altre (§4.7)."""
        deduped: dict[str, Finding] = {}
        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                log.debug("nuclei: riga non-JSON ignorata: %r", line[:80])
                continue
            finding = self._record_to_finding(record, target)
            if finding is None:
                continue
            # Primo vince (§16): stesso finding_id → stesso problema, niente duplicati.
            deduped.setdefault(finding.finding_id, finding)
        return list(deduped.values())

    def _record_to_finding(self, record: object, target: str) -> Finding | None:
        """Un record JSONL di nuclei → Finding, o None se non interpretabile (§14).

        rule_id = `template-id`; severity da `info.severity`; location = URL
        matchato (`matched-at`, fallback `host`). Evidence sintetica e NON segreta
        (P8): solo template-id + URL matchato, mai corpi di risposta."""
        if not isinstance(record, dict):
            return None
        template_id = record.get("template-id") or record.get("templateID")
        if not isinstance(template_id, str) or not template_id:
            log.debug("nuclei: record senza template-id, saltato")
            return None

        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        severity = _map_severity(info.get("severity"))
        name = info.get("name") if isinstance(info.get("name"), str) else template_id

        matched = (
            record.get("matched-at")
            or record.get("matched")
            or record.get("host")
            or ""
        )
        matched = matched if isinstance(matched, str) else ""

        location = Location(url=matched or None, endpoint=None)
        fid = _finding_id("nuclei", template_id, location)
        # Evidence NON segreta (P8): solo template-id + URL matchato, mai risposte.
        evidence = f"nuclei template '{template_id}' matched-at {matched}".rstrip()

        return Finding(
            finding_id=fid,
            module="nuclei",
            rule_id=template_id,
            title=f"nuclei: {name}",
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=(
                f"Il template nuclei '{template_id}' ({name}) ha prodotto un match "
                f"su {matched or 'target'} (severità {severity.name}). "
                "Rilevato da una scansione passive/safe (PROBE §14). "
                "Verifica il dettaglio nel report raw/nuclei.jsonl."
            ),
            remediation_ref=template_id,
            intrusion_used=IntrusionLevel.PROBE,
        )

    # ── helper: Finding INFO SKIPPED (§14/§26) ──────────────────────────────

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Costruisce il Finding INFO `NUCLEI_SKIPPED` (§14/§26): rende lo skip
        ESPLICITO nel report (onestà §4.7), invece di tacere. Severità INFO,
        confidence FIRM, intrusion READ_ONLY (nessuna azione eseguita)."""
        location = Location(endpoint="nuclei")
        fid = _finding_id("nuclei", "NUCLEI_SKIPPED", location)
        finding = Finding(
            finding_id=fid,
            module="nuclei",
            rule_id="NUCLEI_SKIPPED",
            title="Scansione nuclei saltata",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=motivo,
            description=(
                f"La scansione nuclei (§14) è stata saltata: {motivo} "
                "Lo skip è dichiarato esplicitamente (non nascosto, §4.7/§26): "
                "questa verifica NON è stata eseguita."
            ),
            intrusion_used=IntrusionLevel.READ_ONLY,
        )
        return ModuleResult(findings=[finding], posture_checks=[])
