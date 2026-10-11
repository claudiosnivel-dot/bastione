"""ZapModule — colla sottile attorno a OWASP ZAP (§14 del blueprint). PROBE 🟡.

ZAP è un proxy/scanner maturo. Bastione NON reimplementa la detection: gli mette
intorno la colla canonica (§14), in modalità **passive** (PROBE):

  1. **self-gate + which** — il modulo gira SOLO se il tetto della run è ≥ PROBE E
     l'ownership è verificata; in più chiama `gate.authorize(PROBE, ctx)` come
     backstop (§7). Sotto read-only → Finding INFO `SKIPPED` e prosegue, NESSUN
     authorize, NESSUN subprocess. Se il binario manca (`shutil.which` None) →
     Finding INFO `SKIPPED` ONESTO: il report DICHIARA lo skip (§4.7/§26).

  2. **invocazione documentata** — wrapper di `zap-baseline.py` (lo script ufficiale
     ZAP per la *passive baseline scan*: avvia un daemon ZAP, fa lo spider passivo
     del target e produce un report). Scelta del binario (LOCKED, documentata):
     usiamo **`zap-baseline.py`** perché è l'entrypoint passive headless ufficiale
     (vs `zap.sh`, che è la GUI/daemon generica). argv-list (mai shell=True →
     niente command injection §14), report JSON in `ctx.run_dir/raw/zap.json`:
     `-J` riceve il bare-name e si lancia con `cwd=run_dir/raw` (zap-baseline
     risolve `-J` rispetto alla sua working dir, non a un path assoluto), così
     scrittura e lettura del report coincidono e l'artefatto atterra in raw/.
     NESSUNA scansione active/attack: quella è MUTATING e resta M2/gated.

  3. **parse + normalize** — il report JSON ZAP (`{"site":[{"alerts":[...]}]}`) →
     Finding[] (rule_id = pluginid; severity dal `riskcode` 0/1/2/3 →
     Informational/Low/Medium/High, fallback sul testo `riskdesc`; location = URI
     dell'istanza). Dedup via finding_id (§16).

NOTA ambiente (ONESTÀ §26): ZAP NON è installato qui, quindi il path REALE
dominante è SKIPPED (binario assente). Implementiamo la COLLA completa (which/skip
+ invocazione documentata + parser del JSON), MA non simuliamo una scansione che
non può girare: la passive richiede un daemon ZAP attivo, e senza binario si salta
in modo trasparente.

Resilienza (§4.7): report malformato/None → niente crash, 0 finding; un alert
senza campi → saltato. Il confine di I/O è la funzione modulo-livello
`_run_zap(urls, out_path)`: l'unica cosa monkeypatchata nei test (offline).
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
from bastione.toolcheck import check_tool

log = logging.getLogger("bastione.modules.zap")

# Binario passive headless ufficiale (LOCKED, documentato sopra): zap-baseline.py.
_ZAP_BINARY = "zap-baseline.py"
_ZAP_TIMEOUT = 600  # secondi: la baseline avvia un daemon e fa lo spider passivo.

# Mapping ZAP riskcode → Severity (§14). ZAP usa 0=Informational, 1=Low, 2=Medium,
# 3=High; valore sconosciuto → INFO prudenziale (non gonfiamo lo score §17).
_RISKCODE_MAP: dict[str, Severity] = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

# Fallback testuale quando il riskcode manca: si legge il prefisso del `riskdesc`
# (es. "High (Medium)") → Severity. Case-insensitive.
_RISKDESC_MAP: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}


# ─── confine I/O (monkeypatchato nei test) ──────────────────────────────────

def _run_zap(urls: list[str], out_path: str) -> dict | None:
    """Invoca `zap-baseline.py` in passive baseline e ritorna il report JSON (§14).

    Subprocess SICURO: argv-list, mai shell=True — l'URL è un ARGOMENTO, mai
    concatenato in una stringa di shell (niente command injection §14). Il tool
    avvia un daemon ZAP, fa lo spider passivo del PRIMO URL del target e scrive il
    report JSON in `out_path` (`-J`); noi lo rileggiamo dal file.

    NESSUN flag active/attack (`-a` di zap-baseline è MUTATING e NON viene passato):
    qui solo passive (PROBE §14).

    Degrado grazioso (§4.7/L06): binario sparito a runtime / esecuzione fallita /
    report non leggibile → None, mai un crash. Il chiamante (run) ha già fatto il
    `which`, ma restiamo difensivi."""
    target = urls[0] if urls else ""
    out = Path(out_path)
    report_name = out.name
    # zap-baseline.py risolve `-J` come nome RELATIVO alla propria working dir (nel
    # container ufficiale /zap/wrk, nativamente la cwd del processo): NON onora un
    # path assoluto. Per far coincidere scrittura e lettura impostiamo cwd =
    # directory di out_path, così il tool scrive il bare-name DENTRO run_dir/raw/ e
    # il read-back qui sotto da `out` (= raw_dir/report_name) trova lo stesso file
    # (§4: l'artefatto raw atterra in run_dir/raw/). Senza questo, il report finiva
    # in una cwd inattesa e _run_zap ritornava sempre None → 0 finding silenziosi.
    raw_dir = out.parent
    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("zap: impossibile creare la dir di report (%s): %s", raw_dir, exc)
        return None
    argv = [
        _ZAP_BINARY,
        "-t", target,        # target come ARGOMENTO (mai shell)
        "-J", report_name,   # report JSON: bare-name risolto rispetto a cwd=raw_dir
        "-I",                # non fallire il processo sui warning (exit non-zero)
        # NB: nessun "-a" → niente active scan (resta passive = PROBE §14).
    ]
    try:
        subprocess.run(
            argv, capture_output=True, text=True,
            timeout=_ZAP_TIMEOUT, check=False, cwd=str(raw_dir))
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("zap: esecuzione fallita, degrado a nessun report (§4.7): %s", exc)
        return None
    # Rileggiamo il report JSON dallo STESSO path dove il tool lo ha scritto
    # (cwd=raw_dir + bare-name = out_path), garantendo l'allineamento I/O.
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("zap: report JSON non leggibile (%s): %s", out_path, exc)
        return None


# ─── helper: finding_id stabile (§16) ────────────────────────────────────────

def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, formula LOCKED):

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    Esclude `target` ed evidenza (allineato a baseline/diff.py:finding_id)."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_risk(alert: dict) -> Severity:
    """Rischio ZAP → Severity (§14).

    Il `riskcode` è la fonte AUTORITATIVA: se è presente e non vuoto lo si onora —
    un valore presente ma fuori 0/1/2/3 è anomalo (ZAP usa solo quei quattro) →
    INFO prudenziale, SENZA cadere sul testo `riskdesc` (che potrebbe disallinearsi
    dal codice). Solo quando il riskcode è ASSENTE/vuoto si ripiega sul prefisso
    testuale di `riskdesc` (es. "High (Medium)" → High). Ignoto in entrambi → INFO."""
    riskcode = alert.get("riskcode")
    if riskcode is not None and str(riskcode).strip() != "":
        # riskcode presente: è la fonte autoritativa (ignoto → INFO, niente fallback).
        return _RISKCODE_MAP.get(str(riskcode).strip(), Severity.INFO)
    # riskcode assente: fallback sul prefisso testuale di riskdesc.
    riskdesc = alert.get("riskdesc")
    if isinstance(riskdesc, str):
        prefix = riskdesc.split("(", 1)[0].strip().lower()
        if prefix in _RISKDESC_MAP:
            return _RISKDESC_MAP[prefix]
    return Severity.INFO


# ─── il modulo (§9/§14) ──────────────────────────────────────────────────────

@register
class ZapModule(Module):
    """Colla attorno a OWASP ZAP (§14): passive baseline scan, PROBE 🟡.

    should_run = True se il recon ha raggiunto almeno un URL (§14). Il `which` NON
    si controlla qui (valutazione leggera, senza I/O): si controlla in run, così
    il report può DICHIARARE lo SKIPPED (§26)."""

    name = "zap"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """True se il fingerprint ha resolved_urls (§14). Valutazione leggera,
        nessun I/O: il which resta per la fase run (report onesto, §26)."""
        return bool(fp.resolved_urls)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Esegue ZAP passive (§14): self-gate → which → toolcheck (R4, versione) →
        authorize backstop → invocazione argv-list → parse+normalize → Finding[] dedupati.

        Sotto read-only o senza ownership/binario/versione ammessa, emette un singolo
        Finding INFO SKIPPED e prosegue (nessun authorize, nessun subprocess, nessun
        daemon)."""
        target = ctx.target_cfg.name

        # (a) self-gate: niente PROBE sotto read-only o senza ownership (M0 identico).
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "ZAP passive richiede --max-intrusion >= probe e ownership "
                "verificata (§14): scansione saltata, run read-only invariata.",
            )

        # (b) which: binario assente → SKIPPED onesto (il path reale qui §26).
        if shutil.which(_ZAP_BINARY) is None:
            return self._skipped(
                target,
                f"binario {_ZAP_BINARY} assente sul PATH (§14): scansione saltata. "
                "Installa OWASP ZAP (passive baseline) per abilitare questo modulo.",
            )

        # (b-bis) gate di versione fail-closed (R4, §4.2/§4.7). Il binario è
        # `zap-baseline.py` (_ZAP_BINARY): senza policy in TOOL_POLICY `check_tool`
        # ritorna ok=True senza leggere la versione (no-op a costo zero), ma il gate
        # resta cablato e pronto per policy future.
        status = check_tool(_ZAP_BINARY)
        if not status.ok:
            return self._skipped(target, f"versione non ammessa (R4): {status.reason}")

        # (c) backstop del gate (§7): se nega, SKIPPED, niente crash, niente subprocess.
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            log.info("zap: PROBE negata dal gate, salto (§7): %s", exc)
            return self._skipped(
                target, f"PROBE negata dal gate (§7): {exc}")

        # (d) invocazione su confine I/O monkeypatchabile → report JSON in raw/.
        raw_dir = Path(ctx.run_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / "zap.json"
        try:
            report = _run_zap(list(ctx.fingerprint.resolved_urls), str(out_path))
        except Exception as exc:  # noqa: BLE001 — resilienza (§4.7): isola il fallimento
            log.warning("zap: invocazione fallita, nessun finding (§4.7): %s", exc)
            return ModuleResult(findings=[], posture_checks=[])

        # (e) parse + normalize → Finding[] dedupati per finding_id (§16).
        findings = self._parse(report, target)
        log.info("zap: report → %d finding (dedupati) per %s", len(findings), target)
        return ModuleResult(findings=findings, posture_checks=[])

    # ── parse + normalize ───────────────────────────────────────────────────

    def _parse(self, report: object, target: str) -> list[Finding]:
        """Parsa il report JSON ZAP → Finding[] dedupati (§14/§16).

        Struttura attesa: `{"site": [{"alerts": [ {pluginid, riskcode, instances}
        ... ] } ... ]}`. Resiliente (§4.7): report None/non-dict/senza 'site' → [];
        un alert/istanza malformato → saltato senza fermare gli altri."""
        if not isinstance(report, dict):
            return []
        sites = report.get("site")
        if not isinstance(sites, list):
            return []

        deduped: dict[str, Finding] = {}
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                for finding in self._alert_to_findings(alert, target):
                    # Primo vince (§16): stesso finding_id → niente duplicati.
                    deduped.setdefault(finding.finding_id, finding)
        return list(deduped.values())

    def _alert_to_findings(self, alert: object, target: str) -> list[Finding]:
        """Un alert ZAP → un Finding per ogni `instance` (URI distinta) (§14).

        rule_id = `pluginid` (o `alertRef`); severity da `_map_risk`. Un alert senza
        pluginid o senza instances valide → [] (saltato, §4.7). Evidence NON segreta
        (P8): solo nome alert + URI, mai corpi di risposta."""
        if not isinstance(alert, dict):
            return []
        plugin_id = alert.get("pluginid") or alert.get("alertRef")
        if plugin_id is None or str(plugin_id) == "":
            log.debug("zap: alert senza pluginid, saltato")
            return []
        rule_id = str(plugin_id)
        name = alert.get("name") or alert.get("alert") or rule_id
        severity = _map_risk(alert)

        instances = alert.get("instances")
        # Senza instances esplicite, l'alert non ha un URI: lo saltiamo (serve una
        # location per il finding_id stabile §16).
        if not isinstance(instances, list) or not instances:
            log.debug("zap: alert %s senza instances, saltato", rule_id)
            return []

        findings: list[Finding] = []
        for inst in instances:
            if not isinstance(inst, dict):
                continue
            uri = inst.get("uri")
            uri = uri if isinstance(uri, str) and uri else ""
            location = Location(url=uri or None)
            fid = _finding_id("zap", rule_id, location)
            # Evidence NON segreta (P8): nome alert + URI, mai il corpo.
            evidence = f"ZAP alert '{name}' (pluginid {rule_id}) su {uri}".rstrip()
            findings.append(Finding(
                finding_id=fid,
                module="zap",
                rule_id=rule_id,
                title=f"ZAP: {name}",
                severity=severity,
                confidence=Confidence.FIRM,
                target=target,
                location=location,
                evidence=evidence,
                description=(
                    f"OWASP ZAP (passive baseline, PROBE §14) ha segnalato l'alert "
                    f"'{name}' (pluginid {rule_id}, severità {severity.name}) su "
                    f"{uri or 'target'}. Verifica il dettaglio in raw/zap.json."
                ),
                remediation_ref=rule_id,
                intrusion_used=IntrusionLevel.PROBE,
            ))
        return findings

    # ── helper: Finding INFO SKIPPED (§14/§26) ──────────────────────────────

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Costruisce il Finding INFO `ZAP_SKIPPED` (§14/§26): rende lo skip
        ESPLICITO nel report (onestà §4.7). Severità INFO, confidence FIRM,
        intrusion READ_ONLY (nessuna azione eseguita)."""
        location = Location(endpoint="zap")
        fid = _finding_id("zap", "ZAP_SKIPPED", location)
        finding = Finding(
            finding_id=fid,
            module="zap",
            rule_id="ZAP_SKIPPED",
            title="Scansione ZAP saltata",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=motivo,
            description=(
                f"La scansione OWASP ZAP passive (§14) è stata saltata: {motivo} "
                "Lo skip è dichiarato esplicitamente (non nascosto, §4.7/§26): "
                "questa verifica NON è stata eseguita."
            ),
            intrusion_used=IntrusionLevel.READ_ONLY,
        )
        return ModuleResult(findings=[finding], posture_checks=[])
