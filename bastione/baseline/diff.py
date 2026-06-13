"""Baseline & drift detection — il kernel di difesa (§16).

Risolve P7 ("solo delta") e abilita il monitoring (§20): dopo la prima baseline,
l'attenzione umana va solo su ciò che è `NEW` o `DRIFT`.

Pezzi:
- `finding_id(finding)`: id stabile (LOCKED, §16) che ESCLUDE l'evidenza, così lo
  stesso problema mantiene lo stesso id tra run anche se il testo cambia.
  `Location.canonical()` normalizza già i content-hash dei bundle (§5.2): senza,
  ogni deploy rinominerebbe `index-ab12.js` e lo stesso segreto produrrebbe un
  falso `NEW` + un falso `FIXED` ad ogni build.
- `load_baseline` / `save_baseline`: formato §16
  (`baselines/<target>.baseline.json`). Il file contiene SOLO id/status/date,
  **mai evidenze** (L05) — è ciò che lo rende committabile e abilita il diff in
  CI (§22).
- `apply_baseline`: il diff vero e proprio (fasi BASELINE + POSTURE, §6):
  arricchisce i finding con status/first_seen/last_seen, emette i FIXED, marca il
  DRIFT dei posture check e calcola i `counts` (shape §24).

Nessun I/O di rete qui: input puri (liste di Finding/PostureCheck + dict baseline)
→ output puro. Solo `load/save` toccano il filesystem (lettura/scrittura JSON).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from bastione.enums import Confidence, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.state import empty_counts

log = logging.getLogger("bastione.baseline")

# Stati ereditabili dalla baseline (§16): un finding già visto può essere
# `known` (riconosciuto, ancora aperto) o `accepted` (rumore noto silenziato).
_INHERITABLE = {Status.KNOWN, Status.ACCEPTED}


# ─── finding_id stabile (LOCKED, §16) ───────────────────────────────────────

def finding_id(finding: Finding) -> str:
    """Id stabile di un finding (§16). Formula LOCKED:

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    ESCLUDE l'evidenza apposta (tracciabilità nel tempo) e si appoggia a
    `Location.canonical()` che normalizza i content-hash dei bundle (§5.2).
    """
    raw = f"{finding.module}:{finding.rule_id}:{finding.location.canonical()}"
    return sha256(raw.encode()).hexdigest()[:16]


# ─── formato baseline §16 ───────────────────────────────────────────────────

def _empty_baseline(target: str = "") -> dict:
    """Struttura baseline vuota (§16): nessun finding, nessun posture noto."""
    return {"target": target, "updated_at": None, "findings": {}, "posture": {}}


def load_baseline(path: str | Path) -> dict:
    """Carica `baselines/<target>.baseline.json` (§16). Se il file non esiste
    ritorna una struttura vuota (prima run: ogni finding sarà NEW). Degrada a
    vuoto anche se il file è illeggibile/corrotto — non si crasha la pipeline
    per una baseline malformata (resilienza)."""
    path = Path(path)
    if not path.exists():
        return _empty_baseline()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("baseline %s illeggibile (%s): la tratto come vuota", path, exc)
        return _empty_baseline()
    # Difesa: garantiamo sempre le chiavi attese, qualunque cosa contenga il file.
    base = _empty_baseline(data.get("target", "") if isinstance(data, dict) else "")
    if isinstance(data, dict):
        base["updated_at"] = data.get("updated_at")
        if isinstance(data.get("findings"), dict):
            base["findings"] = data["findings"]
        if isinstance(data.get("posture"), dict):
            base["posture"] = data["posture"]
    return base


def save_baseline(
    path: str | Path,
    *,
    target: str,
    findings: dict,
    posture: dict,
    updated_at: datetime | None = None,
) -> Path:
    """Scrive la baseline (§16) come JSON. Il formato contiene SOLO id/status/date
    e l'esito booleano dei posture check: **mai evidenze** (L05), per restare
    committabile e abilitare il diff in CI (§22)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "target": target,
        "updated_at": (updated_at.isoformat() if updated_at else None),
        "findings": findings,
        "posture": posture,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ─── risultato del diff ─────────────────────────────────────────────────────

@dataclass
class BaselineResult:
    """Esito di `apply_baseline` (output delle fasi BASELINE + POSTURE, §6).

    - `findings`: i finding *emessi* nella run, arricchiti (finding_id, status,
      first_seen/last_seen). Esclude i FIXED.
    - `fixed`: finding presenti in baseline ma NON nella run (status FIXED) —
      positivo, da mostrare nel report come "risolto" (§16).
    - `posture_checks`: gli stessi in input, con `drift=True` dove regrediti.
    - `counts`: shape §24 (new/known/fixed/drift + by_severity dei finding emessi).
    """

    findings: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    posture_checks: list[PostureCheck] = field(default_factory=list)
    counts: dict = field(default_factory=empty_counts)


# ─── diff (fasi BASELINE + POSTURE, §16) ────────────────────────────────────

def _parse_dt(value: object) -> datetime | None:
    """ISO string → datetime; tollerante (None/errori → None)."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def apply_baseline(
    findings: list[Finding],
    posture_checks: list[PostureCheck],
    baseline: dict,
    *,
    now: datetime,
) -> BaselineResult:
    """Diff dei finding e dei posture check contro la baseline (§16).

    Finding (per ciascuno, calcolato `finding_id` stabile):
    - assente in baseline → `status=NEW`, `first_seen=last_seen=now`;
    - presente in baseline → eredita `first_seen` e lo `status` (`known`/`accepted`),
      `last_seen=now`;
    - in baseline ma NON nella run → emesso come `FIXED` (`fixed`), `first_seen`
      preservato, `last_seen=now`.

    Posture: `drift=True` dove in baseline era `passed:true` e ora è `false`.

    `counts` (§24): `new/known/fixed/drift` + `by_severity` dei *soli finding
    emessi* (esclusi i FIXED e i posture check).
    """
    bl_findings: dict = baseline.get("findings", {}) if isinstance(baseline, dict) else {}
    bl_posture: dict = baseline.get("posture", {}) if isinstance(baseline, dict) else {}

    result = BaselineResult()
    counts = empty_counts()
    seen_ids: set[str] = set()

    # ── finding presenti nella run ──────────────────────────────────────────
    for finding in findings:
        fid = finding_id(finding)
        seen_ids.add(fid)
        prior = bl_findings.get(fid)

        if prior is None:
            # Mai visto: NEW. first_seen e last_seen coincidono con "ora".
            finding.finding_id = fid
            finding.status = Status.NEW
            finding.first_seen = now
            finding.last_seen = now
            counts["new"] += 1
        else:
            # Già visto: eredita status (known/accepted) e first_seen.
            inherited = _inherited_status(prior.get("status"))
            finding.finding_id = fid
            finding.status = inherited
            finding.first_seen = _parse_dt(prior.get("first_seen")) or now
            finding.last_seen = now
            # Solo i KNOWN gonfiano counts.known: gli ACCEPTED sono rumore noto
            # silenziato (§16) e non vanno trattati come "aperti da rivedere".
            if inherited is Status.KNOWN:
                counts["known"] += 1

        # by_severity per OGNI emesso; new_by_severity solo per i NEW (gate CI §22).
        _bump_severity(counts, finding, new_only=finding.status is Status.NEW)
        result.findings.append(finding)

    # ── finding in baseline ma non più nella run → FIXED (§16) ──────────────
    for fid, prior in bl_findings.items():
        if fid in seen_ids:
            continue
        fixed = _make_fixed_finding(fid, prior, baseline, now)
        result.fixed.append(fixed)
        counts["fixed"] += 1

    # ── posture DRIFT: passed:true in baseline → false ora (§16) ────────────
    for check in posture_checks:
        prior = bl_posture.get(check.check_id)
        was_passed = bool(prior.get("passed")) if isinstance(prior, dict) else False
        check.drift = bool(was_passed and not check.passed)
        if check.drift:
            counts["drift"] += 1
        result.posture_checks.append(check)

    result.counts = counts
    return result


def _inherited_status(raw: object) -> Status:
    """Mappa lo status della baseline su `Status`. Default difensivo: `KNOWN`
    (presente in baseline, non accettato) se il valore è ignoto/assente."""
    if isinstance(raw, str):
        try:
            status = Status(raw)
        except ValueError:
            return Status.KNOWN
        if status in _INHERITABLE:
            return status
    return Status.KNOWN


def _make_fixed_finding(fid: str, prior: dict, baseline: dict, now: datetime) -> Finding:
    """Costruisce un Finding sintetico `FIXED` per un id sparito dalla run (§16).

    La baseline non conserva i dettagli del finding (solo id/status/date, L05):
    ricostruiamo un guscio minimo ma valido, sufficiente al report ("risolto") e
    ai counts. first_seen è preservato dalla baseline; last_seen = now.
    """
    first_seen = _parse_dt(prior.get("first_seen") if isinstance(prior, dict) else None)
    return Finding(
        finding_id=fid,
        module="(baseline)",
        rule_id="(fixed)",
        title="Finding risolto",
        severity=Severity.INFO,
        confidence=Confidence.FIRM,
        target=baseline.get("target", "") if isinstance(baseline, dict) else "",
        location=Location(),
        evidence="",                       # mai evidenze in baseline (L05)
        description="Presente in baseline ma non più riscontrato in questa run.",
        first_seen=first_seen or now,
        last_seen=now,
        status=Status.FIXED,
    )


def _bump_severity(counts: dict, finding: Finding, *, new_only: bool = False) -> None:
    """Incrementa il breakdown per severità di un finding *emesso* (§24). Conta i
    finding, non i posture check; i FIXED non passano di qui.

    `by_severity` raccoglie TUTTI gli emessi (NEW/KNOWN/ACCEPTED); con
    `new_only=True` aggiorna anche `new_by_severity`, lo specchio dei soli NEW su
    cui scatta il gate CI (§22)."""
    key = finding.severity.name.lower()
    if key in counts["by_severity"]:
        counts["by_severity"][key] += 1
    if new_only and key in counts["new_by_severity"]:
        counts["new_by_severity"][key] += 1
