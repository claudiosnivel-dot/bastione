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
- `ReverifyScope` (S16, R6): un finding sparito dalla run è FIXED solo se la run
  poteva RI-OSSERVARLO (modulo eseguito senza errori/skip, livello d'intrusione
  sufficiente). Altrimenti è "non ri-verificato": resta aperto, mai dato per chiuso.

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

from bastione.enums import Confidence, IntrusionLevel, Severity, Status
from bastione.models import Finding, Location, PostureCheck
from bastione.state import empty_counts, intrusion_to_cli

log = logging.getLogger("bastione.baseline")

# Stati ereditabili dalla baseline (§16): un finding già visto può essere
# `known` (riconosciuto, ancora aperto) o `accepted` (rumore noto silenziato).
_INHERITABLE = {Status.KNOWN, Status.ACCEPTED}

# Livello d'intrusione salvato in baseline (stringa CLI, §25) → IntrusionLevel.
_CLI_TO_INTRUSION = {intrusion_to_cli(level): level for level in IntrusionLevel}

# Limiti dichiarati da una run (S16, R6). Un modulo che emette MODULE_ERROR,
# `*_SKIPPED` o `*_NOT_FOUND` non ha verificato nulla; `*_NOT_VERIFIABLE`,
# `*_NOT_READABLE` e `*_NOT_ENUMERABLE` dicono QUALE asset (o famiglia di asset,
# endpoint che finisce con "/") non è stato verificato; l'infisso `_SKIPPED_`
# (CANARY_SKIPPED_NO_SCHEMA, IDOR_WRITE_SKIPPED_NO_CANARY) = test di scrittura saltato.
_MODULE_NOT_RUN_SUFFIXES = ("_SKIPPED", "_NOT_FOUND")
_ASSET_LIMIT_SUFFIXES = ("_NOT_VERIFIABLE", "_NOT_READABLE", "_NOT_ENUMERABLE")
_WRITE_SKIPPED_INFIX = "_SKIPPED_"

# Baseline scritte prima di S16 (senza `intrusion_used`): livello dedotto dal tipo di
# controllo, mai un READ_ONLY concesso alla cieca a un controllo attivo.
_LEGACY_MUTATING_RULES = ("RLS_WRITE_OPEN", "CANARY_", "IDOR_CROSS_TENANT_WRITE",
                          "IDOR_CLEANUP", "IDOR_WRITE")
_LEGACY_PROBE_RULES = ("STORAGE_", "RPC_", "SUPABASE_GRAPHQL_", "IDOR_")
# Famiglie d'endpoint salvate in chiaro in baseline: solo quelle generiche di
# Supabase (le uniche usate dai limiti). Altrove la "famiglia" può contenere URL o
# id reali (es. /api/users/1234/) → stringa vuota.
_KNOWN_FAMILIES = frozenset({"/rest/v1/", "/rest/v1/rpc/", "/storage/v1/object/list/",
                             "/auth/v1/", "/graphql/"})

_LEGACY_LEVEL_BY_MODULE = {
    "zap_active": IntrusionLevel.MUTATING,
    "server_exposure": IntrusionLevel.PROBE, "login_hardening": IntrusionLevel.PROBE,
    "nuclei": IntrusionLevel.PROBE, "zap": IntrusionLevel.PROBE,
    "semgrep": IntrusionLevel.PROBE, "trivy": IntrusionLevel.PROBE,
}


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


# ─── promozione selettiva KNOWN→ACCEPTED (gradino 2, §16 riga 599) ───────────

def accept_finding(baseline: dict, finding_id: str) -> bool:
    """Promozione *selettiva e deliberata* di UN finding a `accepted` (§16, gradino
    2). Imposta `status="accepted"` per quel solo `finding_id` nella baseline.

    Funzione PURA: muta il dict in-place e ritorna un esito booleano, **senza I/O**
    (load/save restano a carico del chiamante CLI). Idempotente:

    - `finding_id` assente in baseline → ritorna `False` (niente da promuovere);
    - già `accepted` → no-op, ritorna `True` (idempotente);
    - altrimenti → status portato a `accepted`, ritorna `True`.

    Non tocca nessun altro finding: la promozione è puntuale (L05 — il file resta
    solo id/status/date/rule_id/module + esito posture, mai evidenze).
    """
    findings = baseline.get("findings") if isinstance(baseline, dict) else None
    if not isinstance(findings, dict) or finding_id not in findings:
        return False
    entry = findings[finding_id]
    if not isinstance(entry, dict):
        return False
    entry["status"] = Status.ACCEPTED.value
    return True


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
    # S16 (R6): in baseline, non visti ora, ma la run NON poteva ri-osservarli →
    # restano aperti (status ereditato), non sono FIXED. Gusci come i FIXED.
    not_reverified: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class VerifyLimit:
    """Un limite dichiarato dalla run (S16): il modulo `module` NON ha verificato
    l'endpoint `endpoint` ("" = tutto il modulo; finale "/" = l'intera famiglia,
    es. "/rest/v1/"; altrimenti l'asset esatto) per i controlli di livello
    ≥ `min_level`. `rule_id` serve solo a spiegarlo nel report."""

    module: str
    endpoint: str
    min_level: IntrusionLevel
    rule_id: str


@dataclass(frozen=True)
class ReverifyScope:
    """Ciò che la run corrente ha potuto RI-VERIFICARE (S16, R6 / Missione §5).

    - `max_intrusion`: tetto della run. Un finding trovato a PROBE/MUTATING non può
      sparire per merito di una run READ_ONLY (es. `verify`): quei controlli non
      sono nemmeno partiti.
    - `modules_ok`: moduli eseguiti senza `MODULE_ERROR` né `*_SKIPPED`. Se il modulo
      che aveva trovato il problema non ha girato (recon fallito, tool assente,
      eccezione), l'assenza del finding non prova nulla."""

    max_intrusion: IntrusionLevel
    modules_ok: frozenset[str]
    limits: tuple[VerifyLimit, ...] = ()
    # hash dei check_id dei PostureCheck PASSATI in questa run (prove positive).
    passed_proofs: frozenset[str] = frozenset()


def _strip_fragment(endpoint: str | None) -> str:
    return (endpoint or "").split("#", 1)[0]


def _endpoint_family(endpoint: str) -> str:
    """"/rest/v1/clienti" → "/rest/v1/": la famiglia, senza il nome dell'asset. Solo
    le famiglie note (`_KNOWN_FAMILIES`) finiscono in chiaro, le altre → ""."""
    if "/" not in endpoint:
        return ""
    family = endpoint.rsplit("/", 1)[0] + "/"
    return family if family in _KNOWN_FAMILIES else ""


def _proof_hash(check_id: str) -> str:
    return sha256(f"proof|{check_id}".encode()).hexdigest()[:16]


def proof_keys(verified_by: str | None) -> dict[str, str]:
    """Chiave della prova positiva (S16) da salvare in baseline: hash del check_id
    (che contiene il nome dell'asset), mai il check_id in chiaro."""
    return {"proof_key": _proof_hash(verified_by)} if verified_by else {}


def _endpoint_hash(module: str, endpoint: str) -> str:
    return sha256(f"{module}|{endpoint}".encode()).hexdigest()[:16]


def endpoint_keys(module: str, endpoint: str | None) -> dict[str, str]:
    """Chiavi d'endpoint salvate in baseline (S16) per collegare un finding ai
    limiti di una run futura. La baseline è committata: l'asset (tabella, bucket,
    RPC) NON compare in chiaro, solo la famiglia generica e un hash."""
    ep = _strip_fragment(endpoint)
    return {"endpoint_family": _endpoint_family(ep),
            "endpoint_key": _endpoint_hash(module, ep)}


def observation_level(finding: Finding) -> IntrusionLevel:
    """Livello minimo con cui il finding si ri-osserva (S16). Per i segreti la
    RILEVAZIONE è READ_ONLY anche quando la liveness (PROBE) l'ha arricchita: un
    segreto rimosso si chiude con un verify di default."""
    if finding.module == "secrets":
        return IntrusionLevel.READ_ONLY
    return finding.intrusion_used


def reverify_scope_from_run(
    max_intrusion: IntrusionLevel,
    planned_modules,
    findings: list[Finding],
    posture_checks: list[PostureCheck] | None = None,
) -> ReverifyScope:
    """Costruisce lo scope di ri-verifica dai moduli pianificati e dai finding-limite
    emessi dalla run (funzione pura, usata dall'orchestratore in BASELINE)."""
    not_done: set[str] = set()
    limits: list[VerifyLimit] = []
    for f in findings:
        rule = f.rule_id
        if rule == "MODULE_ERROR" or rule.endswith(_MODULE_NOT_RUN_SUFFIXES):
            not_done.add(f.module)
        elif _WRITE_SKIPPED_INFIX in rule:
            limits.append(VerifyLimit(f.module, "", IntrusionLevel.MUTATING, rule))
        elif rule.endswith(_ASSET_LIMIT_SUFFIXES):
            limits.append(VerifyLimit(
                f.module, _strip_fragment(f.location.endpoint), f.intrusion_used, rule))
    return ReverifyScope(
        max_intrusion=max_intrusion,
        modules_ok=frozenset(planned_modules) - not_done,
        limits=tuple(limits),
        passed_proofs=frozenset(_proof_hash(c.check_id)
                                for c in (posture_checks or []) if c.passed),
    )


def _limit_covers(limit: VerifyLimit, entry: dict) -> bool:
    """Il limite copre l'entry? "" = tutto il modulo; finale "/" = gli asset di
    QUELLA famiglia (non la radice stessa né altre famiglie: un limite ricorrente non
    deve bloccare per sempre finding che la run ri-osserva); altrimenti l'asset
    esatto. Entry senza chiavi (pre-S16): solo i limiti di modulo."""
    if not limit.endpoint:
        return True
    key = entry.get("endpoint_key")
    if not isinstance(key, str):
        return False
    if limit.endpoint.endswith("/"):
        return (entry.get("endpoint_family") == limit.endpoint
                and key != _endpoint_hash(limit.module, limit.endpoint))
    return key == _endpoint_hash(limit.module, limit.endpoint)


def _legacy_level(module: object, rule_id: object) -> IntrusionLevel:
    rule = rule_id if isinstance(rule_id, str) else ""
    if rule.startswith(_LEGACY_MUTATING_RULES):
        return IntrusionLevel.MUTATING
    if isinstance(module, str) and module in _LEGACY_LEVEL_BY_MODULE:
        return _LEGACY_LEVEL_BY_MODULE[module]
    if rule.startswith(_LEGACY_PROBE_RULES):
        return IntrusionLevel.PROBE
    return IntrusionLevel.READ_ONLY


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
    scope: ReverifyScope | None = None,
) -> BaselineResult:
    """Diff dei finding e dei posture check contro la baseline (§16).

    Finding (per ciascuno, calcolato `finding_id` stabile):
    - assente in baseline → `status=NEW`, `first_seen=last_seen=now`;
    - presente in baseline → eredita `first_seen` e lo `status` (`known`/`accepted`),
      `last_seen=now`;
    - in baseline ma NON nella run → emesso come `FIXED` (`fixed`), `first_seen`
      preservato, `last_seen=now`. Con uno `scope` (S16), SOLO se la run poteva
      ri-osservarlo; altrimenti va in `not_reverified` (status ereditato,
      `last_seen` invariato). Senza `scope` vale il comportamento storico.

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
    # ...solo se la run poteva ri-osservarlo (S16, R6): altrimenti l'assenza non
    # prova la correzione e il finding resta aperto come "non ri-verificato".
    for fid, prior in bl_findings.items():
        if fid in seen_ids:
            continue
        reason = _not_reverifiable_reason(prior, scope) if scope is not None else None
        if reason is not None:
            result.not_reverified.append(
                _make_not_reverified_finding(fid, prior, baseline, reason, now))
            counts["not_reverified"] += 1
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


def _not_reverifiable_reason(prior: object, scope: ReverifyScope) -> str | None:
    """Motivo per cui la run NON ha potuto ri-osservare il finding di baseline, o
    None se poteva (→ FIXED legittimo). Conservativo (R6): un livello d'intrusione
    illeggibile non concede il FIXED.

    Compatibilità: le baseline scritte prima di S16 non hanno `intrusion_used` →
    livello dedotto dal tipo di controllo (`_legacy_level`); senza `module` non si
    può verificare il modulo → si salta quel controllo."""
    entry = prior if isinstance(prior, dict) else {}
    raw_level = entry.get("intrusion_used")
    if raw_level is None:
        level = _legacy_level(entry.get("module"), entry.get("rule_id"))
    else:
        level = _CLI_TO_INTRUSION.get(str(raw_level).strip().lower())
        if level is None:
            shown = str(raw_level)[:20]
            return f"livello d'intrusione in baseline non riconosciuto ('{shown}')"
    if level > scope.max_intrusion:
        return (f"era stato trovato a livello '{intrusion_to_cli(level)}', la run "
                f"corrente si è fermata a '{intrusion_to_cli(scope.max_intrusion)}' "
                f"(rilancia con --max-intrusion {intrusion_to_cli(level)})")
    module = entry.get("module")
    if isinstance(module, str) and module and module not in scope.modules_ok:
        return (f"il modulo '{module}' non ha completato la verifica in questa run "
                "(non selezionato, saltato o in errore)")
    for limit in scope.limits:
        if limit.module == module and level >= limit.min_level and _limit_covers(limit, entry):
            return (f"la run ha dichiarato un limite di verifica ({limit.rule_id}) "
                    "sullo stesso controllo")
    proof = entry.get("proof_key")
    if isinstance(proof, str) and proof not in scope.passed_proofs:
        return ("nessuna prova positiva della correzione in questa run: il controllo "
                "che la conferma non è stato eseguito o non è passato")
    return None


def _make_not_reverified_finding(
    fid: str, prior: object, baseline: dict, reason: str, now: datetime,
) -> Finding:
    """Guscio di un finding in baseline che la run NON ha potuto ri-osservare
    (S16). Come per i FIXED la baseline non ha i dettagli (L05): si conservano id,
    modulo, rule_id, date e lo status ereditato (resta aperto). `last_seen` NON
    avanza: il problema non è stato visto ora, ma nemmeno escluso."""
    entry = prior if isinstance(prior, dict) else {}
    rule_id = entry.get("rule_id") if isinstance(entry.get("rule_id"), str) else None
    module = entry.get("module") if isinstance(entry.get("module"), str) else None
    first_seen = _parse_dt(entry.get("first_seen")) or now
    last_seen = _parse_dt(entry.get("last_seen")) or first_seen
    return Finding(
        finding_id=fid,
        module=module or "(baseline)",
        rule_id=rule_id or "(non ri-verificato)",
        title="Finding non ri-verificato in questa run",
        severity=Severity.INFO,
        confidence=Confidence.TENTATIVE,
        target=baseline.get("target", "") if isinstance(baseline, dict) else "",
        location=Location(),
        evidence="",                       # mai evidenze in baseline (L05)
        description=(
            f"Presente in baseline ({rule_id or 'rule_id ignoto'}) ma NON "
            f"ri-verificato: {reason}. Resta aperto finché una run in grado di "
            "ri-controllarlo non lo conferma risolto (R6: mai un FIXED non "
            "verificato)."),
        first_seen=first_seen,
        last_seen=last_seen,
        status=_inherited_status(entry.get("status")),
    )


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
