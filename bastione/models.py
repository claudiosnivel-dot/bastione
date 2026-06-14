"""Contratti dati universali (§5 del blueprint).

Ogni modulo *produce* `Finding` e/o `PostureCheck`; nessun modulo inventa il
proprio formato. Tutte le classi sono `pydantic.BaseModel` (L03), salvo
`ModuleResult` che è una `NamedTuple` (valore di ritorno di `Module.run`, §9).

NB di scopo M0: questo file copre §5.2–§5.6. I contratti dell'Agent Remediation
Bundle (`FixEntry`/`FixPlan`, §18-bis.3) sono M1 e verranno aggiunti lì — non si
anticipano (P5).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal, NamedTuple

from pydantic import BaseModel, field_validator

from bastione.enums import (
    Confidence,
    IntrusionLevel,
    Severity,
    Status,
)

# "index-ab12cd.js" → "index.js": rimuove il suffisso content-hash dei bundle.
HASH_SEGMENT = re.compile(r"[-.][0-9a-f]{6,}(?=\.\w+$)", re.I)


# ─── 5.2 Location ──────────────────────────────────────────────────────────

class Location(BaseModel):
    url: str | None = None
    endpoint: str | None = None        # es. "/rest/v1/clienti"
    file: str | None = None            # es. "assets/index-ab12.js"
    line: int | None = None

    def canonical(self) -> str:
        # Usata per il finding_id stabile (§16). NON include evidenza.
        # Il campo file è normalizzato dai suffissi content-hash dei bundle:
        # senza, ogni deploy rinomina il bundle, cambia il finding_id e genera
        # falsi NEW/FIXED — minando P7 (solo delta).
        file_norm = HASH_SEGMENT.sub("", self.file) if self.file else None
        return "|".join(str(x) for x in (self.url, self.endpoint, file_norm, self.line))


# ─── 5.3 Finding (il contratto principale) ─────────────────────────────────

class Finding(BaseModel):
    finding_id: str                    # vedi §16 — hash stabile per dedup/drift
    module: str                        # es. "supabase", "secrets"
    rule_id: str                       # es. "RLS_DISABLED", "SECRET_SERVICE_ROLE"
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    location: Location
    evidence: str                      # SEMPRE redatto in output salvo --unsafe-show-secrets
    description: str
    remediation_ref: str | None = None  # chiave playbook (§18), es. "RLS_DISABLED"
    owasp: list[str] = []              # es. ["A01:2021","A05:2021"]
    gdpr_relevant: bool = False        # dati personali esposti? (rilevante per noi)
    cvss: float | None = None
    intrusion_used: IntrusionLevel = IntrusionLevel.READ_ONLY
    first_seen: datetime | None = None  # valorizzato in BASELINE
    last_seen: datetime | None = None
    status: Status = Status.NEW        # valorizzato in BASELINE


# ─── 5.4 PostureCheck (la verifica positiva — §17) ─────────────────────────

class PostureCheck(BaseModel):
    check_id: str                      # es. "POSTURE_HSTS", "POSTURE_SERVICE_ROLE_HIDDEN"
    title: str
    passed: bool
    severity_if_failed: Severity       # peso nel posture score
    target: str
    detail: str                        # cosa è stato verificato
    remediation_ref: str | None = None
    drift: bool = False                # True se in baseline era passed e ora è failed (§16) —
                                       # valorizzato in POSTURE; è qui che vive Status.DRIFT


# ─── 5.5 Supporto ──────────────────────────────────────────────────────────

class Fingerprint(BaseModel):          # output di RECON (§8)
    target: str
    resolved_urls: list[str]
    technologies: list[dict] = []      # [{"name","version","confidence"}]
    is_wordpress: bool = False
    is_supabase: bool = False          # PostgREST rilevato
    supabase_url: str | None = None
    anon_key: str | None = None        # pubblica per design, estratta dal bundle
    # Nomi tabella ricavati dai riferimenti `.from('...')` del client Supabase nei
    # bundle same-host (§8). Fallback per l'RLS test quando l'OpenAPI è chiusa (401,
    # §11.1). Default [] → backward-compatible e serializza in fingerprint.json.
    discovered_tables: list[str] = []
    cloudflare_fronted: bool = False
    endpoints: list[str] = []
    response_headers: dict[str, str] = {}


class TextAsset(BaseModel):            # input ai detector di segreti (§10)
    source: str                        # url o path del file
    content: str


class RawSecret(BaseModel):
    detector_id: str
    value: str                         # valore grezzo (redatto in output)
    location: Location
    entropy: float | None = None


class LivenessResult(BaseModel):
    alive: bool
    mode: str | None = None            # es. "live", "test", "revoked"
    detail: str = ""


class RunContext(BaseModel):           # passato a ogni modulo
    target_cfg: "TargetConfig"         # forward ref a §5.6 (risolto a fondo file)
    fingerprint: Fingerprint
    max_intrusion: IntrusionLevel      # tetto effettivo della run (§7)
    run_dir: Path
    ownership_verified: bool


# ─── 5.6 Config e aggregati ────────────────────────────────────────────────

class TableExpectation(BaseModel):     # [[expectations.table]] del TOML (§15)
    name: str
    anon_select: bool = False
    anon_insert: bool = False


class TargetConfig(BaseModel):         # prodotto da config.py: parse+validate del TOML (§29)
    name: str
    base_url: str
    environment: Literal["staging", "production"]
    ownership: Literal["owned", "authorized-written"]
    ownership_token: str | None = None  # richiesto solo per run > READ_ONLY (§7.1)
    supabase_url: str | None = None    # [supabase].url, opzionale (il recon può scoprirlo)
    notify_channel: str = "none"       # [notify].channel
    notify_min_severity: Severity = Severity.HIGH   # [notify].min_severity (--fail-on ha precedenza, §25)
    expectations: list[TableExpectation] = []       # §15 (M2)
    modules_disabled: list[str] = []   # [modules].disabled

    @field_validator("notify_min_severity", mode="before")
    @classmethod
    def _coerce_severity_name(cls, v: object) -> object:
        # Il TOML porta min_severity come nome ("high"); Severity è un IntEnum,
        # quindi mappiamo il nome (case-insensitive) prima della validazione.
        if isinstance(v, str):
            try:
                return Severity[v.strip().upper()]
            except KeyError as exc:
                raise ValueError(f"severità sconosciuta: {v!r}") from exc
        return v


class ModuleResult(NamedTuple):        # valore di ritorno di Module.run (§9)
    findings: list[Finding]
    posture_checks: list[PostureCheck]


class RunSummary(BaseModel):           # input dei Notifier (§19)
    target: str
    posture_score: float
    counts: dict                       # stessa shape di state.json (§24)
    drift_count: int
    report_path: str                   # link al report HTML


# RunContext referenzia TargetConfig in avanti (§5.5 prima di §5.6): ora che
# TargetConfig è definita, risolviamo il forward ref.
RunContext.model_rebuild()
