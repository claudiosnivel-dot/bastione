"""Contratti dati universali (§5 del blueprint).

Ogni modulo *produce* `Finding` e/o `PostureCheck`; nessun modulo inventa il
proprio formato. Tutte le classi sono `pydantic.BaseModel` (L03), salvo
`ModuleResult` che è una `NamedTuple` (valore di ritorno di `Module.run`, §9).

NB di scopo M0: questo file copre §5.2–§5.6. I contratti dell'Agent Remediation
Bundle (`FixEntry`/`FixPlan`, §18-bis.3) sono M1 e ora sono aggiunti in coda, nella
loro sezione dedicata (§18-bis.3).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal, NamedTuple

from pydantic import BaseModel, Field, field_validator

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
    # Path API applicativi (`/api/...`) referenziati nei bundle same-host (M4.0).
    # Assist alla scoperta della superficie autenticata; la ground truth sono gli
    # endpoint dichiarati in [auth] (§5/§15). Default [] → backward-compatible.
    discovered_api_paths: list[str] = []
    cloudflare_fronted: bool = False
    endpoints: list[str] = []
    response_headers: dict[str, str] = {}


class SurfaceSnapshot(BaseModel):      # contratto persistito dell'attack-surface inventory (M3)
    schema_name: str = Field(default="bastione-surface/1", alias="schema")
    target: str
    taken_at: datetime | None = None
    tables: list[str] = []
    endpoints: list[str] = []
    urls: list[str] = []
    snapshot_id: str = ""

    model_config = {"populate_by_name": True}

    @classmethod
    def build(
        cls,
        target: str,
        tables: list[str],
        endpoints: list[str],
        urls: list[str],
        taken_at: datetime | None = None,
    ) -> "SurfaceSnapshot":
        """Costruisce uno snapshot ordinando e deduplicando le liste, poi calcola
        lo snapshot_id deterministico: stesso contenuto → stesso id, a prescindere
        dall'ordine di input."""
        t = sorted(set(tables))
        e = sorted(set(endpoints))
        u = sorted(set(urls))
        # Payload JSON *strutturato* per categoria, non un flat "\n".join(t+e+u):
        # il naive flat-join appiattiva le tre liste senza delimitatore di
        # categoria, così superfici diverse ma con lo stesso insieme totale di
        # stringhe collidevano (es. tables=['a','b'] vs tables=['a'],endpoints=['b']),
        # e un valore contenente '\n' collideva con due valori separati
        # (tables=['a\nb'] vs tables=['a','b']). Il JSON dà un confine inequivocabile
        # tra categorie e fa l'escape dei newline nei valori, eliminando entrambe le
        # collisioni; vedi i test di regressione in tests/test_surface.py.
        payload = json.dumps(
            {"tables": t, "endpoints": e, "urls": u},
            separators=(",", ":"),
        )
        sid = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return cls(target=target, taken_at=taken_at, tables=t, endpoints=e, urls=u,
                   snapshot_id=sid)


class SurfaceDiff(BaseModel):          # delta tra due SurfaceSnapshot (M3)
    target: str
    added_tables: list[str] = []
    removed_tables: list[str] = []
    added_endpoints: list[str] = []
    removed_endpoints: list[str] = []
    added_urls: list[str] = []
    removed_urls: list[str] = []
    unchanged: bool


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


class TestAccount(BaseModel):          # M4.0 — un account di test per il probe autenticato
    __test__ = False                   # non è una test-class pytest (il prefisso "Test" è casuale)
    label: str                         # es. "A", "B"
    mode: Literal["token", "login_post"]
    # mode="token": il token è in una env var (mai nel TOML), P8
    token_env: str | None = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "      # "" per cookie/raw
    # mode="login_post":
    login_url: str | None = None
    email: str | None = None
    password_env: str | None = None    # nome env var con la password (mai in chiaro)
    session_json_path: str | None = None  # chiave del JSON di risposta col token (es. "access_token")
    session_cookie: str | None = None  # nome del cookie di sessione (alternativa)


class ApiEndpoint(BaseModel):          # M4.0 — un endpoint dell'API applicativa
    method: str                        # GET/POST/PUT/PATCH/DELETE
    path_template: str                 # es. "/api/orders/{id}"
    kind: Literal["list", "read", "create", "update", "delete"]
    public: bool = False               # dichiarato pubblico-di-proposito → oracolo soppresso (§15)


class AuthConfig(BaseModel):           # M4.0 — sezione [auth] del TOML
    test_accounts: list[TestAccount] = []
    api_endpoints: list[ApiEndpoint] = []
    public_endpoints: list[str] = []   # path/prefissi pubblici-di-proposito (§15)


class AuthSession(BaseModel):          # M4.0 — sessione acquisita per un account
    account_label: str
    headers: dict[str, str] = Field(default_factory=dict, repr=False)   # P8: token fuori dal repr
    cookies: dict[str, str] = Field(default_factory=dict, repr=False)   # P8
    acquired_ok: bool = False


class ApiSurface(BaseModel):           # M4.0 — superficie API per il probe autenticato
    endpoints: list[ApiEndpoint] = []  # ground truth (dichiarati in [auth])
    extracted_paths: list[str] = []    # assist: path /api/... estratti dal bundle


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
    source_path: str | None = None     # path locale del sorgente (white-box: semgrep/trivy)
    auth: AuthConfig | None = None     # [auth] — modalità autenticata (M4.0)

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


# ─── 18-bis.3 Agent Remediation Bundle (M1) ────────────────────────────────
#
# Stessa conoscenza di remediation dei playbook umani (§18), in una resa
# *machine-consumable* per un agente di coding. La chiave di mapping resta il
# `rule_id`. Shape LOCKED (§18-bis.3): non cambiare i valori degli enum né i
# nomi dei campi — il bundle `fix/` (FIX-PLAN.md, fix-plan.json) è un contratto
# versionato (`schema_version="bastione-fixplan/1"`).

class FixType(str, Enum):
    """Categoria di fix — determina la *shape* di `FixEntry.instructions` (§18-bis.4)."""

    SQL_MIGRATION   = "sql_migration"     # artefatto letterale: file .sql pronto
    CONFIG_CHANGE   = "config_change"     # header/impostazione: valore letterale
    INFRA_CHANGE    = "infra_change"      # Cloudflare/DNS: valore letterale
    CODE_CHANGE     = "code_change"       # intent + hint: l'agente localizza nel repo
    SECRET_ROTATION = "secret_rotation"   # rotazione chiave: passo umano obbligatorio


class Applicability(str, Enum):
    """Chi può applicare il fix end-to-end (§18-bis.3)."""

    AGENT       = "agent"          # un agente di coding lo applica end-to-end
    HUMAN       = "human"          # richiede una console/dashboard del provider
    AGENT_HUMAN = "agent+human"    # l'agente prepara, l'umano completa (o viceversa)


class Verification(BaseModel):
    """Criterio di accettazione di un fix: si chiude solo con un re-scan (§18-bis.8)."""

    method: str = "bastione-rescan"
    command: str                    # es. "bastione verify --target gestionale"
    expect: str                     # es. "finding 7f3a…e1 → FIXED"


class FixEntry(BaseModel):
    """Una singola voce del piano di remediation per l'agente (§18-bis.3).

    `finding_id` è lo stesso id stabile del `Finding` (§16): chiude il loop tra
    "ecco il bug" e "ecco la patch + la prova che è chiusa". La shape di
    `instructions` dipende da `fix_type` (§18-bis.4, LOCKED).
    """

    finding_id: str                 # stesso id stabile del Finding (§16) — chiude il loop
    rule_id: str
    severity: Severity
    title: str
    fix_type: FixType
    applicable_by: Applicability
    priority: int                   # 1 = primo. secret_rotation è SEMPRE 1 (§18-bis.5).
    depends_on: list[str] = []      # finding_id da risolvere prima (es. ruota PRIMA di ripulire)
    context: dict                   # {resource, endpoint, file, evidence_redacted}
    instructions: dict              # shape dipende da fix_type (§18-bis.4)
    verification: Verification


class FixPlan(BaseModel):
    """Il piano di remediation completo, serializzato in `fix-plan.json` (§18-bis.3).

    `fixes` è ordinato per priority crescente, poi severity decrescente
    (§18-bis.4). `summary` riassume i conteggi (§18-bis.6).
    """

    schema_version: str = "bastione-fixplan/1"
    target: str
    generated_at: datetime
    run_dir: str
    summary: dict                   # {total, agent_applicable, human_required, by_severity}
    fixes: list[FixEntry]           # ordinati per priority, poi severity
