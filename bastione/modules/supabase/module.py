"""Modulo Supabase probe — la gemma (§11 del blueprint). Intrusione: READ_ONLY.

Il differenziatore di Bastione: nessuno scanner generico capisce PostgREST/RLS.
Qui sonderemo una istanza Supabase usando la **anon key** (pubblica per design,
§8/§11): esattamente come farebbe un esterno, ma in modo difensivo e read-only.

**SCOPE M0 (golden rule, §11.1):** SOLO due controlli, entrambi read-only:
  1. SURFACE MAP — `GET <supabase_url>/rest/v1/` ritorna lo schema OpenAPI di
     PostgREST: enumera tabelle/view (chiavi di `definitions`, o `paths` escluse
     le `/rpc/*`) e conta le RPC (path `/rpc/*`) — SENZA mai invocarle.
  2. RLS READ TEST (il controllo principe) — per OGNI tabella,
     `GET <supabase_url>/rest/v1/<tabella>?limit=1` con la anon key:
       - 200 con array NON vuoto → Finding `RLS_DISABLED` (RLS off o policy SELECT
         troppo permissiva). Severità LOCKED: `CRITICAL` + `gdpr_relevant=True` se
         i NOMI colonna suggeriscono dati personali (euristica §11.1), altrimenti
         `HIGH`. Evidence REDATTA (P8): mai i valori delle righe — solo conteggio
         e nomi colonna.
       - 200 vuoto / 401 / 403 → PostureCheck `POSTURE_RLS_<tabella>` passed.

NON anticipare §11.1.3–6 (storage, RPC-invocation, auth posture, service_role
hidden): sono M1/orchestratore. Le scritture canary (§11.2) sono M2 e qui restano
uno stub che solleva `NotImplementedError("M2")` — non si anticipano scritture.

Resilienza (P8): un confine I/O che fallisce o un singolo asset che esplode viene
saltato/loggato, non fa crashare il resto. Surface map irraggiungibile/non-JSON →
`ModuleResult` vuoto.

Il confine HTTP è la funzione modulo-livello `_get(url, headers)`: l'unica cosa
monkeypatchata nei test (probe offline) — come per il gate (§7) e il recon (§8).
"""

from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    PostureCheck,
    RunContext,
    TargetConfig,
)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.supabase")

_HTTP_TIMEOUT = 15.0

# Euristica dati personali (§11.1): se un NOME colonna contiene uno di questi
# token, la tabella è trattata come contenente dati personali → CRITICAL + GDPR.
# Confronto su sottostringa, case-insensitive (es. "user_email", "telefono_2").
_PERSONAL_DATA_HINTS: tuple[str, ...] = (
    "email",
    "nome",
    "name",          # copre anche "name"/"surname"/"username"
    "cognome",
    "telefono",
    "phone",
    "cellulare",
    "cf",
    "codice_fiscale",
    "fiscal",
    "indirizzo",
    "address",
    "iban",
    "carta",
    "card",
    "passport",
    "passaporto",
    "birth",
    "nascita",
    "ssn",
    "tax",
)


# ─── confine di I/O (monkeypatchato nei test) ───────────────────────────────

def _get(url: str, headers: dict[str, str]):
    """GET read-only via httpx-lib (redirect seguiti). Ritorna la response (con
    `.status_code` e `.json()`) o None se httpx manca o la richiesta fallisce.

    Degrado grazioso (L06): nessun crash se la dipendenza opzionale è assente o
    l'host è irraggiungibile — il modulo prosegue trattando il risultato come
    "non disponibile"."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: probe Supabase non disponibile (§11)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT,
                         follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("GET %s fallita: %s", url, exc)
        return None


# ─── funzioni pure (la gemma): nessuna I/O ──────────────────────────────────

def _is_personal_column(column: str) -> bool:
    """True se il NOME colonna suggerisce un dato personale (euristica §11.1).
    Lavora SOLO sul nome (mai sui valori — P8): match per sottostringa,
    case-insensitive."""
    low = column.lower()
    return any(hint in low for hint in _PERSONAL_DATA_HINTS)


def _has_personal_data(columns: list[str]) -> bool:
    """True se almeno una colonna della tabella è un dato personale (§11.1)."""
    return any(_is_personal_column(c) for c in columns)


def _enumerate_surface(schema: dict) -> tuple[dict[str, list[str]], int]:
    """Dalla schema OpenAPI di PostgREST estrae (tabelle→colonne, n_rpc).

    Tabelle/view: chiavi di `definitions` (PostgREST elenca lì ogni relazione con
    le sue `properties`=colonne). Fallback: dai `paths`, escludendo `/` e `/rpc/*`.
    Le RPC (`/rpc/<nome>`) sono SOLO conteggiate — MAI invocate in M0 (§11.1)."""
    tables: dict[str, list[str]] = {}
    definitions = schema.get("definitions")
    if isinstance(definitions, dict):
        for name, spec in definitions.items():
            props = spec.get("properties") if isinstance(spec, dict) else None
            cols = list(props.keys()) if isinstance(props, dict) else []
            tables[name] = cols

    paths = schema.get("paths")
    rpc_count = 0
    if isinstance(paths, dict):
        for path in paths:
            if not isinstance(path, str):
                continue
            stripped = path.strip("/")
            if not stripped:
                continue                      # la root "/"
            if stripped.startswith("rpc/"):
                rpc_count += 1                # conteggio RPC (mai invocate, §11.1)
                continue
            # fallback: se `definitions` mancava, deriva le tabelle dai paths
            if not definitions:
                tables.setdefault(stripped, [])

    return tables, rpc_count


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, LOCKED): sha256 di module:rule_id:location.canonical(),
    troncato a 16. Esclude l'evidenza apposta → stesso problema, stesso id tra run."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── il modulo (§9/§11) ─────────────────────────────────────────────────────

@register
class SupabaseModule(Module):
    """Sonda Supabase READ-ONLY (§11.1): surface map + RLS read test."""

    name = "supabase"
    max_intrusion = IntrusionLevel.READ_ONLY

    # ── selezione (§9) ──────────────────────────────────────────────────────

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Gira solo se il recon ha rilevato Supabase E ha estratto la anon key
        (§9): senza anon key non c'è nulla da sondare come anonimo, senza
        is_supabase non è una superficie PostgREST."""
        return fp.is_supabase and fp.anon_key is not None

    # ── run (§11.1) — SOLO surface map + RLS read test ──────────────────────

    def run(self, ctx: RunContext) -> ModuleResult:
        findings: list[Finding] = []
        posture_checks: list[PostureCheck] = []

        supabase_url = ctx.fingerprint.supabase_url or ctx.target_cfg.supabase_url
        anon = ctx.fingerprint.anon_key
        if not supabase_url or not anon:
            # should_run dovrebbe averlo escluso; difesa in profondità (P8).
            log.warning("supabase_url o anon_key assenti: probe saltata (§11.1)")
            return ModuleResult(findings, posture_checks)

        base = supabase_url.rstrip("/")
        headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
        target = ctx.target_cfg.name

        # 1) SURFACE MAP — GET <supabase_url>/rest/v1/ → schema OpenAPI PostgREST.
        schema = self._fetch_surface(base, headers)
        if schema is None:
            # Resiliente: surface map fallita/non-JSON → ModuleResult vuoto (§11.1).
            log.warning("surface map non disponibile: probe Supabase vuota (§11.1)")
            return ModuleResult(findings, posture_checks)

        tables, rpc_count = _enumerate_surface(schema)
        log.info("Supabase surface map: %d tabelle/view, %d RPC (non invocate, §11.1)",
                 len(tables), rpc_count)

        # 2) RLS READ TEST — per OGNI tabella, GET <url>/rest/v1/<tab>?limit=1.
        for table, columns in tables.items():
            try:
                self._rls_read_test(
                    base, headers, table, columns, supabase_url, target,
                    findings, posture_checks,
                )
            except Exception:  # noqa: BLE001 — resilienza (P8): un asset non blocca gli altri
                log.warning("RLS read test fallito per la tabella %r: saltata",
                            table, exc_info=True)

        return ModuleResult(findings, posture_checks)

    # ── passi interni ───────────────────────────────────────────────────────

    def _fetch_surface(self, base: str, headers: dict[str, str]) -> dict | None:
        """GET <base>/rest/v1/ → dict OpenAPI, o None se irraggiungibile/non-JSON.
        Resiliente: qualunque errore di rete o di parsing → None (§11.1)."""
        resp = _get(f"{base}/rest/v1/", headers)
        if resp is None:
            log.warning("surface map: nessuna risposta dalla root REST "
                        "(httpx assente o errore di rete) (§11.1)")
            return None
        status = getattr(resp, "status_code", None)
        if status != 200:
            log.warning("surface map: la root REST ha risposto status=%s "
                        "(l'anon non legge lo schema OpenAPI?) (§11.1)", status)
            return None
        try:
            schema = resp.json()
        except (ValueError, TypeError):
            log.warning("surface map: risposta non-JSON dalla root REST (§11.1)")
            return None
        return schema if isinstance(schema, dict) else None

    def _rls_read_test(
        self,
        base: str,
        headers: dict[str, str],
        table: str,
        columns: list[str],
        supabase_url: str,
        target: str,
        findings: list[Finding],
        posture_checks: list[PostureCheck],
    ) -> None:
        """RLS read test per UNA tabella (§11.1.2).

        - 200 con array NON vuoto → Finding `RLS_DISABLED` (severità per dati
          personali, evidence redatta).
        - 200 vuoto / 401 / 403 / altro → PostureCheck `POSTURE_RLS_<tabella>`
          passed (l'anon non legge → RLS sta proteggendo)."""
        endpoint = f"/rest/v1/{table}"
        resp = _get(f"{base}{endpoint}?limit=1", headers)

        rows = self._readable_rows(resp)
        if rows is not None and len(rows) > 0:
            findings.append(self._rls_disabled_finding(
                table, columns, rows, supabase_url, endpoint, target))
            return

        # protetto (vuoto / 401 / 403 / irraggiungibile) → posture positiva
        posture_checks.append(self._rls_protected_posture(table, target))

    @staticmethod
    def _readable_rows(resp) -> list | None:
        """Estrae l'array di righe leggibili da anon, o None se non leggibile.

        Solo `200` con corpo JSON-array è "leggibile": 401/403/altri status, corpo
        non-JSON o non-lista → None (tabella protetta o risposta non interpretabile).
        NB: i VALORI non vengono mai messi in evidence (P8); qui servono solo a
        contare le righe."""
        if resp is None or getattr(resp, "status_code", None) != 200:
            return None
        try:
            data = resp.json()
        except (ValueError, TypeError):
            return None
        return data if isinstance(data, list) else None

    @staticmethod
    def _rls_disabled_finding(
        table: str,
        columns: list[str],
        rows: list,
        supabase_url: str,
        endpoint: str,
        target: str,
    ) -> Finding:
        """Costruisce il Finding `RLS_DISABLED` (§11.1.2). Severità LOCKED e
        evidence REDATTA (P8): mai i valori delle righe, solo conteggio + colonne."""
        personal = _has_personal_data(columns)
        severity = Severity.CRITICAL if personal else Severity.HIGH

        # Evidence REDATTA (P8): SOLO conteggio righe + NOMI colonna — mai i valori.
        evidence = (
            f"{len(rows)} righe leggibili da anon; "
            f"colonne: {sorted(columns)}"
        )
        location = Location(endpoint=endpoint, url=supabase_url)
        title = (
            f"RLS disabilitata/permissiva sulla tabella '{table}'"
            + (" (dati personali esposti)" if personal else "")
        )
        description = (
            f"La GET anonima a {endpoint}?limit=1 ha restituito righe: l'anon key "
            f"legge la tabella '{table}'. RLS assente o policy SELECT troppo "
            f"permissiva (§11.1). "
            + (
                "I nomi colonna suggeriscono dati personali → severità CRITICAL e "
                "gdpr_relevant."
                if personal else
                "Nessun nome colonna riconducibile a dati personali → severità HIGH."
            )
        )
        return Finding(
            finding_id=_finding_id("supabase", "RLS_DISABLED", location),
            module="supabase",
            rule_id="RLS_DISABLED",
            title=title,
            severity=severity,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_DISABLED",
            owasp=["A01:2021"],
            gdpr_relevant=personal,
            intrusion_used=IntrusionLevel.READ_ONLY,
        )

    @staticmethod
    def _rls_protected_posture(table: str, target: str) -> PostureCheck:
        """Costruisce il PostureCheck positivo `POSTURE_RLS_<tabella>` (§11.1.2):
        l'anon NON legge la tabella → RLS sta proteggendo."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_{table}",
            title=f"RLS attiva sulla tabella '{table}'",
            passed=True,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"GET anonima a /rest/v1/{table}?limit=1 non ha restituito righe "
                f"(vuoto/401/403): l'anon non legge la tabella → RLS protegge (§11.1)."
            ),
            remediation_ref="RLS_DISABLED",
        )

    # ── §11.2 MUTATING — stub: NON implementare scritture in M0/M1 ───────────

    def _canary_write_test(self, ctx: RunContext) -> ModuleResult:
        """Canary write test (§11.2) — MUTATING 🔴, staging-only + ownership.

        STUB: in M0/M1 non si anticipano scritture. Quando implementato (M2) dovrà
        passare da `gate.authorize(MUTATING, ctx)`, scrivere un canary marcato,
        verificare l'esito e garantire il cleanup (DELETE del solo canary)."""
        raise NotImplementedError("M2")
