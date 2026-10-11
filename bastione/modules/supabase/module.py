"""Modulo Supabase probe — la gemma (§11 del blueprint). Intrusione MAX: MUTATING.

Il differenziatore di Bastione: nessuno scanner generico capisce PostgREST/RLS.
Qui sonderemo una istanza Supabase usando la **anon key** (pubblica per design,
§8/§11): esattamente come farebbe un esterno, ma in modo difensivo.

`max_intrusion = MUTATING` è la PIÙ ALTA intrusione che il modulo PUÒ chiedere
(§9), per il canary write (§11.2). NON è quella che usa sempre: il canary si
self-gata su `ctx.max_intrusion` e parte SOLO se la run è MUTATING; con un tetto
inferiore il modulo resta ESATTAMENTE read-only (M0/M1), nessuna scrittura.

**Controlli READ_ONLY (golden rule, §11.1):** due controlli, entrambi read-only:
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
hidden): sono M1/orchestratore.

**Controllo MUTATING (§11.2, M2 step 2) — il CANARY WRITE, il primo "scrivere":**
sopra il tetto MUTATING, per l'unione di (a) tabelle con attesa `anon_insert` in
matrice §15 e (b) tabelle trovate read-aperte in questa run, prova un POST marcato
(`__bastione_canary_<runid>`) e — se la riga è inserita — garantisce il cleanup
VERIFICATO (DELETE del solo canary; se non confermato → `CANARY_CLEANUP_FAILED`
CRITICAL con istruzioni manuali). Cinque invarianti LOCKED: gate-first, cleanup
garantito, superficie limitata, solo-con-schema-noto, offline-nei-test (vedi
`_canary_write_test`).

Resilienza (P8): un confine I/O che fallisce o un singolo asset che esplode viene
saltato/loggato, non fa crashare il resto. Surface map irraggiungibile/non-JSON
(es. la root REST risponde 401 all'anon su un target reale) → NON si tace: si
emette UN segnale onesto `SUPABASE_SCHEMA_NOT_ENUMERABLE` (RLS non verificabile
via introspezione, verifica INCOMPLETA, §11.1).

I confini HTTP sono le funzioni modulo-livello `_get` (read), `_post` e `_delete`
(canary, §11.2): le UNICHE cose monkeypatchate nei test (probe offline) — come per
il gate (§7) e il recon (§8). Nessun target live nei test.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json as _json
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    PostureCheck,
    RunContext,
    TableExpectation,
    TargetConfig,
)
from bastione.modules.base import Module, register
# §4.3 M5: i quattro sottomoduli PROBE/READ_ONLY cablati da `_run_submodules`.
# Import a livello di modulo (non dentro la funzione) così i test possono
# monkeypatchare `supa.storage.run_storage_checks` ecc. Nessun ciclo: i sottomoduli
# non importano `module.py`.
from bastione.modules.supabase import auth_posture, graphql, rpc, storage

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


def _post(url: str, headers: dict[str, str], json: dict):
    """POST MUTATING (§11.2 canary): scrive il body `json` su `url`. Ritorna la
    response (con `.status_code` e `.json()`) o None (degrado grazioso, niente
    crash). UNICO confine di scrittura del modulo insieme a `_delete`: monkeypatchato
    nei test (probe offline) → nessun host reale è mai puntato.

    NB di sicurezza: questa funzione NON decide se scrivere — quella decisione è
    già passata dal gate (`authorize(MUTATING, ctx)`) nel chiamante. Qui è solo il
    confine HTTP."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: canary write non disponibile (§11.2)")
        return None
    try:
        return httpx.post(url, headers=headers, json=json, timeout=_HTTP_TIMEOUT,
                          follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("POST %s fallita: %s", url, exc)
        return None


def _delete(url: str, headers: dict[str, str]):
    """DELETE MUTATING (§11.2 cleanup): rimuove la SOLA riga canary (l'url porta il
    filtro per PK o per marker). Ritorna la response o None (degrado grazioso).
    Insieme a `_post` è l'unico confine di scrittura: monkeypatchato nei test.

    Il cleanup è la garanzia LOCKED del canary (§11.2): ogni POST riuscito DEVE
    essere seguito da un DELETE verificato — se non confermato, il chiamante emette
    CANARY_CLEANUP_FAILED (CRITICAL)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: cleanup canary non disponibile (§11.2)")
        return None
    try:
        return httpx.delete(url, headers=headers, timeout=_HTTP_TIMEOUT,
                            follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("DELETE %s fallita: %s", url, exc)
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


def _expectation_for(table: str, cfg: TargetConfig) -> TableExpectation | None:
    """Modo ORACOLO (§15): l'attesa dichiarata dal proprietario per UNA tabella,
    o None se la matrice §15 non la menziona.

    Match per NOME tabella, **case-sensitive** come PostgREST (le relazioni sono
    case-sensitive: `Clienti` ≠ `clienti`). Funzione PURA (nessuna I/O): è il
    ponte tra la matrice di attese parsata in config (`cfg.expectations`) e la
    sonda. None → modo adversario (comportamento invariato, euristica colonne);
    presente → modo oracolo (la matrice dà ground-truth e chiude gli ambigui)."""
    for exp in cfg.expectations:
        if exp.name == table:
            return exp
    return None


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


def _jwt_alg(token: str) -> str | None:
    """Algoritmo di firma (`alg`) dall'header di un JWT, o None se non decodificabile.

    Funzione PURA (nessuna I/O): legge SOLO il segmento header (`token.split('.')[0]`),
    mai payload o firma. Per una chiave publishable (`sb_publishable_…`), che NON è un
    JWT, ritorna None → nessun falso finding HS256 (§4.3). Helper locale per non
    riaprire `recon/fingerprint.py` (zero cross-task)."""
    try:
        head = token.split(".")[0]
        head += "=" * (-len(head) % 4)
        data = _json.loads(base64.urlsafe_b64decode(head))
    except (IndexError, ValueError, binascii.Error):
        return None
    return data.get("alg") if isinstance(data, dict) else None


# ─── il modulo (§9/§11) ─────────────────────────────────────────────────────

@register
class SupabaseModule(Module):
    """Sonda Supabase (§11): surface map + RLS read test (READ_ONLY, §11.1) e,
    sopra il tetto MUTATING, il canary write test (§11.2).

    `max_intrusion = MUTATING` è la PIÙ ALTA intrusione che il modulo PUÒ chiedere
    (§9), NON quella che usa sempre: il canary si self-gate su `ctx.max_intrusion`
    e parte SOLO se la run è MUTATING. Con un tetto inferiore il modulo resta
    ESATTAMENTE read-only come in M0/M1 (nessuna scrittura)."""

    name = "supabase"
    max_intrusion = IntrusionLevel.MUTATING

    # ── selezione (§9) ──────────────────────────────────────────────────────

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """§4.3 M5: gira anche SENZA chiave, per emettere il segnale onesto
        `SUPABASE_KEY_NOT_FOUND` (R6) invece di tacere. Basta che il recon abbia
        rilevato Supabase OPPURE che il TOML dichiari un `supabase_url`."""
        return fp.is_supabase or (cfg.supabase_url is not None)

    # ── run (§11): surface map + RLS read test (§11.1), poi canary (§11.2) ───

    def run(self, ctx: RunContext) -> ModuleResult:
        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        cfg = ctx.target_cfg
        target = cfg.name
        supabase_url = ctx.fingerprint.supabase_url or cfg.supabase_url
        anon = ctx.fingerprint.anon_key

        # §4.3 M5 — INFO onesti (R6): niente URL / niente chiave → NON si tace, si
        # dichiara che la relativa verifica NON è stata fatta, poi si esce.
        if supabase_url is None:
            findings.append(self._not_found_info(
                "SUPABASE_URL_NOT_FOUND", "URL Supabase non trovato", target,
                "Nessun URL Supabase (né dal recon né dal TOML): la verifica "
                "Supabase NON è stata fatta."))
        if anon is None:
            findings.append(self._not_found_info(
                "SUPABASE_KEY_NOT_FOUND", "Chiave pubblica Supabase non trovata",
                target,
                "Nessuna chiave pubblica (legacy o publishable) estratta: la "
                "verifica RLS NON è stata fatta."))
        if supabase_url is None or anon is None:
            return ModuleResult(findings, posture)

        base = supabase_url.rstrip("/")
        headers = {"apikey": anon, "Authorization": f"Bearer {anon}"}
        # Registro delle tabelle trovate RLS-LEGGIBILI in questa run: è metà della
        # superficie LIMITATA del canary (§11.2 invariante 3). Lo popola il read test.
        read_open: set[str] = set()

        self._emit_key_kind_info(ctx, supabase_url, target, findings)
        self._run_rls_surface(ctx, base, headers, supabase_url, target,
                              findings, posture, read_open)
        self._run_submodules(ctx, base, headers, target, findings, posture)
        return ModuleResult(findings, posture)

    def _run_rls_surface(
        self,
        ctx: RunContext,
        base: str,
        headers: dict[str, str],
        supabase_url: str,
        target: str,
        findings: list[Finding],
        posture_checks: list[PostureCheck],
        read_open: set[str],
    ) -> None:
        """Surface map + RLS read test (§11.1) e canary (§11.2), estratti da `run`
        (§4.3 M5). Appende a `findings`/`posture_checks`/`read_open` passati — NON
        ritorna un ModuleResult (lo compone `run`). La logica RLS/canary è INVARIATA
        rispetto a prima del wiring dei sottomoduli: i `return` interni escono solo da
        questo helper."""
        # 1) SURFACE MAP — GET <supabase_url>/rest/v1/ → schema OpenAPI PostgREST.
        schema, detail = self._fetch_surface(base, headers)
        if schema is None:
            # Surface non disponibile (es. la root REST risponde 401 all'anon su un
            # target reale): l'introspezione OpenAPI è chiusa. FALLBACK (§11.1): se
            # il recon ha ricavato nomi tabella dal bundle JS (.from('...')) li
            # usiamo per testare l'RLS per nome — esattamente come un attaccante.
            discovered = list(ctx.fingerprint.discovered_tables)
            if discovered:
                log.warning("surface map non disponibile (%s): fallback su %d "
                            "tabelle scoperte dal bundle (§11.1)",
                            detail, len(discovered))
                self._rls_test_via_bundle(
                    base, headers, discovered, supabase_url, detail, target,
                    findings, posture_checks, ctx.target_cfg, read_open,
                )
                # CANARY (§11.2) nel path via_bundle — colonne IGNOTE ma scrittura
                # ABILITATA in modo SICURO. La superficie SINTETICA deve coprire
                # ENTRAMBI i rami dell'invariante 3 (superficie LIMITATA = UNIONE di):
                #   (a) tabelle con anon_insert=True nella matrice §15 (opt-in
                #       ESPLICITO dell'owner al write-test, ANCHE se read-protette),
                #       MA solo quelle effettivamente presenti tra le tabelle scoperte
                #       dal bundle (`discovered`): solo lì abbiamo una superficie reale
                #       da sondare. Una tabella solo-in-matrice ma non scoperta non
                #       avrebbe alcun endpoint enumerato da bersagliare.
                #   (b) tabelle GIÀ PROVATE LEGGIBILI dall'anon (`read_open`, popolata
                #       QUI SOPRA da `_rls_test_via_bundle` → `_rls_read_test`).
                # Per ognuna colonne=[] (ignote). Downstream: `_canary_targets` fa
                # l'unione `(read_open | matrix_insert) & schema` (qui = chiavi del
                # sintetico), `_canary_one_table` riceve columns=[] → body {} (soli
                # default), e il cleanup usa la PK dalla rappresentazione del POST; se
                # manca, è CANARY_CLEANUP_FAILED (mai una riga orfana silenziosa,
                # §11.2 inv. 2). Includere il ramo (a) nel sintetico EVITA il gap di
                # copertura silenzioso: senza, una tabella opt-in read-protetta
                # sparirebbe perché le chiavi del sintetico erano ESATTAMENTE read_open
                # (intersezione che la elimina). read_open E matrice ENTRAMBI vuoti →
                # nessuna tabella su cui testare la scrittura → skip ONESTO (vedi
                # `_canary_write_test`), NON una scrittura cieca.
                matrix_insert_in_discovered = {
                    exp.name for exp in ctx.target_cfg.expectations
                    if exp.anon_insert
                } & set(discovered)
                synthetic: dict[str, list[str]] = {
                    tbl: [] for tbl in (read_open | matrix_insert_in_discovered)
                }
                self._maybe_canary(
                    ctx, base, headers, target, synthetic, read_open,
                    findings, posture_checks, via_bundle=True)
                return
            # Nessun nome tabella NEMMENO nel bundle: NON tacere (sarebbe
            # fuorviante). Emettiamo UN segnale onesto — Supabase rilevato ma RLS
            # NON verificabile via introspezione, verifica INCOMPLETA (§11.1).
            log.warning("surface map non disponibile (%s) e nessuna tabella dal "
                        "bundle: emetto SUPABASE_SCHEMA_NOT_ENUMERABLE (§11.1)",
                        detail)
            findings.append(self._schema_not_enumerable_finding(
                supabase_url, detail, target))
            # Nessuna superficie nota: niente schema, niente nomi tabella → il
            # canary non avrebbe nulla su cui agire. Lo si salta del tutto.
            return

        tables, rpc_count = _enumerate_surface(schema)
        log.info("Supabase surface map: %d tabelle/view, %d RPC (non invocate, §11.1)",
                 len(tables), rpc_count)

        # 2) RLS READ TEST — per OGNI tabella, GET <url>/rest/v1/<tab>?limit=1.
        for table, columns in tables.items():
            try:
                self._rls_read_test(
                    base, headers, table, columns, supabase_url, target,
                    findings, posture_checks, ctx.target_cfg, read_open=read_open,
                )
            except Exception:  # noqa: BLE001 — resilienza (P8): un asset non blocca gli altri
                log.warning("RLS read test fallito per la tabella %r: saltata",
                            table, exc_info=True)

        # 3) CANARY WRITE TEST (§11.2, MUTATING 🔴) — schema noto (colonne dalle
        # `tables` di OpenAPI). Si auto-gata su ctx.max_intrusion: parte SOLO se la
        # run è MUTATING; altrimenti il modulo resta read-only identico a M1.
        self._maybe_canary(
            ctx, base, headers, target, tables, read_open,
            findings, posture_checks)

        return

    # ── nuovi helper M5 (§4.3): INFO onesti, legacy keys, wiring sottomoduli ──

    @staticmethod
    def _not_found_info(rule_id, title, target, detail) -> Finding:
        """INFO onesto (R6) quando manca l'URL o la chiave pubblica Supabase: non si
        tace, si dichiara che la relativa verifica NON è stata fatta (INCOMPLETA).
        Evidence/description NON segrete (P8). Stessa formula `finding_id` LOCKED."""
        loc = Location(endpoint="/rest/v1/")
        return Finding(
            finding_id=_finding_id("supabase", rule_id, loc), module="supabase",
            rule_id=rule_id, title=title, severity=Severity.INFO,
            confidence=Confidence.TENTATIVE, target=target, location=loc,
            evidence=detail, description=detail + " (R6: verifica INCOMPLETA)",
            remediation_ref=None, owasp=["A05:2021"],
            intrusion_used=IntrusionLevel.READ_ONLY)

    def _emit_key_kind_info(self, ctx, supabase_url, target, findings) -> None:
        """Chiavi legacy ancora in uso → INFO di migrazione (§4.3). Se la chiave è un
        JWT HS256 (firma legacy) aggiunge un secondo INFO. Per una chiave publishable
        (`sb_publishable_…`), `supabase_key_kind` non è "legacy_jwt" → nessun INFO
        (e `_jwt_alg` ritornerebbe comunque None)."""
        if ctx.fingerprint.supabase_key_kind != "legacy_jwt":
            return
        loc = Location(endpoint="/rest/v1/", url=supabase_url)
        findings.append(Finding(
            finding_id=_finding_id("supabase", "SUPABASE_LEGACY_KEYS_IN_USE", loc),
            module="supabase", rule_id="SUPABASE_LEGACY_KEYS_IN_USE",
            title="Chiavi Supabase legacy ancora in uso", severity=Severity.INFO,
            confidence=Confidence.FIRM, target=target, location=loc,
            evidence="chiave pubblica in formato legacy JWT (eyJ…)",
            description="Il progetto usa ancora la chiave pubblica legacy (JWT). Le "
                        "legacy saranno rimosse 'late 2026': migra a "
                        "sb_publishable_/sb_secret_.",
            remediation_ref=None, owasp=["A05:2021"],
            intrusion_used=IntrusionLevel.READ_ONLY))
        # alg del JWT: HS256 = firma legacy (helper locale puro, zero cross-task).
        if _jwt_alg(ctx.fingerprint.anon_key or "") == "HS256":
            findings.append(Finding(
                finding_id=_finding_id(
                    "supabase", "SUPABASE_JWT_LEGACY_HS256", loc),
                module="supabase", rule_id="SUPABASE_JWT_LEGACY_HS256",
                title="JWT Supabase con firma legacy HS256", severity=Severity.INFO,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence="alg=HS256",
                description="La chiave pubblica è un JWT HS256 (schema legacy). Con "
                            "le nuove chiavi la firma passa ad asimmetrica: pianifica "
                            "la migrazione.",
                remediation_ref=None, owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.READ_ONLY))

    def _run_submodules(self, ctx, base, headers, target, findings, posture) -> None:
        """Invoca i sottomoduli PROBE/READ_ONLY (storage/rpc/auth/graphql). Ognuno si
        auto-gated (§4.0.7): con un tetto < PROBE o ownership non verificata le probe
        PROBE restituiscono liste vuote senza alcuna I/O (nessuna IntrusionDenied
        sfugge). Isolamento per resilienza (§4.7): un sottomodulo che esplode viene
        loggato e saltato, NON blocca gli altri né fa crashare la run.

        Buckets/RPC = UNIONE di (bundle ∪ TOML ∪ attese), ordinata e deduplicata."""
        cfg = ctx.target_cfg
        buckets = sorted(set(ctx.fingerprint.discovered_buckets)
                         | set(cfg.supabase_buckets)
                         | {b.name for b in cfg.expect_buckets})
        rpcs = sorted(set(ctx.fingerprint.discovered_rpcs)
                      | set(cfg.supabase_rpcs)
                      | {r.name for r in cfg.expect_rpcs})
        for fn, args in (
            (storage.run_storage_checks, (ctx, base, headers, buckets, target)),
            (rpc.run_rpc_checks, (ctx, base, headers, rpcs, target)),
            (auth_posture.run_auth_posture_checks, (ctx, base, headers, target)),
            (graphql.run_graphql_checks, (ctx, base, headers, target)),
        ):
            try:
                f, p = fn(*args)
                findings.extend(f)
                posture.extend(p)
            except IntrusionDenied:
                raise  # il gate ABORTA, non si declassa a "sottomodulo fallito" (§7)
            except Exception:  # noqa: BLE001 — un sottomodulo non blocca gli altri
                log.warning("supabase: sottomodulo %s fallito, saltato",
                            getattr(fn, "__name__", fn), exc_info=True)

    # ── passi interni ───────────────────────────────────────────────────────

    def _fetch_surface(
        self, base: str, headers: dict[str, str]
    ) -> tuple[dict | None, str]:
        """GET <base>/rest/v1/ → `(schema, detail)` (§11.1).

        Successo: `(schema_dict, "status=200")`. In caso contrario `schema` è None
        e `detail` motiva ESPLICITAMENTE il fallimento (per un segnale onesto nel
        report, §11.1) — es. "status=401", "nessuna risposta (httpx assente o
        errore di rete)", "risposta non-JSON", "schema non valido".
        Resiliente: qualunque errore di rete o di parsing → `(None, detail)`."""
        resp = _get(f"{base}/rest/v1/", headers)
        if resp is None:
            detail = "nessuna risposta (httpx assente o errore di rete)"
            log.warning("surface map: %s dalla root REST (§11.1)", detail)
            return None, detail
        status = getattr(resp, "status_code", None)
        if status != 200:
            detail = f"status={status}"
            log.warning("surface map: la root REST ha risposto %s "
                        "(l'anon non legge lo schema OpenAPI?) (§11.1)", detail)
            return None, detail
        try:
            schema = resp.json()
        except (ValueError, TypeError):
            detail = "risposta non-JSON"
            log.warning("surface map: %s dalla root REST (§11.1)", detail)
            return None, detail
        if not isinstance(schema, dict):
            detail = "schema non valido"
            log.warning("surface map: %s dalla root REST (§11.1)", detail)
            return None, detail
        return schema, "status=200"

    @staticmethod
    def _schema_not_enumerable_finding(
        supabase_url: str,
        detail: str,
        target: str,
    ) -> Finding:
        """Segnale ONESTO `SUPABASE_SCHEMA_NOT_ENUMERABLE` (§11.1): Supabase è stato
        rilevato (is_supabase + anon_key) ma la root REST non espone lo schema
        OpenAPI all'anon → impossibile enumerare le tabelle e quindi verificare
        l'RLS per-tabella via introspezione. Questo NON conferma che l'RLS sia
        corretta: è una verifica INCOMPLETA, da rendere esplicita nel report.

        Severità LOCKED `INFO` + confidence `TENTATIVE`. Evidence NON segreta
        (solo l'esito della GET). finding_id via la STESSA formula LOCKED §16."""
        location = Location(endpoint="/rest/v1/", url=supabase_url)
        # Evidence NON segreta (P8): solo l'esito della GET, mai chiavi/dati.
        evidence = f"GET /rest/v1/ -> {detail}"
        description = (
            "Supabase rilevato (is_supabase + anon_key) ma la root REST "
            "(/rest/v1/) non espone lo schema OpenAPI all'anon → impossibile "
            "enumerare le tabelle e quindi verificare l'RLS per-tabella via "
            "introspezione (§11.1). **Questo NON conferma che l'RLS sia "
            "corretta: è una verifica INCOMPLETA.** Inoltre NESSUN nome tabella è "
            "stato trovato nel bundle JS (nessun riferimento `.from('...')` del "
            "client Supabase): non c'è quindi alcun nome su cui ripiegare per "
            "testare l'RLS per nome. La superficie resta non verificabile."
        )
        return Finding(
            finding_id=_finding_id(
                "supabase", "SUPABASE_SCHEMA_NOT_ENUMERABLE", location),
            module="supabase",
            rule_id="SUPABASE_SCHEMA_NOT_ENUMERABLE",
            title="Superficie Supabase non enumerabile dall'anon",
            severity=Severity.INFO,
            confidence=Confidence.TENTATIVE,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_DISABLED",
            owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.READ_ONLY,
        )

    @staticmethod
    def _schema_via_bundle_finding(
        supabase_url: str,
        detail: str,
        tables: list[str],
        target: str,
    ) -> Finding:
        """Segnale ONESTO `SUPABASE_SCHEMA_VIA_BUNDLE` (§11.1): l'OpenAPI è chiusa
        (surface non-200) quindi l'enumerazione delle tabelle è avvenuta via bundle
        JS (`.from('...')`). È una copertura PARZIALE: testiamo SOLO le tabelle
        referenziate nel client JS — altre relazioni possono esistere e NON essere
        state testate (l'OpenAPI, che le elencherebbe tutte, non è disponibile).

        Severità LOCKED `INFO` + confidence `TENTATIVE`. Evidence NON segreta (solo
        l'esito della GET + il conteggio tabelle). finding_id via formula LOCKED §16."""
        location = Location(endpoint="/rest/v1/", url=supabase_url)
        # Evidence NON segreta (P8): esito GET surface + quante tabelle dal bundle.
        evidence = (
            f"GET /rest/v1/ -> {detail}; enumerazione via bundle: "
            f"{len(tables)} tabelle referenziate nel client JS"
        )
        description = (
            "L'introspezione OpenAPI è chiusa all'anon (la root REST /rest/v1/ non "
            f"ha risposto 200: {detail}). L'enumerazione delle tabelle è quindi "
            "avvenuta dal bundle JS, sui riferimenti `.from('...')` del client "
            "Supabase, e l'RLS è stata testata per ciascun nome (§11.1). "
            "**Copertura PARZIALE:** sono testate SOLO le tabelle referenziate nel "
            "client JS; poiché l'OpenAPI non è disponibile, potrebbero esistere "
            "altre tabelle/relazioni non referenziate nel bundle e quindi NON "
            "testate. Inoltre le colonne non sono note → niente euristica dati "
            "personali sui finding via-bundle (severità HIGH prudenziale)."
        )
        return Finding(
            finding_id=_finding_id(
                "supabase", "SUPABASE_SCHEMA_VIA_BUNDLE", location),
            module="supabase",
            rule_id="SUPABASE_SCHEMA_VIA_BUNDLE",
            title="Superficie Supabase enumerata dal bundle (OpenAPI chiusa, copertura parziale)",
            severity=Severity.INFO,
            confidence=Confidence.TENTATIVE,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_DISABLED",
            owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.READ_ONLY,
        )

    def _rls_test_via_bundle(
        self,
        base: str,
        headers: dict[str, str],
        tables: list[str],
        supabase_url: str,
        detail: str,
        target: str,
        findings: list[Finding],
        posture_checks: list[PostureCheck],
        cfg: TargetConfig,
        read_open: set[str] | None = None,
    ) -> None:
        """FALLBACK §11.1: l'OpenAPI è chiusa (surface non-200) ma il recon ha
        ricavato nomi tabella dal bundle JS (`.from('...')`). Testiamo l'RLS per
        ogni nome (riuso `_rls_read_test`) — come farebbe un attaccante.

        `read_open` (M2 step 2): propagato a `_rls_read_test` così le tabelle
        read-aperte scoperte via bundle finiscono nel registro della superficie
        canary (§11.2). NB: nel path via_bundle il canary NON scriverà comunque
        (colonne ignote → CANARY_SKIPPED_NO_SCHEMA), ma il registro resta coerente.

        Differenza chiave dal path OpenAPI: le COLONNE non sono note (il bundle dà
        i nomi tabella, non lo schema). Passiamo quindi `columns=[]` → niente
        euristica GDPR → severità HIGH LOCKED. In più emettiamo UN finding onesto
        INFO/TENTATIVE che documenta la copertura PARZIALE (solo le tabelle
        referenziate nel client JS; altre potrebbero esistere e non essere testate).

        ORACOLO (§15): qui la matrice vale DI PIÙ — niente euristica colonne, ma la
        matrice dà ground-truth per nome tabella. `cfg` è passato a `_rls_read_test`
        così conformità (anon_select=True → soppressione) e violazioni
        (anon_select=False → CRITICAL) si applicano anche senza colonne note."""
        for table in tables:
            try:
                # columns=[] LOCKED: senza schema niente GDPR → HIGH. La nota di
                # parzialità è iniettata da `_via_bundle` dentro la description.
                # La matrice §15 (via cfg) può comunque sopprimere/scalare per nome.
                self._rls_read_test(
                    base, headers, table, [], supabase_url, target,
                    findings, posture_checks, cfg, via_bundle=True,
                    read_open=read_open,
                )
            except Exception:  # noqa: BLE001 — resilienza (P8): un asset non blocca gli altri
                log.warning("RLS read test (via bundle) fallito per la tabella %r: "
                            "saltata", table, exc_info=True)

        # Finding onesto sulla copertura PARZIALE (§11.1): enumerazione via bundle.
        findings.append(self._schema_via_bundle_finding(
            supabase_url, detail, tables, target))

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
        cfg: TargetConfig,
        via_bundle: bool = False,
        read_open: set[str] | None = None,
    ) -> None:
        """RLS read test per UNA tabella (§11.1.2), arricchito dal modo ORACOLO (§15).

        `read_open` (M2 step 2): se passato, vi si annota il NOME della tabella
        quando l'anon LEGGE righe (anche se il finding è soppresso dalla matrice:
        read-open è read-open). È la superficie LIMITATA (§11.2 invariante 3) che
        il canary write userà — le tabelle read-aperte sono le più probabilmente
        anche write-aperte. NON cambia il comportamento read-only: è solo un
        registro per la fase MUTATING successiva.

        - 200 con array NON vuoto → l'anon LEGGE la tabella. Qui entra la matrice
          di attese (§15), che chiude gli ambigui da sola:
            * exp.anon_select == True  → CONFORME (tabella pubblica BY DESIGN, es.
              listino_pubblico): la lettura anon è ATTESA → si SOPPRIME il Finding
              RLS_DISABLED ed si emette un PostureCheck passed=True onesto (lo score
              resta onesto, non è un fallimento).
            * exp.anon_select == False → VIOLAZIONE: il proprietario ha dichiarato
              che l'anon NON deve leggere, ma legge → CRITICAL (criterio LOCKED
              §11.1.2) + nota esplicita in description; confidence resta FIRM.
            * exp None → modo adversario invariato (euristica colonne: CRITICAL se
              dati personali, altrimenti HIGH; via_bundle senza colonne → HIGH).
        - 200 vuoto / 401 / 403 / altro → PostureCheck `POSTURE_RLS_<tabella>`
          passed (l'anon non legge → RLS sta proteggendo)."""
        endpoint = f"/rest/v1/{table}"
        resp = _get(f"{base}{endpoint}?limit=1", headers)
        status = getattr(resp, "status_code", None)

        rows = self._readable_rows(resp)
        if rows is not None and len(rows) > 0:
            # SUPERFICIE LIMITATA (§11.2): registra la tabella come read-aperta per
            # il canary write. Lo facciamo PRIMA di ogni ramo (conformità inclusa):
            # una tabella pubblica-per-scelta in lettura resta un bersaglio legittimo
            # del write-test (la matrice §15 deciderà poi se la scrittura è attesa).
            if read_open is not None:
                read_open.add(table)
            # ORACOLO (§15): l'attesa dichiarata per QUESTA tabella (None se assente).
            exp = _expectation_for(table, cfg)

            # CONFORMITÀ: la lettura anon è ATTESA (tabella pubblica per scelta) →
            # NON è un fallimento. Si SOPPRIME il Finding RLS_DISABLED e si emette
            # un PostureCheck passed=True che dichiara la conformità alla matrice.
            # Lo score resta onesto (§17): nessun peso fallito per questa tabella.
            if exp is not None and exp.anon_select:
                posture_checks.append(self._rls_expected_public_posture(
                    table, endpoint, target))
                return

            # ESPOSTA NON ATTESA: severità LOCKED §11.1.2 — CRITICAL se i nomi
            # colonna suggeriscono dati personali OPPURE se VIOLA un'attesa della
            # matrice (exp esiste e not exp.anon_select); altrimenti HIGH. La
            # calcoliamo UNA volta e la condividiamo tra Finding e PostureCheck
            # FALLITO, così il peso nello score (§17) è proporzionale e allineato.
            violates_matrix = exp is not None  # qui exp.anon_select è False
            severity = self._rls_disabled_severity(columns, violates_matrix)
            findings.append(self._rls_disabled_finding(
                table, columns, rows, supabase_url, endpoint, target, severity,
                via_bundle, violates_matrix))
            # Mutua esclusione (§17): tabella esposta → PostureCheck passed=False.
            # Senza, lo score si calcola dai PostureCheck e resterebbe 100/100
            # pur con finding HIGH/CRITICAL aperti (fuorviante). drift resta al
            # default False: lo valorizza la fase POSTURE/baseline (§16).
            posture_checks.append(self._rls_exposed_posture(
                table, endpoint, target, severity))
            return

        # protetto (vuoto / 401 / 403 / irraggiungibile) → posture positiva. Lo
        # status è propagato per la nota "protetto ma fragile" sul 401/403 (§4.3).
        posture_checks.append(self._rls_protected_posture(table, target, status))

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
    def _rls_disabled_severity(
        columns: list[str],
        violates_matrix: bool = False,
    ) -> Severity:
        """Severità LOCKED del caso RLS disabilitata (§11.1.2), calcolata UNA volta
        e condivisa tra Finding e PostureCheck per evitare disallineamenti.

        Criterio LOCKED §11.1.2: CRITICAL se i NOMI colonna suggeriscono dati
        personali (euristica §11.1) **OPPURE se la tabella viola un'attesa della
        matrice §15** (`violates_matrix=True`, cioè exp.anon_select=False ma l'anon
        legge); altrimenti HIGH.

        Nel path via_bundle le colonne non sono note (columns=[]) → l'euristica non
        scatta → HIGH prudenziale; ma la matrice §15 (per nome tabella) può comunque
        portare a CRITICAL anche lì — ed è proprio dove l'oracolo dà più valore.
        La CONFORMITÀ (anon_select=True → soppressione) è gestita PRIMA, in
        `_rls_read_test`, quindi qui non serve gestirla."""
        if _has_personal_data(columns) or violates_matrix:
            return Severity.CRITICAL
        return Severity.HIGH

    @staticmethod
    def _rls_disabled_finding(
        table: str,
        columns: list[str],
        rows: list,
        supabase_url: str,
        endpoint: str,
        target: str,
        severity: Severity,
        via_bundle: bool = False,
        violates_matrix: bool = False,
    ) -> Finding:
        """Costruisce il Finding `RLS_DISABLED` (§11.1.2). Severità LOCKED (passata
        dal chiamante, calcolata da `_rls_disabled_severity` così da coincidere col
        PostureCheck fallito) ed evidence REDATTA (P8): mai i valori delle righe,
        solo conteggio + colonne.

        `via_bundle=True` (fallback §11.1): la tabella è stata scoperta dal bundle
        JS (`.from('...')`), NON dall'OpenAPI → le COLONNE non sono note (columns=[]).
        Senza colonne non si applica l'euristica GDPR → severità HIGH LOCKED (salvo
        violazione di matrice, vedi sotto), e la description lo NOTA esplicitamente.

        `violates_matrix=True` (ORACOLO §15): il proprietario ha dichiarato
        anon_select=False per questa tabella ma l'anon legge → VIOLAZIONE. La
        severità è già CRITICAL (criterio LOCKED §11.1.2); qui la description lo
        NOTA esplicitamente. La violazione NON forza `gdpr_relevant`: dichiarare
        che l'anon non deve leggere non implica che il contenuto sia personale."""
        # gdpr_relevant LEGATO all'euristica colonne (NON alla severità): una
        # violazione di matrice può rendere CRITICAL una tabella senza colonne
        # personali — in quel caso gdpr_relevant resta False (lo notiamo soltanto).
        personal = _has_personal_data(columns)

        # Evidence REDATTA (P8): SOLO conteggio righe + NOMI colonna — mai i valori.
        # In fallback le colonne non sono note (tabella dal bundle) → lo si dichiara.
        if via_bundle:
            evidence = (
                f"{len(rows)} righe leggibili da anon; colonne non note "
                f"(tabella scoperta dal bundle, non da OpenAPI)"
            )
        else:
            evidence = (
                f"{len(rows)} righe leggibili da anon; "
                f"colonne: {sorted(columns)}"
            )
        location = Location(endpoint=endpoint, url=supabase_url)
        title = (
            f"RLS disabilitata/permissiva sulla tabella '{table}'"
            + (" (dati personali esposti)" if personal else "")
            + (" (viola la matrice di attese §15)"
               if violates_matrix and not personal else "")
        )
        # Spiegazione della severità: prima il motivo "colonne" (euristica/bundle),
        # poi — se presente — la NOTA sulla violazione di matrice (§15), che da sola
        # giustifica CRITICAL anche senza colonne personali (criterio LOCKED §11.1.2).
        if via_bundle:
            severity_note = (
                "Le colonne non sono note (tabella scoperta dal bundle JS "
                ".from('...'), non da OpenAPI): senza schema non si applica "
                "l'euristica dati personali"
                + (" → severità HIGH (potrebbe in realtà esporre dati personali, "
                   "da verificare)." if not violates_matrix else ".")
            )
        elif personal:
            severity_note = (
                "I nomi colonna suggeriscono dati personali → severità CRITICAL e "
                "gdpr_relevant."
            )
        elif violates_matrix:
            severity_note = (
                "Nessun nome colonna riconducibile a dati personali."
            )
        else:
            severity_note = (
                "Nessun nome colonna riconducibile a dati personali → severità HIGH."
            )
        # NOTA ORACOLO (§15): la violazione della matrice è il motivo che ALZA a
        # CRITICAL quando le colonne da sole non lo farebbero (criterio LOCKED).
        matrix_note = (
            " La matrice di attese (§15) dichiara che l'anon NON deve leggere "
            "questa tabella (anon_select=false), ma legge: **viola la matrice di "
            "attese (§15)** → severità CRITICAL (criterio LOCKED §11.1.2), "
            "confidence FIRM. (La violazione non implica di per sé dati personali.)"
            if violates_matrix else ""
        )
        description = (
            f"La GET anonima a {endpoint}?limit=1 ha restituito righe: l'anon key "
            f"legge la tabella '{table}'. RLS assente o policy SELECT troppo "
            f"permissiva (§11.1). "
            + severity_note
            + matrix_note
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
    def _rls_protected_posture(
        table: str, target: str, status: int | None = None,
    ) -> PostureCheck:
        """PostureCheck positivo `POSTURE_RLS_<tabella>` (§11.1.2): l'anon NON legge
        la tabella → RLS sta proteggendo.

        §4.3 M5 "protetto ma fragile" (30/10/2026): un `401/403` può derivare dalla
        SOLA assenza di GRANT (nuovo default Supabase), non da una policy RLS
        esplicita. La posture passa comunque (l'anon non legge), ma con una NOTA e la
        raccomandazione di abilitare la RLS esplicitamente (verifica definitiva in
        M8). Uno status diverso (vuoto 200, irraggiungibile, ecc.) resta la nota
        classica."""
        fragile = status in (401, 403)
        if fragile:
            detail = (
                f"GET anonima a /rest/v1/{table}?limit=1 → {status}: tabella "
                "protetta, ma la protezione potrebbe derivare dalla SOLA assenza di "
                "GRANT (default Supabase dal 30/10/2026), non da una policy RLS "
                "esplicita → 'protetto ma fragile'. Raccomandazione: abilita la RLS "
                "esplicitamente. Verifica definitiva in M8."
            )
        else:
            detail = (
                f"GET anonima a /rest/v1/{table}?limit=1 non ha restituito righe: "
                "l'anon non legge la tabella → RLS protegge (§11.1)."
            )
        return PostureCheck(
            check_id=f"POSTURE_RLS_{table}",
            title=f"RLS attiva sulla tabella '{table}'",
            passed=True,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=detail,
            remediation_ref="RLS_DISABLED",
        )

    @staticmethod
    def _rls_expected_public_posture(
        table: str,
        endpoint: str,
        target: str,
    ) -> PostureCheck:
        """PostureCheck CONFORME alla matrice di attese (§15): l'anon LEGGE la
        tabella ma la matrice dichiara `anon_select=true` → è una tabella PUBBLICA
        BY DESIGN (es. listino_pubblico). La lettura anon è ATTESA: NON è un
        fallimento → `passed=True`, e il Finding RLS_DISABLED viene SOPPRESSO a
        monte (in `_rls_read_test`).

        Distinto da `_rls_protected_posture` (lì l'anon NON legge): qui l'anon
        legge ma è OK perché dichiarato. Lo score resta onesto (§17): pesa come un
        check passato, non come un'esposizione. È l'oracolo (§15) che chiude
        l'ambiguo da solo — un 200 con righe che sarebbe un finding diventa una
        conferma di posture corretta."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_{table}",
            title=f"Tabella '{table}' pubblica per scelta (lettura anon attesa, §15)",
            passed=True,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"GET anonima a {endpoint}?limit=1 ha restituito righe, MA la "
                f"matrice di attese (§15) dichiara anon_select=true per '{table}': "
                f"lettura anon ATTESA → tabella pubblica per scelta, non un'esposizione. "
                f"Finding RLS_DISABLED soppresso/declassato; lo score resta onesto (§17)."
            ),
            remediation_ref="RLS_DISABLED",
        )

    @staticmethod
    def _rls_exposed_posture(
        table: str,
        endpoint: str,
        target: str,
        severity: Severity,
    ) -> PostureCheck:
        """Costruisce il PostureCheck FALLITO `POSTURE_RLS_<tabella>` (§17): la GET
        anonima ha restituito righe → l'anon LEGGE la tabella → RLS NON sta
        proteggendo (esposizione). Mutuamente esclusivo con `_rls_protected_posture`:
        per una tabella si emette O il passed=True (protetta) O questo passed=False
        (esposta), MAI entrambi.

        `severity_if_failed` coincide con la severità del Finding RLS_DISABLED (la
        stessa `severity` calcolata da `_rls_disabled_severity`) → il peso nello
        score (§17) è proporzionale: CRITICAL pesa 8, HIGH 5. `drift` resta al
        default False: lo valorizza la fase POSTURE/baseline confrontando con la
        baseline (passed→failed = DRIFT, §16) — NON lo impostiamo qui."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_{table}",
            title=f"RLS NON attiva sulla tabella '{table}' (esposta all'anon)",
            passed=False,
            severity_if_failed=severity,
            target=target,
            detail=(
                f"GET anonima a {endpoint}?limit=1 ha restituito righe: l'anon "
                f"LEGGE la tabella → RLS NON sta proteggendo (esposizione, §17). "
                f"Vedi il Finding RLS_DISABLED per i dettagli."
            ),
            remediation_ref="RLS_DISABLED",
        )

    # ════════════════════════════════════════════════════════════════════════
    # §11.2 MUTATING 🔴 — CANARY WRITE: il PRIMO "scrivere" di Bastione (M2)
    # ════════════════════════════════════════════════════════════════════════
    #
    # Cinque INVARIANTI di sicurezza LOCKED (NON negoziabili):
    #   1. GATE: parte SOLO se ctx.max_intrusion >= MUTATING; PRIMA azione =
    #      authorize(MUTATING, ctx) (backstop: aborta se non staging / non owned).
    #   2. CLEANUP GARANTITO: ogni POST 201 → DELETE VERIFICATO; se non confermato
    #      → CANARY_CLEANUP_FAILED (CRITICAL) con tabella + marker + DELETE manuale.
    #   3. SUPERFICIE LIMITATA: solo (a) tabelle con attesa anon_insert in matrice
    #      ∪ (b) tabelle trovate RLS-LEGGIBILI in questa run. Mai blind-write.
    #   4. SOLO con SCHEMA NOTO: scrive solo con colonne note (INSERT mirato +
    #      cleanup deterministico). Via_bundle (colonne ignote) → SKIPPED, niente POST.
    #   5. OFFLINE nei test: _post/_delete monkeypatchati, nessun target live.

    def _maybe_canary(
        self,
        ctx: RunContext,
        base: str,
        headers: dict[str, str],
        target: str,
        tables: dict[str, list[str]],
        read_open: set[str],
        findings: list[Finding],
        posture_checks: list[PostureCheck],
        via_bundle: bool = False,
    ) -> None:
        """SELF-GATE (§11.2 invariante 1): il canary parte SOLO se il tetto della
        run è MUTATING. Con un tetto inferiore NON facciamo NULLA — il modulo si
        comporta esattamente come read-only (M1). Questo è ciò che rende il bump di
        `max_intrusion` a MUTATING innocuo finché la run non è esplicitamente 🔴.

        `via_bundle=True` ⇒ path FALLBACK con OpenAPI chiusa: `tables` è la superficie
        SINTETICA derivata da `read_open` (colonne=[] per ogni tabella read-aperta).
        Il canary scrive a body VUOTO (soli default) e fa cleanup per PK dalla
        rappresentazione; se `read_open` è vuoto NON scrive (skip onesto)."""
        if ctx.max_intrusion < IntrusionLevel.MUTATING:
            return  # read-only: canary INTERAMENTE saltato (NON-REGRESSIONE)
        self._canary_write_test(
            ctx, base, headers, target, tables, read_open,
            findings, posture_checks, via_bundle=via_bundle)

    def _canary_write_test(
        self,
        ctx: RunContext,
        base: str,
        headers: dict[str, str],
        target: str,
        tables: dict[str, list[str]],
        read_open: set[str],
        findings: list[Finding],
        posture_checks: list[PostureCheck],
        via_bundle: bool = False,
    ) -> None:
        """Canary write test (§11.2) — MUTATING 🔴, staging-only + ownership.

        INVARIANTE 1 (GATE): la PRIMA azione è `authorize(MUTATING, ctx)`. È il
        backstop del gate (§7): se la run non è staging, il target non è owned o
        l'ownership non è verificata, `authorize` solleva `IntrusionDenied` e il
        canary ABORTA prima di qualsiasi scrittura. NON la catturiamo qui: deve
        propagare (l'orchestratore la gestisce) — meglio abortire che scrivere
        senza autorizzazione.

        `via_bundle=True`: superficie SINTETICA da `read_open` (colonne ignote). La
        scrittura È abilitata, ma cleanup-safe: body VUOTO + cleanup per PK; se la
        rappresentazione non dà una PK e col è None il cleanup non confermato →
        CANARY_CLEANUP_FAILED (mai una riga orfana, §11.2 inv. 2)."""
        # ── INVARIANTE 1 (GATE): authorize PRIMA di tutto, niente scritture senza ──
        authorize(IntrusionLevel.MUTATING, ctx)

        # ── INVARIANTE 3 (SUPERFICIE LIMITATA): unione delle due liste, mai a caso ──
        targets = self._canary_targets(tables, read_open, ctx.target_cfg)
        if not targets:
            if via_bundle:
                # Path via_bundle senza alcuna tabella anon-leggibile: NON c'è una
                # superficie già provata leggibile su cui testare la scrittura in
                # modo cleanup-safe. Lo si DICHIARA (segnale onesto nel NUOVO
                # significato), invece di tacere — 'nessun finding di scrittura' non
                # significa 'scrittura testata'.
                findings.append(self._canary_skipped_no_schema_finding(
                    ctx, target))
            else:
                log.info("canary: nessuna tabella bersaglio (né read-aperta né in "
                         "matrice anon_insert) → nessuna scrittura (§11.2)")
            return

        supabase_url = (ctx.fingerprint.supabase_url
                        or ctx.target_cfg.supabase_url)
        marker = f"__bastione_canary_{ctx.run_dir.name}"
        for table in targets:
            columns = tables.get(table, [])
            # `_pending_cleanup` traccia, per la tabella corrente, una riga canary
            # scritta (201) il cui cleanup NON è ancora stato eseguito/segnalato.
            # Lo resettiamo PRIMA di ogni tabella così il backstop sotto sa, in caso
            # di eccezione, se è rimasto garbage da segnalare (difesa-in-profondità).
            self._pending_cleanup = None
            try:
                self._canary_one_table(
                    base, headers, table, columns, marker, supabase_url,
                    target, ctx.target_cfg, findings, posture_checks)
            except Exception:  # noqa: BLE001 — resilienza (P8): un bersaglio non blocca gli altri
                log.warning("canary write fallito per la tabella %r: saltata",
                            table, exc_info=True)
                # BACKSTOP invariante 2: se per questa tabella un POST era andato a
                # 201 e il cleanup NON è stato completato (eccezione sfuggita perfino
                # al finally di `_canary_one_table`), NON ingoiare in silenzio: emetti
                # comunque CANARY_CLEANUP_FAILED così la riga orfana è segnalata.
                pending = getattr(self, "_pending_cleanup", None)
                if pending is not None:
                    p_table, p_endpoint, p_marker, p_col, p_url, p_target = pending
                    log.warning("canary: cleanup NON completato su %r dopo "
                                "eccezione: emetto CANARY_CLEANUP_FAILED (§11.2)",
                                p_table)
                    findings.append(self._canary_cleanup_failed_finding(
                        p_table, p_endpoint, p_marker, p_col, p_url, p_target,
                        "eccezione tra POST e cleanup"))
                    self._pending_cleanup = None

    @staticmethod
    def _canary_targets(
        tables: dict[str, list[str]],
        read_open: set[str],
        cfg: TargetConfig,
    ) -> list[str]:
        """SUPERFICIE LIMITATA (§11.2 invariante 3): l'UNIONE di
          (a) tabelle con attesa `anon_insert` nella matrice §15 (l'owner ha opt-in
              al write-test, ANCHE se la tabella è read-protetta), e
          (b) tabelle già trovate RLS-LEGGIBILI in questa run (le più probabilmente
              write-aperte).
        Mai un blind-write su relazioni a caso: il bersaglio deve appartenere allo
        schema noto (`tables`) — un nome solo-in-matrice ma assente dallo schema è
        scartato (non avremmo le colonne per un INSERT cleanup-safe). Ordine
        deterministico per riproducibilità."""
        matrix_insert = {
            exp.name for exp in cfg.expectations if exp.anon_insert
        }
        union = (read_open | matrix_insert) & set(tables.keys())
        return sorted(union)

    def _canary_one_table(
        self,
        base: str,
        headers: dict[str, str],
        table: str,
        columns: list[str],
        marker: str,
        supabase_url: str | None,
        target: str,
        cfg: TargetConfig,
        findings: list[Finding],
        posture_checks: list[PostureCheck],
    ) -> None:
        """Esegue il canary su UNA tabella con colonne note (§11.2).

        Meccanica: POST del marker in una colonna (euristica: una testuale; se non
        determinabile, una qualsiasi — un type-mismatch darà 4xx, esito SICURO:
        nessuna riga scritta). Mappa l'esito su PostureCheck/Finding e, se una riga
        è stata inserita (201), esegue e VERIFICA il cleanup (invariante 2)."""
        endpoint = f"/rest/v1/{table}"
        col = self._canary_column(columns)
        # Header PostgREST: return=representation così il 201 ci ridà la riga (con
        # la PK) per un cleanup deterministico (DELETE per PK).
        post_headers = {**headers, "Prefer": "return=representation",
                        "Content-Type": "application/json"}
        body = {col: marker} if col is not None else {}
        resp = _post(f"{base}{endpoint}", post_headers, body)

        status = getattr(resp, "status_code", None) if resp is not None else None

        # ── INSERT PROTETTO (401/403) → posture write passed, niente da pulire ──
        if status in (401, 403):
            posture_checks.append(self._rls_write_protected_posture(
                table, endpoint, target, status))
            return

        # ── INSERT ACCETTATO (200/201, riga scritta) → RLS_WRITE_OPEN + CLEANUP ──
        if status in (200, 201):
            # CLEANUP GARANTITO IN OGNI RAMO (invariante 2): da questo punto una
            # riga canary È sul target. Il cleanup va eseguito SEMPRE, anche se la
            # costruzione di Finding/PostureCheck qui sotto sollevasse (oggi non è
            # innescabile, ma il try/finally rende il punto robusto per
            # difesa-in-profondità: NESSUNA eccezione tra il POST e il DELETE può
            # saltare la rimozione). Per lo stesso motivo registriamo subito che il
            # cleanup è OBBLIGATORIO, così il backstop di `_canary_write_test` può
            # emettere CANARY_CLEANUP_FAILED se un'eccezione sfugge perfino al
            # finally.
            self._pending_cleanup = (table, endpoint, marker, col, supabase_url,
                                     target)
            try:
                exp = _expectation_for(table, cfg)
                # ORACOLO §15: anon_insert=True → scrittura ATTESA → CONFORME: si
                # SOPPRIME il finding, posture write passed=True. MA il cleanup va
                # eseguito comunque (la riga canary va rimossa — invariante 2).
                conforme = exp is not None and exp.anon_insert
                if conforme:
                    posture_checks.append(self._rls_write_expected_posture(
                        table, endpoint, target))
                else:
                    # Severità (§11.2): HIGH di base; CRITICAL se viola la matrice
                    # (anon_insert=False) OPPURE colonne con dati personali.
                    violates = exp is not None  # qui exp.anon_insert è False
                    personal = _has_personal_data(columns)
                    severity = (Severity.CRITICAL
                                if violates or personal else Severity.HIGH)
                    findings.append(self._rls_write_open_finding(
                        table, endpoint, supabase_url, target, severity,
                        Confidence.FIRM, written=True, violates_matrix=violates,
                        personal=personal, note=None))
                    posture_checks.append(self._rls_write_exposed_posture(
                        table, endpoint, target, severity))
            finally:
                # CLEANUP nel finally: rimuovi la SOLA riga canary, anche se il
                # finding è stato soppresso per conformità E anche se il blocco
                # sopra ha sollevato. Verifica l'esito (rimozione PROVATA).
                self._canary_cleanup(
                    base, headers, table, endpoint, col, marker, resp,
                    supabase_url, target, findings)
                # Cleanup tentato (confermato o segnalato): non più pendente.
                self._pending_cleanup = None
            return

        # ── 4xx SCHEMA/CONSTRAINT (400/409/422) → ha SUPERATO l'RLS, schema l'ha ──
        # respinto: nessuna riga scritta → RLS_WRITE_OPEN TENTATIVE, niente cleanup.
        if status in (400, 409, 422):
            exp = _expectation_for(table, cfg)
            # ORACOLO §15 anche qui (coerenza col ramo 201): se l'owner ha dichiarato
            # anon_insert=True la scrittura è ATTESA by design → CONFORME, si SOPPRIME
            # il finding e si emette posture write passed=True. Senza, la posture per
            # la STESSA tabella+config si ribalterebbe (passed True↔False) a seconda
            # che l'INSERT abbia fatto 201 o 4xx — incoerente. Qui nessuna riga è
            # scritta, quindi nessun cleanup.
            if exp is not None and exp.anon_insert:
                posture_checks.append(self._rls_write_expected_posture(
                    table, endpoint, target))
                return
            note = ("nessuna riga scritta; INSERT probabilmente permesso all'anon, "
                    "da confermare")
            violates = exp is not None and not exp.anon_insert
            personal = _has_personal_data(columns)
            severity = (Severity.CRITICAL
                        if violates or personal else Severity.HIGH)
            findings.append(self._rls_write_open_finding(
                table, endpoint, supabase_url, target, severity,
                Confidence.TENTATIVE, written=False, violates_matrix=violates,
                personal=personal, note=note))
            posture_checks.append(self._rls_write_exposed_posture(
                table, endpoint, target, severity))
            return

        # ── None / altro → INFO inconcludente (resilienza), nessuna scrittura ──
        log.info("canary: esito inconcludente su %r (status=%s) → nessun finding "
                 "di scrittura (§11.2)", table, status)

    @staticmethod
    def _canary_column(columns: list[str]) -> str | None:
        """Euristica di scelta colonna per il marker (§11.2): preferisci una colonna
        testuale plausibile (nome che NON suggerisce id/pk/numero/timestamp); in
        mancanza, la prima colonna disponibile. Se non ci sono colonne → None (body
        vuoto: un INSERT a vuoto su PostgREST darà 4xx, esito SICURO).

        Un marker stringa su una colonna non-testuale produrrà un type-mismatch
        (4xx) → trattato come 'nessuna riga scritta' (sicuro). Non indovinare tipi:
        l'euristica massimizza solo la probabilità di un INSERT pulito."""
        if not columns:
            return None
        _skip = ("id", "uuid", "pk", "created", "updated", "_at",
                 "date", "time", "num", "count", "price", "prezzo", "total")
        for c in columns:
            low = c.lower()
            if not any(tok in low for tok in _skip):
                return c
        return columns[0]

    def _canary_cleanup(
        self,
        base: str,
        headers: dict[str, str],
        table: str,
        endpoint: str,
        col: str | None,
        marker: str,
        post_resp,
        supabase_url: str | None,
        target: str,
        findings: list[Finding],
    ) -> None:
        """CLEANUP GARANTITO + VERIFICATO (§11.2 invariante 2). DELETE della SOLA
        riga canary: per PK (dalla rappresentazione tornata dal POST) se disponibile,
        altrimenti filtro sul marker `?<col>=eq.<marker>`.

        VERIFICA DELLA RIMOZIONE (non basta il 2xx!): il DELETE viene inviato con
        `Prefer: return=representation`, così PostgREST ci ridà l'ARRAY delle righe
        EFFETTIVAMENTE cancellate. Lo status 2xx da solo NON prova nulla: la
        misconfigurazione write-open più comune è anon con policy INSERT permissiva
        MA senza policy DELETE — in quel caso il DELETE gira sotto RLS, le righe
        vengono silenziosamente filtrate (0 cancellate) e l'API risponde 2xx (es.
        204). Trattare quel caso come 'cleanup riuscito' lascerebbe una riga canary
        ORFANA senza alcun finding: violerebbe l'invariante 2. Quindi confermiamo
        SOLO se status 2xx E la rappresentazione tornata dimostra ≥1 riga rimossa.
        Ogni altro esito (2xx ma 0 righe / body non interpretabile / non-2xx / None)
        è trattato ESATTAMENTE come cleanup NON confermato → Finding
        CANARY_CLEANUP_FAILED (CRITICAL). Erriamo verso il segnalare: un falso
        CANARY_CLEANUP_FAILED costa una verifica manuale (innocua); un falso
        'cleanup OK' lascerebbe garbage silenzioso sul target (inaccettabile).

        Il marker NON è un segreto: è incluso nell'evidence proprio per consentire
        la rimozione manuale. MAI lasciare una riga canary non rimossa senza un
        finding CRITICAL che la segnali."""
        delete_url = self._cleanup_url(base, endpoint, col, marker, post_resp)
        # Prefer: return=representation → la response porta le righe DAVVERO
        # cancellate; count=exact aggiunge il Content-Range come ulteriore prova.
        delete_headers = {**headers, "Prefer": "return=representation,count=exact"}
        resp = _delete(delete_url, delete_headers)
        status = getattr(resp, "status_code", None) if resp is not None else None
        status_ok = isinstance(status, int) and 200 <= status < 300
        confirmed = status_ok and self._delete_removed_a_row(resp)
        if confirmed:
            log.info("canary cleanup OK su %r (DELETE status=%s, riga rimossa "
                     "confermata) (§11.2)", table, status)
            return
        # CLEANUP NON CONFERMATO (non-2xx, OPPURE 2xx ma 0 righe rimosse / body non
        # interpretabile) → finding CRITICAL con istruzioni manuali. Un DELETE 2xx
        # che non cancella (RLS che filtra le righe) NON è un successo: la riga
        # resta sul target e va segnalata (invariante 2).
        log.warning("canary cleanup NON confermato su %r (status=%s, rimozione non "
                    "provata): emetto CANARY_CLEANUP_FAILED (§11.2)", table, status)
        findings.append(self._canary_cleanup_failed_finding(
            table, endpoint, marker, col, supabase_url, target, status))

    @staticmethod
    def _delete_removed_a_row(resp) -> bool:
        """Prova POSITIVA che il DELETE ha cancellato ≥1 riga (§11.2 invariante 2).

        Con `Prefer: return=representation` PostgREST mette nel body l'array delle
        righe EFFETTIVAMENTE cancellate: confermiamo SOLO se contiene ≥1 elemento
        (lista non vuota) o è un singolo oggetto-riga. Un body `[]` significa 0
        righe colpite (es. RLS che ha filtrato il DELETE pur rispondendo 2xx) →
        NON confermato. In più, se è presente l'header `Content-Range` da
        `count=exact`, lo si usa come prova ridondante: `*/0` o un range vuoto →
        0 righe. Se nulla è interpretabile, NON confermiamo (fail-safe: meglio un
        CANARY_CLEANUP_FAILED di troppo che una riga orfana silenziosa)."""
        # (a) Content-Range, se il server l'ha fornito: "0-0/1" (≥1) vs "*/0" (0).
        headers = getattr(resp, "headers", None)
        if headers is not None:
            try:
                cr = headers.get("Content-Range") or headers.get("content-range")
            except (AttributeError, TypeError):
                cr = None
            if isinstance(cr, str) and cr.strip():
                total = cr.split("/")[-1].strip()
                # "*/0" o ".../0" → 0 righe coinvolte → NON confermato.
                if total == "0":
                    return False
                # range presente e non vuoto (es. "0-0/1") → ≥1 riga rimossa.
                if not cr.lstrip().startswith("*"):
                    return True
        # (b) rappresentazione delle righe cancellate.
        try:
            data = resp.json() if resp is not None else None
        except (ValueError, TypeError):
            return False
        if isinstance(data, list):
            return len(data) > 0          # [] → 0 righe rimosse → NON confermato.
        if isinstance(data, dict):
            return bool(data)             # singolo oggetto-riga non vuoto → rimossa.
        return False

    @staticmethod
    def _cleanup_url(
        base: str,
        endpoint: str,
        col: str | None,
        marker: str,
        post_resp,
    ) -> str:
        """Costruisce l'URL del DELETE mirato alla SOLA riga canary.

        Preferenza: filtro per PK dalla rappresentazione tornata dal POST (più
        preciso). Fallback: filtro sul marker `?<col>=eq.<marker>`. Se nessuno dei
        due è possibile, filtra comunque per id se presente — non emettiamo mai un
        DELETE senza filtro (sarebbe una cancellazione di massa)."""
        row = None
        try:
            data = post_resp.json() if post_resp is not None else None
            if isinstance(data, list) and data:
                row = data[0]
            elif isinstance(data, dict):
                row = data
        except (ValueError, TypeError):
            row = None
        # PK: euristica 'id' dalla rappresentazione → filtro esatto per PK.
        if isinstance(row, dict) and "id" in row and row["id"] is not None:
            return f"{base}{endpoint}?id=eq.{row['id']}"
        # Fallback: filtro sul marker nella colonna scritta.
        if col is not None:
            return f"{base}{endpoint}?{col}=eq.{marker}"
        # Ultima spiaggia: nessun id, nessuna colonna nota → filtro sul marker su
        # una colonna convenzionale (non emettiamo MAI un DELETE non filtrato).
        return f"{base}{endpoint}?marker=eq.{marker}"

    # ── costruttori di Finding/PostureCheck del canary (§11.2) ───────────────

    def _canary_skipped_no_schema_finding(
        self, ctx: RunContext, target: str,
    ) -> Finding:
        """Segnale ONESTO INFO `CANARY_SKIPPED_NO_SCHEMA` (§11.2): nel path
        FALLBACK via_bundle (OpenAPI chiusa) il canary scrive sulla superficie GIÀ
        PROVATA LEGGIBILE dall'anon (`read_open`) — ma se NESSUNA tabella è
        risultata anon-leggibile non c'è una superficie cleanup-safe su cui testare
        la scrittura, quindi NON si scrive. Lo si DICHIARA invece di tacere (sarebbe
        fuorviante: 'nessun finding di scrittura' non significa 'scrittura
        testata')."""
        location = Location(endpoint="/rest/v1/", url=ctx.fingerprint.supabase_url
                            or ctx.target_cfg.supabase_url)
        evidence = ("canary write saltato (via bundle): nessuna tabella "
                    "anon-leggibile su cui testare la scrittura")
        description = (
            "Il canary write (§11.2) è stato SALTATO per questa superficie: le "
            "tabelle sono state enumerate dal bundle JS (OpenAPI chiusa) e NESSUNA "
            "di esse è risultata anon-leggibile in questa run. La scrittura canary "
            "via bundle viene testata SOLO sulle tabelle già provate leggibili "
            "dall'anon (`read_open`) — le più probabilmente anche write-aperte e le "
            "uniche su cui un cleanup è realisticamente verificabile. Senza alcuna "
            "tabella anon-leggibile non c'è una superficie cleanup-safe su cui "
            "scrivere, perciò NON si scrive. La verifica delle policy INSERT resta "
            "INCOMPLETA per questa superficie (verifica onesta, non un via libera)."
        )
        return Finding(
            finding_id=_finding_id("supabase", "CANARY_SKIPPED_NO_SCHEMA", location),
            module="supabase",
            rule_id="CANARY_SKIPPED_NO_SCHEMA",
            title="Canary write saltato: nessuna tabella anon-leggibile (via bundle)",
            severity=Severity.INFO,
            confidence=Confidence.TENTATIVE,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_WRITE_OPEN",
            owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING,
        )

    @staticmethod
    def _rls_write_open_finding(
        table: str,
        endpoint: str,
        supabase_url: str | None,
        target: str,
        severity: Severity,
        confidence: Confidence,
        *,
        written: bool,
        violates_matrix: bool,
        personal: bool,
        note: str | None,
    ) -> Finding:
        """Finding `RLS_WRITE_OPEN` (§11.2): l'anon può scrivere la tabella.

        `written=True`  → una riga è stata davvero inserita (201): FIRM.
        `written=False` → 4xx schema/constraint: la richiesta ha SUPERATO l'RLS ma
                          lo schema l'ha respinta (nessuna riga) → TENTATIVE + nota.
        Severità: HIGH di base; CRITICAL se viola la matrice (anon_insert=False)
        OPPURE colonne personali. Evidence NON segreta (esito + nota)."""
        evidence = (
            f"POST anonimo a {endpoint} accettato (riga inserita)"
            if written else
            f"POST anonimo a {endpoint}: la richiesta ha superato l'RLS "
            f"(respinta dallo schema, nessuna riga scritta)"
        )
        matrix_note = (
            " La matrice di attese (§15) dichiara anon_insert=false per questa "
            "tabella, ma la scrittura è accettata: **viola la matrice (§15)** → "
            "severità CRITICAL."
            if violates_matrix else ""
        )
        personal_note = (
            " I nomi colonna suggeriscono dati personali → severità CRITICAL."
            if personal and not violates_matrix else ""
        )
        note_str = f" ({note})" if note else ""
        description = (
            f"Un POST anonimo a {endpoint} con la sola anon key è stato "
            f"{'accettato (riga inserita)' if written else 'ammesso dall RLS'} "
            f"sulla tabella '{table}': manca una policy INSERT che limiti chi può "
            f"scrivere (§11.2). Le scritture aperte sono più gravi delle letture "
            f"(defacement/frode/distruzione dati)."
            + note_str + matrix_note + personal_note
        )
        # Stessa convenzione dei finding read (§11.1): url = supabase_url, endpoint
        # = la tabella. Così il finding_id (§16) è stabile per tabella tra le run.
        location = Location(endpoint=endpoint, url=supabase_url)
        return Finding(
            finding_id=_finding_id("supabase", "RLS_WRITE_OPEN", location),
            module="supabase",
            rule_id="RLS_WRITE_OPEN",
            title=(f"RLS di scrittura aperta sulla tabella '{table}'"
                   + (" (viola la matrice §15)" if violates_matrix else "")
                   + (" (dati personali)" if personal and not violates_matrix else "")),
            severity=severity,
            confidence=confidence,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_WRITE_OPEN",
            owasp=["A01:2021"],
            gdpr_relevant=personal,
            intrusion_used=IntrusionLevel.MUTATING,
        )

    @staticmethod
    def _canary_cleanup_failed_finding(
        table: str,
        endpoint: str,
        marker: str,
        col: str | None,
        supabase_url: str | None,
        target: str,
        status,
    ) -> Finding:
        """Finding `CANARY_CLEANUP_FAILED` (§11.2 invariante 2): una riga canary è
        stata inserita ma il DELETE di cleanup NON è stato confermato. CRITICAL/FIRM.
        L'evidence include tabella + marker + istruzione di DELETE manuale: il
        marker NON è un segreto, va incluso per consentire la rimozione."""
        location = Location(endpoint=endpoint, url=supabase_url)
        manual_filter = f"{col}=eq.{marker}" if col else f"marker=eq.{marker}"
        evidence = (
            f"tabella={table}; marker={marker}; DELETE non confermato "
            f"(status={status}). Rimozione manuale: DELETE FROM {table} WHERE "
            f"{col or '<colonna_marker>'} = '{marker}'  oppure via PostgREST "
            f"DELETE {endpoint}?{manual_filter}"
        )
        description = (
            f"Il canary write ha INSERITO una riga marcata nella tabella '{table}' "
            f"ma il cleanup automatico (DELETE) NON è stato confermato "
            f"(status={status}). **Resta una riga canary da rimuovere a mano.** "
            f"Marker (non segreto, serve per la rimozione): `{marker}`. "
            f"Esegui: `DELETE FROM {table} WHERE "
            f"{col or '<colonna_marker>'} = '{marker}';` oppure via PostgREST "
            f"`DELETE {endpoint}?{manual_filter}` con la stessa chiave. (§11.2)"
        )
        return Finding(
            finding_id=_finding_id("supabase", "CANARY_CLEANUP_FAILED", location),
            module="supabase",
            rule_id="CANARY_CLEANUP_FAILED",
            title=f"Cleanup del canary fallito sulla tabella '{table}' (rimozione manuale)",
            severity=Severity.CRITICAL,
            confidence=Confidence.FIRM,
            target=target,
            location=location,
            evidence=evidence,
            description=description,
            remediation_ref="RLS_WRITE_OPEN",
            owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING,
        )

    @staticmethod
    def _rls_write_protected_posture(
        table: str, endpoint: str, target: str, status,
    ) -> PostureCheck:
        """PostureCheck positivo `POSTURE_RLS_WRITE_<tabella>` (§11.2): il POST
        anonimo è stato RIFIUTATO (401/403) → esiste una policy INSERT che protegge."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_WRITE_{table}",
            title=f"Policy INSERT attiva sulla tabella '{table}'",
            passed=True,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"POST anonimo a {endpoint} rifiutato (status={status}): l'anon non "
                f"può scrivere → policy INSERT presente (§11.2)."
            ),
            remediation_ref="RLS_WRITE_OPEN",
        )

    @staticmethod
    def _rls_write_expected_posture(
        table: str, endpoint: str, target: str,
    ) -> PostureCheck:
        """PostureCheck CONFORME alla matrice (§15): anon_insert=true → la scrittura
        anon è ATTESA by design → POSTURE_RLS_WRITE_<t> passed=True (finding
        RLS_WRITE_OPEN soppresso). Lo score resta onesto (§17)."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_WRITE_{table}",
            title=f"Tabella '{table}' scrivibile dall'anon per scelta (§15)",
            passed=True,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"POST anonimo a {endpoint} accettato, MA la matrice di attese (§15) "
                f"dichiara anon_insert=true per '{table}': scrittura anon ATTESA → "
                f"non un'esposizione. Finding RLS_WRITE_OPEN soppresso; lo score "
                f"resta onesto (§17). (La riga canary è stata comunque rimossa.)"
            ),
            remediation_ref="RLS_WRITE_OPEN",
        )

    @staticmethod
    def _rls_write_exposed_posture(
        table: str, endpoint: str, target: str, severity: Severity,
    ) -> PostureCheck:
        """PostureCheck FALLITO `POSTURE_RLS_WRITE_<tabella>` (§11.2/§17): l'anon
        scrive (o l'INSERT ha superato l'RLS) → manca la policy INSERT. Mutuamente
        esclusivo con `_rls_write_protected_posture`/`_rls_write_expected_posture`:
        per tabella si emette UN solo POSTURE_RLS_WRITE_<t> (passed True XOR False).
        `severity_if_failed` coincide con la severità del Finding RLS_WRITE_OPEN."""
        return PostureCheck(
            check_id=f"POSTURE_RLS_WRITE_{table}",
            title=f"Policy INSERT assente sulla tabella '{table}' (scrivibile dall'anon)",
            passed=False,
            severity_if_failed=severity,
            target=target,
            detail=(
                f"POST anonimo a {endpoint} non rifiutato dall'RLS: l'anon può "
                f"scrivere → manca una policy INSERT (§11.2). Vedi il Finding "
                f"RLS_WRITE_OPEN per i dettagli."
            ),
            remediation_ref="RLS_WRITE_OPEN",
        )
