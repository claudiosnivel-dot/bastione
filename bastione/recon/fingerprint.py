"""Fingerprint read-only del target (§8). Intrusione: READ_ONLY.

Pipeline (ogni passo degrada se un tool manca — L06, mai un crash):
  1. GET base URL (httpx lib)  → resolved_urls, response_headers, cloudflare_fronted
  2. whatweb (opzionale)        → technologies, is_wordpress
  3. katana (opzionale) + fallback built-in `<script src>` → bundle JS da ispezionare
  4. estrazione Supabase custom → supabase_url (is_supabase=True) + anon_key

**Scelte M0 (LOCKED finché non riviste con Claudio):**
- Il passo 1 usa la **libreria** `httpx`, non il binario `httpx` di projectdiscovery:
  per un singolo base_url copre tutto (URL finale, header, redirect, Cloudflare) ed
  è già dipendenza obbligatoria → niente binario opzionale ridondante in M0.
- La **scoperta dei bundle non dipende da katana** (§8): il fallback `<script src>`
  via httpx-lib è sempre attivo, altrimenti la DoD M0 (anon key) sarebbe
  irraggiungibile con katana assente.

**Framing di sicurezza (§8/§10, non confondere mai):** l'`anon_key` è un JWT con
claim `role:anon`, **pubblica per design** (sta nel client) → la estraiamo per
testare cosa l'anonimo raggiunge (è RLS che deve proteggere). La service_role key
NON è una anon key: `extract_anon_key` la ignora di proposito; trovarla nel bundle
è una fuga critica, competenza del modulo secrets (§10), non del recon.

I confini di I/O (`_fetch`, `_run_whatweb`, `_run_katana`) sono funzioni a sé così
da essere monkeypatchabili nei test (recon offline) — come per il gate (§7).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bastione.models import Fingerprint
from bastione.recon.api_surface import extract_api_paths

log = logging.getLogger("bastione.recon")

_HTTP_TIMEOUT = 15.0

# `<script ... src="...">` — solo tag con src (gli script inline non hanno bundle).
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*?\bsrc=[\"']([^\"']+)[\"']", re.I)
# https://<ref>.supabase.co — il ref è l'id di progetto (alfanumerico minuscolo).
_SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]+\.supabase\.co")
# JWT a tre segmenti base64url che inizia con l'header tipico `{"alg":...}` → "eyJ".
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# `.from('NAME')` / `.from("NAME")` — la entry del query-builder PostgREST nel
# client Supabase. NAME = identificatore relazione (`[A-Za-z_][A-Za-z0-9_]*`),
# opzionalmente con UN prefisso schema (`schema.tabella`). L'intero literal deve
# matchare (apici di chiusura subito dopo il nome) → scarta url/spazi/espressioni.
_TABLE_FROM_RE = re.compile(
    r"\.from\(\s*"
    r"(['\"])"
    r"([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)"
    r"\1"
    r"\s*\)"
)
# Builtin JS che espongono un `.from(...)` NON-PostgREST (Array.from, typed-array,
# ecc.): un loro `.from('abc')` non è una tabella, va scartato (§8/§11.1). Il
# nome del costruttore va registrato (per offset) e usato come post-filtro in
# `extract_table_names` — la regex Python non supporta un lookbehind a lunghezza
# variabile sull'alternanza dei builtin, quindi si confronta l'offset esatto del
# `.from(` (v. _JS_BUILTIN_FROM_RE e il post-filtro più sotto).
_JS_FROM_BUILTINS: tuple[str, ...] = (
    "Array",
    "String",
    "Buffer",
    "Object",
    "Number",
    "Promise",
    "Date",
    "Int8Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
)
# Costruttore builtin (eventualmente seguito da spazi) prima del `.from(` —
# usato come post-filtro: se un `.from('x')` è preceduto da `Array`/typed-array/
# ecc. NON è una tabella. Il `(?:^|[^A-Za-z0-9_$])` davanti al nome è il confine
# di parola che evita di scambiare `MyArray` per `Array`; `\s*` tollera lo spazio
# tra nome e `.from(` (in bundle MINIFICATI — l'unico input reale, download
# same-host del recon — non c'è spazio, ma il filtro resta corretto anche se ne
# comparisse uno). Il gruppo catturante include il `.` di `.from(` così possiamo
# allineare l'offset del `.from(` builtin con quello del match-tabella (un
# builtin lontano non sopprime una tabella vicina).
# NB: i commenti `/* */` tra nome e `.from(` non sono coperti (servirebbe un parse
# JS): irrilevante sui bundle minificati, dove i commenti sono già rimossi.
_JS_BUILTIN_FROM_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_$])(?:" + "|".join(_JS_FROM_BUILTINS) + r")\s*(\.from\()"
)
# Chiave pubblica nel formato nuovo 2026 (§4.2): `sb_publishable_<token>`.
_PUBLISHABLE_RE = re.compile(r"sb_publishable_[A-Za-z0-9]+")
# `.rpc('fn')` / `.rpc("fn", {...})` — entry RPC del client Supabase (§3/§4.2).
_RPC_FROM_RE = re.compile(r"\.rpc\(\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1")
# `.storage.from('bucket')` — entry storage del client (nomi bucket, §4.2).
_STORAGE_FROM_RE = re.compile(r"\.storage\s*\.\s*from\(\s*(['\"])([A-Za-z0-9._-]+)\1")
# Il `.from(` di `.storage.from(...)` (group 1): è un bucket, MAI una relazione
# PostgREST → escluso da `extract_table_names` come i builtin JS.
_STORAGE_DOT_FROM_RE = re.compile(r"\.storage\s*(\.\s*from\()")


# ─── funzioni pure (la gemma): nessuna I/O, testate con input reali ─────────

def extract_script_srcs(html: str, base_url: str) -> list[str]:
    """URL (assoluti) dei bundle JS referenziati da `<script src>`, risolti contro
    `base_url`. Fallback obbligatorio alla scoperta bundle senza katana (§8)."""
    return [urljoin(base_url, src) for src in _SCRIPT_SRC_RE.findall(html)]


def extract_supabase_url(text: str) -> str | None:
    """Primo `https://<ref>.supabase.co` trovato nel testo, o None."""
    m = _SUPABASE_URL_RE.search(text)
    return m.group(0) if m else None


def _decode_jwt_payload(token: str) -> dict | None:
    """Payload (claims) di un JWT, o None se non decodificabile. Nessuna verifica
    di firma: ci interessa solo il claim `role` per distinguere anon/service_role."""
    try:
        body = token.split(".")[1]
        body += "=" * (-len(body) % 4)          # ripristina il padding base64url
        claims = json.loads(base64.urlsafe_b64decode(body))
    except (IndexError, ValueError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


def extract_anon_key(text: str) -> str | None:
    """Anon key Supabase = JWT con claim `role == "anon"` (pubblica per design).
    Ignora di proposito la service_role e ogni altro JWT: confonderle tratterebbe
    una fuga critica come chiave innocua (§8/§10)."""
    for token in _JWT_RE.findall(text):
        claims = _decode_jwt_payload(token)
        if claims and claims.get("role") == "anon":
            return token
    return None


def extract_public_key(text: str) -> tuple[str | None, str | None]:
    """Chiave pubblica Supabase: JWT `role:anon` (legacy) OPPURE `sb_publishable_`
    (nuovo formato 2026, §4.2). Ritorna `(chiave, kind)` con kind in
    {"legacy_jwt","publishable"}, o `(None, None)`. Preferisce la legacy quando
    entrambe presenti (deterministico). La service_role NON è una chiave pubblica:
    `extract_anon_key` la ignora già (§8/§10)."""
    legacy = extract_anon_key(text)
    if legacy is not None:
        return legacy, "legacy_jwt"
    m = _PUBLISHABLE_RE.search(text)
    if m is not None:
        return m.group(0), "publishable"
    return None, None


def extract_rpc_names(text: str) -> list[str]:
    """Nomi RPC referenziati da `.rpc('...')` nel bundle (§4.2). Puro, dedup+ordina."""
    return sorted({m.group(2) for m in _RPC_FROM_RE.finditer(text)})


def extract_bucket_names(text: str) -> list[str]:
    """Nomi bucket da `.storage.from('...')` nel bundle (§4.2). Puro, dedup+ordina."""
    return sorted({m.group(2) for m in _STORAGE_FROM_RE.finditer(text)})


def extract_table_names(text: str) -> list[str]:
    """Nomi tabella PostgREST referenziati dal client Supabase nel bundle (§8).

    Estrae i nomi da `.from('NAME')` / `.from("NAME")` — la entry del query-builder
    PostgREST. NAME valido = identificatore relazione (`[A-Za-z_][A-Za-z0-9_]*`),
    con opzionale UN prefisso schema (`schema.tabella`). Url, spazi ed espressioni
    non sono identificatori → scartati dal regex stesso.

    Scarta i falsi positivi dei builtin JS (`Array.from('abc')`, typed-array,
    `String/Buffer/Object/...`): il loro `.from(...)` non è una relazione. Il
    confronto è puramente testuale — nessuna I/O, nessun download: lavora SOLO sul
    testo già in memoria (owned-only, §7). Dedup + ordina (deterministico)."""
    # Offset (inizio del `.from(`) di ogni `.from(` preceduto da un builtin JS:
    # quei `.from(` non sono PostgREST. group(1) è `.from(`, quindi il suo start
    # è l'offset del punto — lo stesso punto da cui parte il match-tabella.
    builtin_dots = {m.start(1) for m in _JS_BUILTIN_FROM_RE.finditer(text)}
    # Idem per `.storage.from('bucket')`: è un bucket (extract_bucket_names), non una
    # tabella — altrimenti finirebbe anche nel RLS test via bundle.
    builtin_dots |= {m.start(1) for m in _STORAGE_DOT_FROM_RE.finditer(text)}

    names: set[str] = set()
    for m in _TABLE_FROM_RE.finditer(text):
        # _TABLE_FROM_RE inizia col `.` di `.from(`: se quell'offset è un builtin,
        # scarta (un builtin lontano non tocca una tabella vicina: confronto esatto).
        if m.start() in builtin_dots:
            continue
        names.add(m.group(2))
    return sorted(names)


def detect_cloudflare(headers: dict[str, str]) -> bool:
    """Cloudflare davanti all'origine: header `cf-ray` presente, o `server`
    contiene "cloudflare" (case-insensitive sui nomi header)."""
    lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    return "cf-ray" in lower or "cloudflare" in lower.get("server", "")


def is_wordpress(technologies: list[dict]) -> bool:
    return any("wordpress" in str(t.get("name", "")).lower() for t in technologies)


# ─── confini di I/O (monkeypatchati nei test) ───────────────────────────────

def _fetch(url: str):
    """GET read-only via httpx-lib, redirect seguiti. Ritorna la response (con
    `.url`/`.headers`/`.text`) o None se httpx manca o la richiesta fallisce (L06)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: recon HTTP non disponibile (§8)")
        return None
    try:
        return httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("GET %s fallita: %s", url, exc)
        return None


def _run_whatweb(target: str) -> list[dict]:
    """`technologies` via whatweb (opzionale). Degrada a [] se il binario manca o
    l'esecuzione/parsing fallisce — mai un crash (§8)."""
    if shutil.which("whatweb") is None:
        log.info("whatweb assente: salto il fingerprint delle tecnologie (§8)")
        return []
    try:
        proc = subprocess.run(
            ["whatweb", "--log-json=-", "--color=never", "--quiet", target],
            capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("whatweb fallito: %s", exc)
        return []
    return _parse_whatweb(proc.stdout)


def _parse_whatweb(stdout: str) -> list[dict]:
    """whatweb --log-json → [{"name","version","confidence"}]. Best-effort: una
    riga malformata viene saltata (non scarta le valide); qualunque altro errore → []."""
    if stdout.strip().startswith("["):
        try:
            records = json.loads(stdout)
        except json.JSONDecodeError:
            return []
    else:
        records = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                log.debug("whatweb: riga non-JSON ignorata: %r", line[:80])
    techs: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for name, hits in (rec.get("plugins") or {}).items():
            version = (hits.get("version") or [None])
            techs.append({"name": name,
                          "version": version[0] if version else None,
                          "confidence": "whatweb"})
    return techs


def _run_katana(target: str) -> list[str]:
    """`endpoints` via katana crawling (opzionale). Degrada a [] se il binario
    manca o l'esecuzione fallisce. NB: la scoperta bundle non dipende da qui."""
    if shutil.which("katana") is None:
        log.info("katana assente: uso il solo fallback <script src> (§8)")
        return []
    try:
        proc = subprocess.run(
            ["katana", "-u", target, "-silent", "-jc"],
            capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("katana fallito: %s", exc)
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


# ─── orchestrazione ─────────────────────────────────────────────────────────

def fingerprint(target: str, run_dir: Path | None = None) -> Fingerprint:
    """Fingerprint read-only di `target` (§8). Se `run_dir` è dato, scrive anche
    `run_dir/fingerprint.json`. Read-only by design: solo GET e tool passivi; la
    proprietà del target è garantita a monte dal gate in LOAD (§7), non qui."""
    resolved_urls: list[str] = []
    response_headers: dict[str, str] = {}
    cloudflare = False
    bundle_urls: list[str] = []
    base_host = ""

    resp = _fetch(target)
    if resp is not None:
        final_url = str(resp.url)
        resolved_urls = [final_url]
        response_headers = dict(resp.headers)
        cloudflare = detect_cloudflare(response_headers)
        bundle_urls = extract_script_srcs(resp.text, final_url)
        base_host = urlparse(final_url).netloc

    technologies = _run_whatweb(target)
    endpoints = _run_katana(target)

    # Bundle da ispezionare: <script src> (sempre) + eventuali .js da katana,
    # de-duplicati preservando l'ordine. Mai dipendere dal solo katana (§8).
    js_urls = list(dict.fromkeys(
        bundle_urls + [e for e in endpoints if e.endswith(".js")]))

    supabase_url: str | None = None
    anon_key: str | None = None
    key_kind: str | None = None
    discovered: set[str] = set()
    buckets_acc: set[str] = set()
    rpcs_acc: set[str] = set()
    api_paths_acc: set[str] = set()
    for url in js_urls:
        # Owned-only (§7/§4.2): non scarichiamo bundle su host esterni non
        # dichiarati. La chiave Supabase sta nel bundle same-origin dell'app; gli
        # script di terzi (CDN/analytics) non la contengono → zero perdita.
        if urlparse(url).netloc != base_host:
            log.info("bundle su host esterno ignorato (owned-only, §7): %s", url)
            continue
        jresp = _fetch(url)
        if jresp is None:
            continue
        supabase_url = supabase_url or extract_supabase_url(jresp.text)
        # §4.2 M5: la chiave pubblica può essere il JWT legacy `role:anon` oppure la
        # nuova `sb_publishable_…`. `anon_key` porta ENTRAMBI i tipi; `key_kind` ne
        # registra il formato. La service_role resta ignorata (extract_anon_key).
        if anon_key is None:
            k, kk = extract_public_key(jresp.text)
            if k is not None:
                anon_key, key_kind = k, kk
        # Scoperta bucket/RPC dal bundle same-host (§4.2): funzioni PURE su testo in
        # memoria, nessun nuovo download (owned-only, §7). Fallback quando lo storage
        # non elenca all'anon e l'OpenAPI è chiusa (usati dai sottomoduli, Task 21).
        buckets_acc.update(extract_bucket_names(jresp.text))
        rpcs_acc.update(extract_rpc_names(jresp.text))
        # Table discovery (§8): aggrega i nomi `.from('...')` da TUTTI i bundle
        # same-host già scaricati. Funzione PURA su testo in memoria: nessun nuovo
        # download (owned-only). Non c'è break su url/anon_key — altrimenti i
        # bundle successivi (che possono referenziare altre tabelle) sarebbero
        # persi; restiamo comunque entro gli stessi host owned già dichiarati.
        discovered.update(extract_table_names(jresp.text))
        # Scoperta superficie API (M4.0): aggrega i path `/api/...` referenziati
        # nei bundle same-host già scaricati, in modo analogo alle tabelle. Funzione
        # PURA su testo in memoria: nessun nuovo download (owned-only, §7).
        api_paths_acc.update(extract_api_paths(jresp.text))

    discovered_tables = sorted(discovered)
    discovered_api_paths = sorted(api_paths_acc)

    fp = Fingerprint(
        target=target,
        resolved_urls=resolved_urls,
        technologies=technologies,
        is_wordpress=is_wordpress(technologies),
        # is_supabase è guidato dalla rilevazione dell'URL PostgREST (§8): evita lo
        # stato incoerente (True con supabase_url=None) che farebbe partire il
        # modulo supabase senza un URL su cui mappare la superficie (§9/§11.1).
        is_supabase=supabase_url is not None,
        supabase_url=supabase_url,
        supabase_key_kind=key_kind,
        discovered_tables=discovered_tables,
        discovered_buckets=sorted(buckets_acc),
        discovered_rpcs=sorted(rpcs_acc),
        discovered_api_paths=discovered_api_paths,
        anon_key=anon_key,
        cloudflare_fronted=cloudflare,
        endpoints=endpoints,
        response_headers=response_headers,
    )

    if run_dir is not None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "fingerprint.json").write_text(
            fp.model_dump_json(indent=2), encoding="utf-8")

    return fp
