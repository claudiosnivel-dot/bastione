"""Prova generale OFFLINE della validazione live M4+M5 (spec M5–M9 §4.11) — S16.

La validazione live chiede: un progetto Supabase NUOVO (solo chiavi 2026) dietro un
sandbox, con debolezze volute (bucket elencabile, RPC non protetta, signup aperto
non dichiarato) → Bastione le trova → dopo la correzione `verify` le dà chiuse.

Qui la stessa sceneggiatura gira contro una "internet virtuale" IN-PROCESS: si
sostituisce solo `httpx.HTTPTransport.handle_request`, cioè lo strato sotto ogni
`httpx.get/post/request` del codice. Tutto il resto è REALE: CLI, gate (incluso
l'ownership challenge via well-known), recon, moduli, sottomoduli Supabase, baseline,
report, verify. A differenza dei test unitari (che monkeypatchano i confini `_get`/
`_post` di ogni modulo) qui passano davvero URL, query, header e body costruiti dal
codice, e il server virtuale si comporta come il gateway Supabase reale:
- la chiave va nell'header `apikey` e deve essere IDENTICA a quella del progetto
  (una chiave troncata → 401 "Invalid API key", come in produzione);
- `Authorization: Bearer <chiave>` è ammesso solo se uguale all'`apikey`
  (compatibilità documentata da Supabase per le chiavi `sb_publishable_`);
- la root OpenAPI `/rest/v1/` è chiusa all'anon (401), come sull'hosted moderno.

Nessun socket: un host diverso dai due dichiarati (sito + progetto Supabase) fa
fallire il test (owned-only, §7). Nessun processo esterno (`which` → None).

Cosa NON prova (resta alla validazione live, outward-facing e gated): che il
Supabase reale risponda come il server virtuale. Il runbook è in
`docs/live-validation/2026-10-11-runbook-validazione-live-m4-m5.md`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

import bastione.cli as cli_mod
import bastione.gate as gate_mod
from bastione.cli import app
from bastione.enums import IntrusionLevel, Severity, Status
from bastione.orchestrator import Orchestrator

runner = CliRunner()

TARGET = "rehearsal"
SITE_HOST = "sandbox-2026.bastione.test"
SUPA_REF = "sbxrehearsal2026abcd"
SUPA_HOST = f"{SUPA_REF}.supabase.co"
OWNERSHIP_TOKEN = "bastione-ownership-rehearsal-7f3c2a9e"

# Chiave publishable nel formato reale (22 base64url con `-`/`_` + `_` + 8 di
# checksum): esercita la regex del recon sul caso che prima la troncava.
PUBLISHABLE = "sb_publishable_Re-hEaRsAl2026_xYzAbC1_pQ9rStUv"

# Sentinelle P8: righe e nomi di oggetti che NON devono mai uscire dai finding/report.
SENTINEL_EMAIL = "sentinella.p8@cliente-segreto.example"
SENTINEL_OBJECT = "contratto_mario_rossi_SENTINELLA.pdf"

BUNDLE_PATH = "/assets/index-a1b2c3d4.js"
BUNDLE_JS = (
    f'const SUPABASE_URL="https://{SUPA_HOST}";'
    f'const SUPABASE_KEY="{PUBLISHABLE}";'
    "const sb=createClient(SUPABASE_URL,SUPABASE_KEY);"
    "sb.from('ordini').select('*');"
    "sb.from('fatture').select('*');"
    "sb.storage.from('documenti').list();"
    "sb.rpc('lista_clienti');"
)
INDEX_HTML = (
    "<!doctype html><html><head><title>Sandbox 2026</title></head><body>"
    f'<div id="app"></div><script type="module" src="{BUNDLE_PATH}"></script>'
    "</body></html>"
)
SECURITY_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}

TARGET_TOML = f"""
name = "{TARGET}"
base_url = "https://{SITE_HOST}"
environment = "staging"
ownership = "owned"
ownership_token = "{OWNERSHIP_TOKEN}"

[notify]
channel = "none"

# signup_open NON dichiarato apposta (spec §4.11: "signup aperto non dichiarato")
[expectations.auth]
anonymous_signin = false

[[expectations.bucket]]
name = "documenti"
anon_list = false
"""

# Sottomoduli/percorsi che esistono SOLO a PROBE: a READ_ONLY non devono partire.
_PROBE_PATHS_SUPA = ("/storage/v1/", "/rest/v1/rpc/", "/graphql/v1")
_PROBE_PATHS_SITE = ("/.env", "/.git/", "/openapi.json", "/@vite/client", ".map",
                     "/.well-known/bastione-ownership.txt")


class VirtualInternet:
    """Sito sandbox + progetto Supabase 2026 simulati. `fixed=False` = debolezze
    volute presenti; `fixed=True` = l'owner le ha corrette."""

    def __init__(self) -> None:
        self.fixed = False
        self.requests: list[httpx.Request] = []
        self.foreign: list[str] = []

    # ── dispatch ────────────────────────────────────────────────────────────
    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host == SITE_HOST:
            return self._site(request)
        if host == SUPA_HOST:
            return self._supabase(request)
        self.foreign.append(f"{request.method} {request.url}")
        raise httpx.ConnectError("host non dichiarato (owned-only)", request=request)

    @staticmethod
    def _json(request, status, payload, headers=None):
        return httpx.Response(status, json=payload, headers=headers or {}, request=request)

    # ── sito statico (Vercel-like) ──────────────────────────────────────────
    def _site(self, request):
        path = request.url.path
        if request.method == "GET" and path == "/":
            return httpx.Response(200, text=INDEX_HTML, request=request, headers={
                "content-type": "text/html; charset=utf-8", "server": "Vercel",
                **SECURITY_HEADERS})
        if request.method == "GET" and path == BUNDLE_PATH:
            return httpx.Response(200, text=BUNDLE_JS, request=request, headers={
                "content-type": "application/javascript"})
        if request.method == "GET" and path == "/.well-known/bastione-ownership.txt":
            return httpx.Response(200, text=OWNERSHIP_TOKEN + "\n", request=request,
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404, text="Not Found", request=request,
                              headers={"content-type": "text/plain"})

    # ── progetto Supabase (gateway + PostgREST + Storage + Auth + GraphQL) ──
    def _supabase(self, request):
        apikey = request.headers.get("apikey")
        auth = request.headers.get("authorization")
        # Gateway: chiave nell'apikey, identica a quella del progetto. Bearer con una
        # chiave publishable ammesso solo se coincide con l'apikey (doc Supabase).
        if apikey != PUBLISHABLE or (auth is not None and auth != f"Bearer {apikey}"):
            return self._json(request, 401, {"message": "Invalid API key"})

        path, method = request.url.path, request.method
        if method == "GET" and path == "/rest/v1/":
            return self._json(request, 401, {
                "message": "Only the service_role API key can be used for this endpoint"})
        if method == "GET" and path == "/rest/v1/ordini":
            return self._json(request, 200, [])             # RLS attiva, nessuna riga
        if method == "GET" and path == "/rest/v1/fatture":
            # Nuovo default 30/10/2026: nessun GRANT → 42501 ("protetto ma fragile").
            return self._json(request, 401, {
                "code": "42501", "message": "permission denied for table fatture"})
        if method == "POST" and path == "/storage/v1/object/list/documenti":
            if self.fixed:
                return self._json(request, 200, [])
            return self._json(request, 200, [
                {"name": SENTINEL_OBJECT, "id": "b1", "metadata": {"size": 1024}}])
        if method == "GET" and path == "/rest/v1/rpc/lista_clienti":
            if self.fixed:
                return self._json(request, 401, {
                    "code": "42501", "message": "permission denied for function lista_clienti"})
            return self._json(request, 200, [
                {"id": 1, "email": SENTINEL_EMAIL, "nome": "Mario"}])
        if method == "GET" and path == "/auth/v1/settings":
            return self._json(request, 200, {
                "external": {"email": True, "anonymous_users": False},
                "disable_signup": self.fixed,
                "mailer_autoconfirm": False,
            })
        if method == "POST" and path == "/graphql/v1":
            return self._json(request, 200, {
                "errors": [{"message": "Unknown field '__schema'"}]})
        return self._json(request, 404, {"message": "not found"})

    # ── viste sul log ───────────────────────────────────────────────────────
    def supabase_requests(self):
        return [r for r in self.requests if r.url.host == SUPA_HOST]

    def site_paths(self):
        return [r.url.path for r in self.requests if r.url.host == SITE_HOST]


@pytest.fixture
def internet(monkeypatch, tmp_path):
    """Internet virtuale + factory dell'Orchestrator su tmp_path + nessun processo
    esterno. Restituisce (VirtualInternet, lista degli Orchestrator creati)."""
    vi = VirtualInternet()
    # Il trasporto virtuale non apre connessioni: niente pool né contesto TLS (che
    # su Windows costa ~0.3 s per client e renderebbe lenta la prova).
    monkeypatch.setattr(httpx.HTTPTransport, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(httpx.HTTPTransport, "__enter__", lambda self: self)
    monkeypatch.setattr(httpx.HTTPTransport, "__exit__", lambda self, *a: None)
    monkeypatch.setattr(httpx.HTTPTransport, "close", lambda self: None)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request",
                        lambda self, request: vi.handle(request))
    # Nessun tool esterno (whatweb/katana/nuclei/zap/...): degradano a SKIPPED.
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

    def _no_subprocess(*a, **k):
        raise AssertionError(f"processo esterno non ammesso nella prova generale: {a!r}")

    monkeypatch.setattr(subprocess, "run", _no_subprocess)
    # Ownership solo via well-known (virtuale): niente DNS reale.
    monkeypatch.setattr(gate_mod, "_check_dns_txt", lambda cfg: False)

    (tmp_path / "targets").mkdir()
    (tmp_path / "targets" / f"{TARGET}.toml").write_text(TARGET_TOML, encoding="utf-8")
    created: list[Orchestrator] = []

    def _factory(*args, **kwargs):
        orch = Orchestrator(targets_dir=tmp_path / "targets",
                            runs_root=tmp_path / "runs",
                            baselines_root=tmp_path / "baselines")
        created.append(orch)
        return orch

    monkeypatch.setattr(cli_mod, "Orchestrator", _factory)

    # Guardia: la sostituzione del trasporto è attiva PRIMA di far partire la
    # pipeline (altrimenti si rischierebbe una richiesta reale a supabase.co).
    guard = httpx.get(f"https://{SUPA_HOST}/__guard__", headers={"apikey": PUBLISHABLE})
    assert guard.status_code == 404 and vi.requests, "trasporto virtuale non attivo"
    vi.requests.clear()
    return vi, created


def _rules(findings) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.rule_id, []).append(f)
    return out


def _scan(args):
    out = runner.invoke(app, args, color=False)
    assert out.exit_code == 0, out.output
    return out


# ─── 1. READ_ONLY: il gate tiene ferme le probe (nessuna richiesta PROBE) ────

def test_read_only_run_sends_no_probe_request(internet):
    vi, created = internet
    _scan(["scan", "--target", TARGET])
    sup_paths = [r.url.path for r in vi.supabase_requests()]
    assert not [p for p in sup_paths if p.startswith(_PROBE_PATHS_SUPA)], sup_paths
    assert not [p for p in vi.site_paths() if any(x in p for x in _PROBE_PATHS_SITE)]
    assert vi.foreign == []
    # A READ_ONLY i controlli READ_ONLY girano comunque (RLS via bundle, auth settings).
    rules = _rules(created[-1]._result.findings)
    assert "SUPABASE_SCHEMA_VIA_BUNDLE" in rules
    assert "AUTH_EXPECTATION_UNDECLARED" in rules
    assert "STORAGE_PUBLIC_LISTABLE" not in rules and "RPC_DATA_EXPOSED" not in rules


# ─── 2. PROBE sul sandbox debole: Bastione trova le debolezze volute ─────────

def test_probe_run_finds_planted_weaknesses_owned_only_and_p8(internet, tmp_path):
    vi, created = internet
    _scan(["scan", "--target", TARGET, "--max-intrusion", "probe"])
    orch = created[-1]
    result = orch._result
    rules = _rules(result.findings)

    # recon: chiave 2026 estratta INTERA (prima veniva troncata → tutto 401)
    assert orch._fp.anon_key == PUBLISHABLE
    assert orch._fp.supabase_key_kind == "publishable"
    assert "SUPABASE_LEGACY_KEYS_IN_USE" not in rules

    # le tre debolezze della spec §4.11
    assert [f.severity for f in rules["STORAGE_PUBLIC_LISTABLE"]] == [Severity.CRITICAL]
    assert [f.severity for f in rules["RPC_DATA_EXPOSED"]] == [Severity.CRITICAL]
    signup = [f for f in rules["AUTH_EXPECTATION_UNDECLARED"]
              if f.location.endpoint.endswith("#signup")]
    assert len(signup) == 1

    # posture: RLS protetta su ordini (200 []) e "protetto ma fragile" su fatture (42501)
    posture = {c.check_id: c for c in result.posture_checks}
    assert posture["POSTURE_RLS_ordini"].passed is True
    assert posture["POSTURE_RLS_fatture"].passed is True
    assert "fragile" in posture["POSTURE_RLS_fatture"].detail
    assert posture["POSTURE_STORAGE_PRIVATE_documenti"].passed is False
    assert posture["POSTURE_RPC_GATED_lista_clienti"].passed is False

    # nessuna falsa debolezza: niente RLS_DISABLED, niente segreti sulla chiave pubblica
    assert "RLS_DISABLED" not in rules
    assert not [r for r in rules if r.startswith("SECRET_")], sorted(rules)

    # owned-only: solo i due host dichiarati; mai scritture verso Supabase a PROBE
    assert vi.foreign == []
    for r in vi.supabase_requests():
        assert r.method in ("GET", "POST"), r
        if r.method == "POST":
            assert r.url.path.startswith(("/storage/v1/object/list/", "/graphql/v1")), r
        assert r.headers.get("apikey") == PUBLISHABLE
    rpc_calls = [r for r in vi.supabase_requests() if "/rpc/" in r.url.path]
    assert rpc_calls and all(r.method == "GET" for r in rpc_calls)   # D5: RPC solo in GET

    # P8: nessuna riga e nessun nome di oggetto negli artefatti della run
    for path in orch._run_dir.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert SENTINEL_EMAIL not in text, path
            assert SENTINEL_OBJECT not in text, path


# ─── 3. Ciclo completo: scan → fix → verify (il cuore di §4.11) ──────────────

def test_verify_closes_only_what_it_actually_rechecked(internet):
    vi, created = internet
    _scan(["scan", "--target", TARGET, "--max-intrusion", "probe", "--accept-baseline"])
    first = _rules(created[-1]._result.findings)
    assert {"STORAGE_PUBLIC_LISTABLE", "RPC_DATA_EXPOSED"} <= set(first)

    vi.fixed = True        # l'owner chiude bucket, RPC e signup

    # verify di default (READ_ONLY): le probe non partono → storage/RPC NON possono
    # risultare FIXED (prima di S16 risultavano FIXED senza alcun controllo).
    out = _scan(["verify", "--target", TARGET])
    res = created[-1]._result
    fixed_ids = {f.finding_id for f in res.fixed}
    nrv = _rules(res.not_reverified)
    assert {"STORAGE_PUBLIC_LISTABLE", "RPC_DATA_EXPOSED"} <= set(nrv)
    assert not fixed_ids & {f.finding_id for fs in nrv.values() for f in fs}
    assert all(f.status is Status.KNOWN for fs in nrv.values() for f in fs)
    assert "not_reverified" in out.output
    # il signup (controllo READ_ONLY) è stato ri-verificato davvero → FIXED
    signup_id = next(f.finding_id for f in first["AUTH_EXPECTATION_UNDECLARED"]
                     if f.location.endpoint.endswith("#signup"))
    assert signup_id in fixed_ids

    # verify al livello giusto (PROBE): ora storage e RPC sono ri-controllati → FIXED
    _scan(["verify", "--target", TARGET, "--max-intrusion", "probe"])
    res = created[-1]._result
    fixed_ids = {f.finding_id for f in res.fixed}
    for rule in ("STORAGE_PUBLIC_LISTABLE", "RPC_DATA_EXPOSED"):
        assert {f.finding_id for f in first[rule]} <= fixed_ids, rule
    assert res.not_reverified == []
    assert vi.foreign == []


def test_verify_without_fix_keeps_probe_findings_open(internet):
    # Controprova: nessuna correzione, verify READ_ONLY → niente FIXED inventati.
    vi, created = internet
    _scan(["scan", "--target", TARGET, "--max-intrusion", "probe", "--accept-baseline"])
    _scan(["verify", "--target", TARGET])
    res = created[-1]._result
    rules_fixed = {f.finding_id for f in res.fixed}
    nrv = _rules(res.not_reverified)
    assert {"STORAGE_PUBLIC_LISTABLE", "RPC_DATA_EXPOSED"} <= set(nrv)
    assert not rules_fixed
    _scan(["verify", "--target", TARGET, "--max-intrusion", "probe"])
    res = created[-1]._result
    still = _rules(res.findings)
    assert [f.status for f in still["STORAGE_PUBLIC_LISTABLE"]] == [Status.KNOWN]
    assert [f.status for f in still["RPC_DATA_EXPOSED"]] == [Status.KNOWN]
    assert res.fixed == [] and res.not_reverified == []


def test_ownership_token_missing_on_site_aborts_probe(internet, tmp_path):
    # Senza token pubblicato il gate aborta (exit 3): nessuna probe parte.
    vi, _created = internet
    toml = tmp_path / "targets" / f"{TARGET}.toml"
    toml.write_text(TARGET_TOML.replace(OWNERSHIP_TOKEN, "token-non-pubblicato"),
                    encoding="utf-8")
    out = runner.invoke(app, ["scan", "--target", TARGET, "--max-intrusion", "probe"])
    assert out.exit_code == 3, out.output
    assert not [r for r in vi.supabase_requests()]
    assert vi.site_paths() == ["/.well-known/bastione-ownership.txt"]
