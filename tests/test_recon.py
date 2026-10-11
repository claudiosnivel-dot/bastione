"""Test della fase RECON / fingerprint (§8) — read-only.

Due livelli, separati di proposito:

1. **Funzioni pure** (parsing `<script src>`, estrazione `supabase_url`/`anon_key`,
   rilevamento Cloudflare/WordPress): la *gemma* del recon. Testate con input reali
   sintetici, **senza mock** — è qui che vive la logica che deve essere corretta.
   In particolare l'anon key (JWT `role:anon`, pubblica per design) NON va mai
   confusa con la service_role key (fuga critica, §8/§10): c'è un test apposta.

2. **Orchestrazione** `fingerprint()`: cabla rete + tool esterni + funzioni pure e
   scrive `fingerprint.json`. Il confine di rete/subprocess (`_fetch`, `_run_whatweb`,
   `_run_katana`) è l'unica cosa monkeypatchata — come in `test_gate.py` — così i
   test girano **offline** e nessun host viene mai puntato. La scoperta dei bundle
   (e quindi l'anon key) NON deve dipendere da katana (vincolo M0, §8).
"""

import base64
import json
from types import SimpleNamespace

import pytest

from bastione.models import Fingerprint
from bastione.recon.fingerprint import (
    _parse_whatweb,
    detect_cloudflare,
    extract_anon_key,
    extract_script_srcs,
    extract_supabase_url,
    extract_table_names,
    fingerprint,
    is_wordpress,
)


# ─── helper: costruzione JWT sintetici (anon vs service_role) ────────────────

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(role: str, ref: str = "abcdefghijklmnopqrst") -> str:
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(json.dumps(
        {"iss": "supabase", "ref": ref, "role": role, "iat": 1, "exp": 2}).encode())
    return f"{header}.{payload}.{_b64url(b'signature')}"


def fake_resp(*, url: str, headers: dict | None = None, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(url=url, headers=headers or {}, text=text)


# ─── funzioni pure: <script src> (fallback obbligatorio senza katana, §8) ────

def test_extract_script_srcs_resolves_relative_and_absolute():
    html = (
        '<html><head>'
        '<script src="/assets/index-ab12cd.js"></script>'
        '<script src="https://cdn.example.com/vendor.js"></script>'
        '</head></html>'
    )
    srcs = extract_script_srcs(html, "https://app.example.com/")
    assert "https://app.example.com/assets/index-ab12cd.js" in srcs
    assert "https://cdn.example.com/vendor.js" in srcs


def test_extract_script_srcs_ignores_inline_scripts():
    html = '<script>var x = 1;</script><script src="app.js"></script>'
    srcs = extract_script_srcs(html, "https://app.example.com/")
    assert srcs == ["https://app.example.com/app.js"]


# ─── funzioni pure: estrazione Supabase (la gemma, §8) ──────────────────────

def test_extract_supabase_url_from_bundle():
    js = 'const u="https://abcdefghijklmnopqrst.supabase.co";const k="x";'
    assert extract_supabase_url(js) == "https://abcdefghijklmnopqrst.supabase.co"


def test_extract_supabase_url_absent_returns_none():
    assert extract_supabase_url("const x = 1; // niente supabase qui") is None


def test_extract_anon_key_returns_anon_jwt():
    anon = make_jwt("anon")
    js = f'createClient(url, "{anon}")'
    assert extract_anon_key(js) == anon


def test_extract_anon_key_ignores_service_role_jwt():
    # LOCKED (§8/§10): la service_role NON è una anon key. Confonderle qui
    # significherebbe trattare una fuga critica come chiave pubblica innocua.
    service = make_jwt("service_role")
    assert extract_anon_key(f'const SECRET = "{service}";') is None


def test_extract_anon_key_picks_anon_among_multiple_jwts():
    service, anon = make_jwt("service_role"), make_jwt("anon")
    assert extract_anon_key(f'{service} ... {anon}') == anon


def test_extract_anon_key_absent_returns_none():
    assert extract_anon_key("nessun jwt qui, solo testo") is None


# ─── funzioni pure: table discovery dal bundle (§8 / §11.1 fallback) ─────────
#
# Un attaccante che non può introspezionare l'OpenAPI (root REST 401) ricava i
# nomi tabella dai riferimenti del client Supabase nel bundle JS: `.from('clienti')`.
# `extract_table_names` replica esattamente questa enumerazione, in modo PURO
# (lavora solo su testo già in memoria, niente I/O, niente download nuovo).

def test_extract_table_names_single_apex():
    js = "supabase.from('clienti').select('*')"
    assert extract_table_names(js) == ["clienti"]


def test_extract_table_names_double_apex():
    js = 'supabase.from("ordini_2024").select("*")'
    assert extract_table_names(js) == ["ordini_2024"]


def test_extract_table_names_chained_select_minified():
    # frammento minificato realistico: catena .from('x').select(...)
    js = 'const r=await s.from("fatture").select("id,totale").eq("anno",2024);'
    assert extract_table_names(js) == ["fatture"]


def test_extract_table_names_with_schema_prefix():
    # identificatore con UN prefisso schema: public.fatture
    js = "s.from('public.fatture').select('*')"
    assert extract_table_names(js) == ["public.fatture"]


def test_extract_table_names_dedup_and_sorted_deterministic():
    js = (
        "a.from('ordini');b.from(\"clienti\");c.from('ordini');"
        "d.from('clienti').select('*')"
    )
    # dedup + ordinamento deterministico
    assert extract_table_names(js) == ["clienti", "ordini"]


def test_extract_table_names_ignores_array_from_builtin():
    # LOCKED: i builtin JS .from NON sono tabelle. Array.from('abc') non
    # deve produrre una "tabella" 'abc'.
    assert extract_table_names("const a = Array.from('abc');") == []


def test_extract_table_names_ignores_other_js_builtins():
    js = (
        "Array.from('a');String.from('b');Buffer.from('c');Object.from('d');"
        "Number.from('e');Promise.from('f');Date.from('g');Int8Array.from('h');"
        "Uint8Array.from('i');Float64Array.from('j');"
    )
    assert extract_table_names(js) == []


def test_extract_table_names_keeps_real_table_amid_builtins():
    # un .from builtin non deve oscurare una vera .from() su tabella vicina
    js = "Array.from('abc'); supabase.from('clienti').select('*')"
    assert extract_table_names(js) == ["clienti"]


def test_extract_table_names_ignores_builtin_with_space_before_from():
    # Regressione (blind-review #1): un builtin con spazio prima di `.from(`
    # (`Array .from('abc')`) NON è una tabella. Caso non realistico sui bundle
    # MINIFICATI (lo spazio è già rimosso), ma il filtro deve restare corretto:
    # `\s*` tollera lo spazio senza scambiare `MyArray` per `Array`.
    assert extract_table_names("const a = Array .from('abc');") == []
    assert extract_table_names("Uint8Array .from('x');") == []


def test_extract_table_names_keeps_userclass_from_with_space():
    # Controprova del fix #1: il confine di parola NON deve sopprimere una vera
    # `.from()` su una classe utente il cui nome FINISCE per un builtin
    # (`MyArray.from('clienti')` resta una tabella, anche con spazio).
    assert extract_table_names("MyArray.from('clienti');") == ["clienti"]
    assert extract_table_names("MyArray .from('clienti');") == ["clienti"]


def test_extract_table_names_rejects_non_identifiers():
    # spazi, url, espressioni: niente di tutto ciò è un identificatore PostgREST
    js = (
        "s.from('https://x.y/z');s.from('ha spazi');s.from(variabile);"
        "s.from('');s.from('1abc')"
    )
    assert extract_table_names(js) == []


def test_extract_table_names_empty_text():
    assert extract_table_names("") == []


# ─── funzioni pure: Cloudflare / WordPress ──────────────────────────────────

def test_detect_cloudflare_from_cf_ray_header():
    assert detect_cloudflare({"CF-RAY": "abc123-FRA", "server": "x"}) is True


def test_detect_cloudflare_from_server_header():
    assert detect_cloudflare({"Server": "cloudflare"}) is True


def test_detect_cloudflare_negative():
    assert detect_cloudflare({"server": "nginx"}) is False


def test_is_wordpress_from_technologies():
    assert is_wordpress([{"name": "WordPress", "version": "6.4"}]) is True
    assert is_wordpress([{"name": "nginx"}]) is False


# ─── orchestrazione fingerprint() — offline, confine monkeypatchato ─────────

def _patch_tools(monkeypatch, *, fetch, whatweb=None, katana=None):
    monkeypatch.setattr("bastione.recon.fingerprint._fetch", fetch)
    monkeypatch.setattr("bastione.recon.fingerprint._run_whatweb",
                        lambda target: whatweb or [])
    monkeypatch.setattr("bastione.recon.fingerprint._run_katana",
                        lambda target: katana or [])


def test_fingerprint_extracts_supabase_via_script_src_without_katana(monkeypatch):
    # katana assente (whatweb/katana → vuoto): la scoperta bundle deve comunque
    # funzionare via <script src>, altrimenti la DoD M0 (anon key) è irraggiungibile.
    anon = make_jwt("anon")
    base = "https://app.example.com/"
    bundle = "https://app.example.com/assets/index-ab12cd.js"
    pages = {
        base: fake_resp(url=base, headers={"server": "nginx"},
                        text='<script src="/assets/index-ab12cd.js"></script>'),
        bundle: fake_resp(url=bundle, text=(
            f'const u="https://abcdefghijklmnopqrst.supabase.co";'
            f'const k="{anon}";')),
    }
    _patch_tools(monkeypatch, fetch=lambda url: pages.get(url))

    fp = fingerprint(base)

    assert fp.resolved_urls == [base]
    assert fp.is_supabase is True
    assert fp.supabase_url == "https://abcdefghijklmnopqrst.supabase.co"
    assert fp.anon_key == anon
    assert fp.technologies == [] and fp.endpoints == []   # tool assenti, nessun crash


def test_fingerprint_uses_final_redirected_url_and_headers(monkeypatch):
    base = "http://app.example.com"
    final = "https://app.example.com/"
    pages = {base: fake_resp(url=final, headers={"CF-RAY": "z-FRA"}, text="<html></html>")}
    _patch_tools(monkeypatch, fetch=lambda url: pages.get(url))

    fp = fingerprint(base)

    assert fp.resolved_urls == [final]          # url finale dopo redirect, non l'input
    assert fp.cloudflare_fronted is True
    assert fp.response_headers.get("CF-RAY") == "z-FRA"


def test_fingerprint_degrades_when_base_fetch_fails(monkeypatch):
    # httpx assente o host irraggiungibile → _fetch None: nessun crash, campi vuoti.
    _patch_tools(monkeypatch, fetch=lambda url: None)

    fp = fingerprint("https://down.example.com")

    assert fp.resolved_urls == []
    assert fp.is_supabase is False
    assert fp.anon_key is None


def test_fingerprint_marks_wordpress_from_whatweb(monkeypatch):
    base = "https://blog.example.com/"
    _patch_tools(
        monkeypatch,
        fetch=lambda url: fake_resp(url=base, text="<html></html>"),
        whatweb=[{"name": "WordPress", "version": "6.4"}],
    )

    fp = fingerprint(base)

    assert fp.is_wordpress is True
    assert {"name": "WordPress", "version": "6.4"} in fp.technologies


def test_fingerprint_writes_valid_json_artifact(monkeypatch, tmp_path):
    base = "https://app.example.com/"
    _patch_tools(monkeypatch,
                 fetch=lambda url: fake_resp(url=base, text="<html></html>"))

    fp = fingerprint(base, run_dir=tmp_path)

    artifact = tmp_path / "fingerprint.json"
    assert artifact.exists()
    reloaded = Fingerprint.model_validate_json(artifact.read_text(encoding="utf-8"))
    assert reloaded == fp


# ─── hardening post-revisione adversariale ──────────────────────────────────

def test_fingerprint_anon_key_without_supabase_url_is_not_supabase(monkeypatch):
    # is_supabase è legato alla rilevazione dell'URL PostgREST (§8): una anon key
    # senza URL NON marca il target come Supabase, altrimenti il modulo supabase
    # partirebbe con supabase_url=None (§9 → §11.1).
    anon = make_jwt("anon")
    base = "https://app.example.com/"
    bundle = "https://app.example.com/x.js"
    pages = {
        base: fake_resp(url=base, text='<script src="/x.js"></script>'),
        bundle: fake_resp(url=bundle, text=f'const k="{anon}";'),  # niente .supabase.co
    }
    _patch_tools(monkeypatch, fetch=lambda url: pages.get(url))

    fp = fingerprint(base)

    assert fp.anon_key == anon
    assert fp.supabase_url is None
    assert fp.is_supabase is False


def test_fingerprint_ignores_off_host_bundle(monkeypatch):
    # Owned-only (§7/§4.2): un <script src> verso un host esterno NON dichiarato
    # non deve essere scaricato, anche se contenesse una chiave Supabase.
    anon = make_jwt("anon")
    base = "https://app.example.com/"
    off_host = "https://cdn.jsdelivr.net/app.js"
    pages = {
        base: fake_resp(url=base,
                        text='<script src="https://cdn.jsdelivr.net/app.js"></script>'),
        off_host: fake_resp(url=off_host, text=(
            f'const u="https://abcdefghijklmnopqrst.supabase.co";const k="{anon}";')),
    }
    fetched: list[str] = []

    def recording_fetch(url):
        fetched.append(url)
        return pages.get(url)

    _patch_tools(monkeypatch, fetch=recording_fetch)

    fp = fingerprint(base)

    assert off_host not in fetched          # host esterno mai contattato
    assert fp.is_supabase is False
    assert fp.anon_key is None


def test_fingerprint_skips_failed_bundle_and_finds_key_in_next(monkeypatch):
    # DoD M0: un bundle irraggiungibile (None) in mezzo non deve impedire di
    # trovare la chiave in un bundle successivo, né causare un crash.
    anon = make_jwt("anon")
    base = "https://app.example.com/"
    b1, b2 = "https://app.example.com/a.js", "https://app.example.com/b.js"
    pages = {
        base: fake_resp(url=base, text=(
            '<script src="/a.js"></script><script src="/b.js"></script>')),
        b1: None,
        b2: fake_resp(url=b2, text=(
            f'const u="https://abcdefghijklmnopqrst.supabase.co";const k="{anon}";')),
    }
    _patch_tools(monkeypatch, fetch=lambda url: pages.get(url))

    fp = fingerprint(base)

    assert fp.is_supabase is True
    assert fp.anon_key == anon


def test_fingerprint_populates_discovered_tables_from_bundles(monkeypatch):
    # discovered_tables = aggregazione di extract_table_names su TUTTI i bundle
    # same-host già scaricati (gli stessi da cui si estraggono url/anon key).
    anon = make_jwt("anon")
    base = "https://app.example.com/"
    b1 = "https://app.example.com/a.js"
    b2 = "https://app.example.com/b.js"
    pages = {
        base: fake_resp(url=base, text=(
            '<script src="/a.js"></script><script src="/b.js"></script>')),
        b1: fake_resp(url=b1, text=(
            f'const u="https://abcdefghijklmnopqrst.supabase.co";'
            f'const k="{anon}";s.from("clienti").select("*");')),
        b2: fake_resp(url=b2, text="x.from('ordini');Array.from('abc');"),
    }
    _patch_tools(monkeypatch, fetch=lambda url: pages.get(url))

    fp = fingerprint(base)

    # aggregato, dedup, ordinato; Array.from non inquina
    assert fp.discovered_tables == ["clienti", "ordini"]


def test_fingerprint_discovered_tables_default_empty(monkeypatch):
    # nessun .from() nei bundle → lista vuota (backward-compatible)
    base = "https://app.example.com/"
    _patch_tools(monkeypatch,
                 fetch=lambda url: fake_resp(url=base, text="<html></html>"))
    fp = fingerprint(base)
    assert fp.discovered_tables == []


def test_fingerprint_discovered_tables_ignores_off_host_bundle(monkeypatch):
    # owned-only: i bundle off-host non vengono scaricati → niente tabelle da lì.
    base = "https://app.example.com/"
    off_host = "https://cdn.jsdelivr.net/app.js"
    pages = {
        base: fake_resp(url=base,
                        text='<script src="https://cdn.jsdelivr.net/app.js"></script>'),
        off_host: fake_resp(url=off_host, text="x.from('segreta');"),
    }
    fetched: list[str] = []

    def recording_fetch(url):
        fetched.append(url)
        return pages.get(url)

    _patch_tools(monkeypatch, fetch=recording_fetch)

    fp = fingerprint(base)

    assert off_host not in fetched
    assert fp.discovered_tables == []


def test_parse_whatweb_skips_malformed_line_keeps_valid():
    # Resilienza (§4.7): una riga non-JSON non deve scartare le tecnologie valide.
    stdout = '{"plugins": {"WordPress": {"version": ["6.4"]}}}\nNON-JSON garbage\n'
    techs = _parse_whatweb(stdout)
    assert {"name": "WordPress", "version": "6.4", "confidence": "whatweb"} in techs


# ─── M5 (Task 3): chiavi pubbliche 2026 + scoperta bucket/rpc dal bundle ─────

from bastione.recon.fingerprint import (
    extract_public_key, extract_rpc_names, extract_bucket_names)


def test_extract_public_key_legacy_jwt():
    anon = make_jwt("anon")
    assert extract_public_key(f'createClient(u,"{anon}")') == (anon, "legacy_jwt")


def test_extract_public_key_publishable():
    assert extract_public_key('createClient(u,"sb_publishable_AbC123xyz")') == (
        "sb_publishable_AbC123xyz", "publishable")


def test_extract_public_key_prefers_legacy_when_both():
    anon = make_jwt("anon")
    assert extract_public_key(f'{anon} ... sb_publishable_AbC1')[1] == "legacy_jwt"


def test_extract_public_key_ignores_service_role():   # Review Focus #1
    svc = make_jwt("service_role")
    assert extract_public_key(f'const S="{svc}";') == (None, None)


def test_extract_rpc_and_bucket_names():
    js = "supabase.rpc('get_listino',{x:1}); supabase.storage.from('avatars').list()"
    assert extract_rpc_names(js) == ["get_listino"]
    assert extract_bucket_names(js) == ["avatars"]


def test_fingerprint_publishable_and_discovery(monkeypatch, tmp_path):
    import bastione.recon.fingerprint as fp_mod
    page = "https://app.example/"
    html = '<script src="/assets/app.js"></script>'
    js = ('const u="https://abcdefghijklmnopqrst.supabase.co";'
          'const k="sb_publishable_AbC123";'
          "supabase.rpc('get_listino');supabase.storage.from('avatars').list();")
    def fake_fetch(url):
        if url.rstrip("/") == page.rstrip("/"):
            return fake_resp(url=page, headers={}, text=html)
        if url == "https://app.example/assets/app.js":
            return fake_resp(url="https://app.example/assets/app.js", headers={}, text=js)
        return None
    monkeypatch.setattr(fp_mod, "_fetch", fake_fetch)
    monkeypatch.setattr(fp_mod, "_run_whatweb", lambda t: [])
    monkeypatch.setattr(fp_mod, "_run_katana", lambda t: [])
    fp = fp_mod.fingerprint(page, tmp_path)
    assert fp.supabase_key_kind == "publishable"
    assert fp.anon_key == "sb_publishable_AbC123"
    assert fp.discovered_rpcs == ["get_listino"]
    assert fp.discovered_buckets == ["avatars"]
    # un bucket non è una tabella: niente RLS test su /rest/v1/avatars
    assert fp.discovered_tables == []


def test_storage_from_is_not_a_table():
    """`.storage.from('x')` è un bucket: resta fuori da discovered_tables, mentre un
    `.from('x')` vero accanto resta una tabella (nessun falso negativo)."""
    from bastione.recon.fingerprint import extract_bucket_names, extract_table_names
    text = "s.storage.from('avatars').list();s.storage .from(\"docs\");s.from('clienti')"
    assert extract_table_names(text) == ["clienti"]
    assert extract_bucket_names(text) == ["avatars", "docs"]
    # stesso nome usato sia come bucket sia come tabella → resta tabella
    both = "s.storage.from('avatars');s.from('avatars').select()"
    assert extract_table_names(both) == ["avatars"]
