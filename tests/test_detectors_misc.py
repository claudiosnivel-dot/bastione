"""Test dei detector misc (M5 Task 11, §4.4): Telegram bot, chiave privata,
alta entropia. Tutto OFFLINE: il confine I/O `_identity_get` è monkeypatchato
(nessuna richiesta di rete, nessun target live, §4.10).

Prima parte: i test del piano (GATE del task). Seconda parte: copertura aggiunta
dal builder (P8 con valori sentinella, resilienza del confine I/O, forme reali
dei token/header, filtri dell'alta entropia). Terza parte: SecretsModule
end-to-end (gate a richieste-zero, liveness solo per Telegram, P8 sui Finding).
"""
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastione.models import (
    Fingerprint,
    Location,
    RawSecret,
    RunContext,
    TargetConfig,
    TextAsset,
)
from bastione.enums import Severity, Confidence, IntrusionLevel
import bastione.modules.secrets.detectors.misc as mc


# ─── GATE del piano ─────────────────────────────────────────────────────────

def test_telegram_bot_token_high():
    d = mc.TelegramBotDetector()
    s = d.scan(TextAsset(source="x", content="123456789:AAE" + "a"*33))
    assert s and d.severity == Severity.HIGH

def test_telegram_liveness(monkeypatch):
    d = mc.TelegramBotDetector()
    raw = RawSecret(detector_id="SECRET_TELEGRAM_BOT", value="123:" + "a"*33, location=Location(file="x"))
    monkeypatch.setattr(mc, "_identity_get", lambda url: SimpleNamespace(status_code=200, json=lambda: {"ok": True}))
    assert d.validate_liveness(raw).alive is True

def test_private_key_block_critical():
    d = mc.PrivateKeyDetector()
    s = d.scan(TextAsset(source="x", content="-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END..."))
    assert s and d.severity == Severity.CRITICAL

def test_high_entropy_low_tentative():
    d = mc.HighEntropyDetector()
    # stringa ad alta entropia, non hex-hash, non in altre regex
    s = d.scan(TextAsset(source="x", content='token="aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0hJ"'))
    assert s and d.severity == Severity.LOW
    # i finding high-entropy sono SEMPRE tentative (il modulo usa confidence FIRM; qui
    # marchiamo l'incertezza nel RawSecret.entropy e nel titolo — vedi impl)
    assert s[0].entropy is not None

def test_high_entropy_skips_low_entropy_and_hex_hashes():
    d = mc.HighEntropyDetector()
    assert d.scan(TextAsset(source="x", content="aaaaaaaaaaaaaaaaaaaaaaaaaaaa")) == []
    assert d.scan(TextAsset(source="x", content="d41d8cd98f00b204e9800998ecf8427e")) == []  # md5-like


# ─── estensioni del builder ─────────────────────────────────────────────────

_TOKEN = "123456789:AAE" + "a" * 33                                   # forma <id>:<segreto>
_SENTINEL_TOKEN = "987654321:SENTINELtokenVALUE_0123456789abcdef"      # P8: non deve mai trapelare
_SENTINEL_SECRET = _SENTINEL_TOKEN.split(":", 1)[1]


def _raw_telegram(value: str = _TOKEN) -> RawSecret:
    return RawSecret(detector_id="SECRET_TELEGRAM_BOT", value=value, location=Location(file="x"))


# --- Telegram: scan --------------------------------------------------------

def test_telegram_scan_reports_location_and_detector_id():
    s = mc.TelegramBotDetector().scan(TextAsset(source="assets/app.js", content=f'const t="{_TOKEN}";'))
    assert [r.value for r in s] == [_TOKEN]
    assert s[0].detector_id == "SECRET_TELEGRAM_BOT"
    assert s[0].location.file == "assets/app.js"


def test_telegram_scan_finds_token_inside_bot_api_url():
    # Forma canonica della fuga: il token incollato a "bot" nell'URL dell'API Bot.
    # Il match è il solo token, senza il prefisso "bot" e senza il path che segue.
    d = mc.TelegramBotDetector()
    url = f"https://api.telegram.org/bot{_TOKEN}/sendMessage"
    s = d.scan(TextAsset(source="app.js", content=f'fetch("{url}")'))
    assert [r.value for r in s] == [_TOKEN]


@pytest.mark.parametrize("content", [
    "12345:" + "a" * 33,               # id troppo corto
    "123456789:" + "a" * 10,           # segreto troppo corto
    "1234567890123:" + "a" * 33,       # id troppo lungo
    "x123456789:" + "a" * 33,          # id incollato a un identificatore qualunque
    "",                                # contenuto vuoto
], ids=["id-too-short", "secret-too-short", "id-too-long", "glued-to-identifier", "empty"])
def test_telegram_scan_ignores_non_tokens(content):
    assert mc.TelegramBotDetector().scan(TextAsset(source="x", content=content)) == []


# --- Telegram: liveness ----------------------------------------------------

@pytest.mark.parametrize("status, alive, mode", [
    (200, True, "live"),
    (401, False, "revoked"),
    (404, False, "revoked"),
])
def test_telegram_liveness_maps_status(monkeypatch, status, alive, mode):
    monkeypatch.setattr(mc, "_identity_get", lambda url: SimpleNamespace(status_code=status))
    res = mc.TelegramBotDetector().validate_liveness(_raw_telegram())
    assert res is not None
    assert res.alive is alive
    assert res.mode == mode


@pytest.mark.parametrize("resp", [
    None,                                  # confine I/O fallito / httpx assente
    SimpleNamespace(status_code=429),      # rate limit: non interpretabile
    SimpleNamespace(status_code=500),
    SimpleNamespace(status_code=302),
    SimpleNamespace(),                     # response senza status_code
])
def test_telegram_liveness_unknown_outcome_is_none(monkeypatch, resp):
    monkeypatch.setattr(mc, "_identity_get", lambda url: resp)
    assert mc.TelegramBotDetector().validate_liveness(_raw_telegram()) is None


def test_telegram_liveness_requests_only_getme_on_fixed_host(monkeypatch):
    calls = []

    def fake(url):
        calls.append(url)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(mc, "_identity_get", fake)
    mc.TelegramBotDetector().validate_liveness(_raw_telegram())
    # una sola richiesta, host fisso, solo identità: mai sendMessage & co.
    assert calls == [f"https://api.telegram.org/bot{_TOKEN}/getMe"]


def test_telegram_liveness_p8_token_never_in_result(monkeypatch):
    for status in (200, 401, 404):
        monkeypatch.setattr(mc, "_identity_get", lambda url, s=status: SimpleNamespace(status_code=s))
        res = mc.TelegramBotDetector().validate_liveness(_raw_telegram(_SENTINEL_TOKEN))
        assert res is not None
        for blob in (res.detail, repr(res), str(res.model_dump())):
            assert _SENTINEL_TOKEN not in blob
            assert _SENTINEL_SECRET not in blob


# --- Telegram: confine I/O reale (httpx monkeypatchato) --------------------

def test_identity_get_failure_degrades_and_never_logs_token(monkeypatch, caplog):
    httpx = pytest.importorskip("httpx")

    def boom(url, **kwargs):
        # eccezione "ostile": il messaggio riflette l'URL, quindi il token (P8).
        raise httpx.ConnectError(f"connection failed for {url}")

    monkeypatch.setattr(httpx, "get", boom)
    url = f"https://api.telegram.org/bot{_SENTINEL_TOKEN}/getMe"
    with caplog.at_level(logging.DEBUG):
        assert mc._identity_get(url) is None
    assert caplog.records, "il fallimento va loggato (onestà, R6), ma senza il token"
    assert _SENTINEL_TOKEN not in caplog.text
    assert _SENTINEL_SECRET not in caplog.text


def test_identity_get_does_not_follow_redirects_and_sets_timeout(monkeypatch):
    httpx = pytest.importorskip("httpx")
    seen = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(httpx, "get", fake_get)
    assert mc._identity_get("https://api.telegram.org/botX/getMe").status_code == 200
    # un redirect cross-host inoltrerebbe il token (nel path) a un terzo
    assert seen["follow_redirects"] is False
    assert seen["timeout"] == mc._TIMEOUT


def test_identity_get_without_httpx_returns_none(monkeypatch):
    monkeypatch.setitem(sys.modules, "httpx", None)   # `import httpx` solleva ImportError
    assert mc._identity_get("https://api.telegram.org/botX/getMe") is None


# --- Chiave privata --------------------------------------------------------

@pytest.mark.parametrize("header", [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
])
def test_private_key_headers_detected(header):
    d = mc.PrivateKeyDetector()
    s = d.scan(TextAsset(source="k.js", content=f'const k = "{header}\\nMIIEvQIBADANBg...";'))
    assert [r.value for r in s] == [header]
    assert s[0].detector_id == "SECRET_PRIVATE_KEY"
    assert s[0].location.file == "k.js"


@pytest.mark.parametrize("header", [
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----",
    "BEGIN PRIVATE KEY",               # senza i trattini non è un header PEM
])
def test_private_key_ignores_public_material(header):
    assert mc.PrivateKeyDetector().scan(TextAsset(source="x", content=header)) == []


def test_private_key_p8_value_is_header_only_never_the_body():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7SENTINELBODY"
    content = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    s = mc.PrivateKeyDetector().scan(TextAsset(source="x", content=content))
    assert len(s) == 1
    assert s[0].value == "-----BEGIN PRIVATE KEY-----"
    assert "SENTINELBODY" not in repr(s[0])


# --- Alta entropia ---------------------------------------------------------

def test_high_entropy_reports_value_entropy_and_marks_uncertainty():
    d = mc.HighEntropyDetector()
    value = "aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0hJ"                 # 32 simboli distinti
    s = d.scan(TextAsset(source="b.js", content=f'token="{value}"'))
    assert [r.value for r in s] == [value]
    assert s[0].entropy == 5.0                                  # log2(32)
    assert s[0].detector_id == "SECRET_HIGH_ENTROPY"
    assert s[0].location.file == "b.js"
    # sempre tentativa: il modulo emette FIRM, l'incertezza sta nel titolo e in entropy
    assert "possibile" in d.title.lower()


@pytest.mark.parametrize("content", [
    # NON esadecimali di proposito: una stringa solo [0-9a-f] di lunghezza 64 verrebbe
    # scartata dalla regola "probabile hash" e il test non proverebbe la soglia.
    "z" * 64,                  # entropia 0
    "zy" * 32,                 # entropia 1
    "hello_world_" * 6,        # testo ripetuto: entropia ~2.9, sotto soglia
    "1234567890" * 4,          # solo cifre
    "",                        # vuoto
], ids=["entropy-0", "entropy-1", "repeated-text", "digits-only", "empty"])
def test_high_entropy_skips_long_low_entropy_and_digit_only(content):
    assert mc.HighEntropyDetector().scan(TextAsset(source="x", content=content)) == []


def test_high_entropy_threshold_is_inclusive_at_4_bits():
    d = mc.HighEntropyDetector()
    at = "ghijklmnopqrstuv" * 2        # 16 simboli uniformi: entropia == 4.0 esatta, non esadecimale
    below = "ghijklmnopqrstu" * 3      # 15 simboli uniformi: entropia ~3.91
    assert mc._shannon(at) == mc._ENTROPY_MIN == 4.0
    assert mc._shannon(below) < mc._ENTROPY_MIN
    assert [r.value for r in d.scan(TextAsset(source="x", content=at))] == [at]
    assert d.scan(TextAsset(source="x", content=below)) == []


def test_high_entropy_skips_hash_length_hex_even_above_threshold():
    uniform_hex = "0123456789abcdef" * 2                        # 32 hex, entropia == 4.0 (== soglia)
    assert mc._shannon(uniform_hex) >= mc._ENTROPY_MIN           # senza la regola hash verrebbe segnalata
    assert mc.HighEntropyDetector().scan(TextAsset(source="x", content=uniform_hex)) == []


def test_high_entropy_ignores_strings_below_candidate_length():
    # 31 simboli distinti: alta entropia ma sotto i 32 caratteri → nessun candidato
    short = "aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0h"
    assert len(short) == 31
    assert mc.HighEntropyDetector().scan(TextAsset(source="x", content=short)) == []


def test_shannon_basics():
    assert mc._shannon("") == 0.0
    assert mc._shannon("aaaa") == 0.0
    assert mc._shannon("abcd") == pytest.approx(2.0)


# --- contratto comune ------------------------------------------------------

def test_misc_detectors_registered_with_expected_contract():
    from bastione.modules.secrets.detectors.base import DETECTORS

    expected = {
        mc.TelegramBotDetector: ("SECRET_TELEGRAM_BOT", Severity.HIGH),
        mc.PrivateKeyDetector: ("SECRET_PRIVATE_KEY", Severity.CRITICAL),
        mc.HighEntropyDetector: ("SECRET_HIGH_ENTROPY", Severity.LOW),
    }
    for cls, (detector_id, severity) in expected.items():
        assert any(isinstance(d, cls) for d in DETECTORS), f"{cls.__name__} non registrato"
        assert cls.detector_id == detector_id
        assert cls.severity == severity
        assert cls.gdpr_relevant is False


def test_scan_is_pure_and_never_touches_the_network_boundary(monkeypatch):
    def boom(url):
        raise AssertionError("scan() non deve toccare la rete")

    monkeypatch.setattr(mc, "_identity_get", boom)
    content = f"{_TOKEN} -----BEGIN PRIVATE KEY----- aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0hJ"
    for d in (mc.TelegramBotDetector(), mc.PrivateKeyDetector(), mc.HighEntropyDetector()):
        assert d.scan(TextAsset(source="x", content=content))   # trovano qualcosa, senza rete


@pytest.mark.parametrize(
    "content",
    ["", "\x00\x01\x02" * 50, "é" * 100, "\n" * 100],
    ids=["empty", "control-chars", "non-ascii", "newlines"],
)
def test_scan_resilient_to_empty_or_odd_content(content):
    asset = TextAsset(source="x", content=content)
    for d in (mc.TelegramBotDetector(), mc.PrivateKeyDetector(), mc.HighEntropyDetector()):
        assert d.scan(asset) == []


# ─── SecretsModule end-to-end: gate a richieste-zero + P8 (§4.10) ───────────
#
# Il self-gate (`max_intrusion >= PROBE` AND `ownership_verified`) e il backstop
# `authorize(PROBE, ctx)` vivono in `SecretsModule._run_liveness`: il detector non
# riceve un ctx. Qui si prova che, attraversando il modulo reale, la liveness
# Telegram NON parte senza gate (richieste zero), parte una sola volta (`getMe`,
# host fisso) con gate aperto, e che nessun valore sentinella trapela in un Finding
# (json + repr) né nei log.

_BASE = "https://staging.example.com/"
_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
_PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7SENTINELBODY"
_HE_VALUE = "aZ3kP9qR7mW2xV5nB8tY4uC6eD1fG0hJ"
_GETME_URL = f"https://api.telegram.org/bot{_SENTINEL_TOKEN}/getMe"
_MODULE_RULES = {"SECRET_TELEGRAM_BOT", "SECRET_PRIVATE_KEY", "SECRET_HIGH_ENTROPY"}
# Mai in chiaro in un campo del Finding / repr / log: l'evidence è redatta (primi 6 +
# ultimi 4 caratteri), quindi nessuna di queste stringhe INTERE può comparire.
_P8_SENTINELS = (_SENTINEL_TOKEN, _SENTINEL_SECRET, _PEM_BODY, _HE_VALUE)


@pytest.fixture
def only_misc_detectors():
    """Riduce DETECTORS ai soli detector misc, così i test non dipendono dagli altri
    detector M5 registrati nello stesso processo (e ripristina a fine test)."""
    import bastione.modules.secrets.detectors.base as base_mod

    original = list(base_mod.DETECTORS)
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend(
        [mc.TelegramBotDetector(), mc.PrivateKeyDetector(), mc.HighEntropyDetector()]
    )
    yield
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend(original)


def _run_module(monkeypatch, *, max_intrusion: IntrusionLevel, ownership_verified: bool):
    import bastione.modules.secrets.module as mod_module
    from bastione.modules.secrets.module import SecretsModule

    content = (
        f'const u="https://api.telegram.org/bot{_SENTINEL_TOKEN}/sendMessage",'
        f'k="{_PEM_HEADER}\\n{_PEM_BODY}",t="{_HE_VALUE}";'
    )
    pages = {_BASE: SimpleNamespace(url=_BASE, text=content)}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    cfg = TargetConfig(
        name="test-target", base_url="https://staging.example.com",
        environment="staging", ownership="owned", ownership_token="tok-123",
    )
    ctx = RunContext(
        target_cfg=cfg,
        fingerprint=Fingerprint(target=cfg.name, resolved_urls=[_BASE]),
        max_intrusion=max_intrusion,
        run_dir=Path("."),
        ownership_verified=ownership_verified,
    )
    return SecretsModule().run(ctx)


def _assert_p8(result, caplog) -> None:
    """P8: nessun valore sentinella in un campo del Finding (json + repr) né nei log."""
    for f in result.findings:
        dumped = f.model_dump_json() + repr(f)
        for sentinel in _P8_SENTINELS:
            assert sentinel not in dumped
    for sentinel in _P8_SENTINELS:
        assert sentinel not in caplog.text


def test_module_read_only_detects_all_with_zero_liveness_requests(
        monkeypatch, caplog, only_misc_detectors):
    caplog.set_level(logging.DEBUG)
    calls: list = []
    monkeypatch.setattr(
        mc, "_identity_get", lambda url: calls.append(url) or SimpleNamespace(status_code=200))
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=True)

    by_rule = {f.rule_id: f for f in result.findings}
    assert set(by_rule) == _MODULE_RULES
    assert by_rule["SECRET_TELEGRAM_BOT"].severity == Severity.HIGH
    assert by_rule["SECRET_PRIVATE_KEY"].severity == Severity.CRITICAL
    assert by_rule["SECRET_HIGH_ENTROPY"].severity == Severity.LOW
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)
    assert calls == []                                  # gate: richieste zero
    _assert_p8(result, caplog)


def test_module_probe_without_ownership_makes_zero_liveness_requests(
        monkeypatch, caplog, only_misc_detectors):
    caplog.set_level(logging.DEBUG)
    calls: list = []
    monkeypatch.setattr(
        mc, "_identity_get", lambda url: calls.append(url) or SimpleNamespace(status_code=200))
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)

    assert {f.rule_id for f in result.findings} == _MODULE_RULES
    assert calls == []                                  # ownership non verificata: richieste zero
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)
    _assert_p8(result, caplog)


def test_module_probe_with_ownership_runs_getme_once_and_only_for_telegram(
        monkeypatch, caplog, only_misc_detectors):
    caplog.set_level(logging.DEBUG)
    calls: list = []

    def fake(url):
        calls.append(url)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(mc, "_identity_get", fake)
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)

    # Una sola richiesta, host fisso, solo identità; niente per chiave privata / entropia.
    assert calls == [_GETME_URL]
    assert {f.rule_id for f in result.findings} == _MODULE_RULES
    for f in result.findings:
        if f.rule_id == "SECRET_TELEGRAM_BOT":
            assert f.intrusion_used == IntrusionLevel.PROBE
            assert f.confidence == Confidence.FIRM
            assert "VIVO" in f.description.upper()
        else:
            assert f.intrusion_used == IntrusionLevel.READ_ONLY
    _assert_p8(result, caplog)


def test_module_probe_revoked_token_is_reported_without_leaking_it(
        monkeypatch, caplog, only_misc_detectors):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(mc, "_identity_get", lambda url: SimpleNamespace(status_code=401))
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)

    telegram = [f for f in result.findings if f.rule_id == "SECRET_TELEGRAM_BOT"]
    assert len(telegram) == 1
    assert telegram[0].intrusion_used == IntrusionLevel.PROBE
    assert "REVOC" in telegram[0].description.upper()
    _assert_p8(result, caplog)


def test_module_liveness_io_failure_does_not_crash_or_enrich(
        monkeypatch, caplog, only_misc_detectors):
    """Resilienza (§4.7): confine I/O che fallisce (None) o che esplode -> la detection resta."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(mc, "_identity_get", lambda url: None)
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    assert {f.rule_id for f in result.findings} == _MODULE_RULES
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)

    def boom(url):
        raise RuntimeError("probe esploso")

    monkeypatch.setattr(mc, "_identity_get", boom)
    result = _run_module(
        monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    assert {f.rule_id for f in result.findings} == _MODULE_RULES
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)
    _assert_p8(result, caplog)


# Composta a runtime: nel sorgente non c'è mai una stringa con la forma di una
# chiave segreta Supabase (la push protection di GitHub la bloccherebbe).
_SB_SECRET_CLI = "sb_" + "secret_" + "N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"


def test_high_entropy_skips_supabase_2026_keys():
    # S16: la publishable è pubblica per design (come la anon legacy) e la secret ha
    # il suo detector CRITICAL dedicato: l'alta entropia non deve ri-segnalarle.
    # Valori = default PUBBLICI dello stack locale della Supabase CLI.
    from bastione.models import TextAsset
    from bastione.modules.secrets.detectors.misc import HighEntropyDetector
    content = ('const k="sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH";'
               f'const s="{_SB_SECRET_CLI}";')
    assert HighEntropyDetector().scan(TextAsset(source="a.js", content=content)) == []


def test_high_entropy_skips_supabase_keys_glued_to_names_and_urls():
    # Blind-review S16: in `.env` esposti (`KEY=valore`) e negli URL (`?apikey=`) il
    # candidato include ciò che precede la chiave e il solo `startswith` non bastava.
    from bastione.models import TextAsset
    from bastione.modules.secrets.detectors.misc import HighEntropyDetector
    content = ("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH\n"
               f"SUPABASE_SECRET_KEY={_SB_SECRET_CLI}\n"
               "wss://x.supabase.co/realtime/v1/websocket?apikey="
               "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH&vsn=1.0.0\n")
    assert HighEntropyDetector().scan(TextAsset(source=".env", content=content)) == []
