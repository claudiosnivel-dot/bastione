"""Test dei detector cloud/repo (M5 Task 9, §4.4): AWS AKIA/ASIA, GitHub, npm, Upstash.

Tre livelli, tutti OFFLINE (nessuna rete reale: il confine I/O `_identity_get` e
`httpx.get` sono monkeypatchati):

1. **Detection** (`scan`, READ_ONLY): formato dei token, falsi negativi/positivi.
2. **Liveness di identità** (`validate_liveness`, PROBE): solo GitHub e npm; AWS è
   flag-only (§10.2), Upstash è rimandata (serve la coppia URL+token, R6).
3. **SecretsModule end-to-end**: gate a richieste-zero (READ_ONLY o ownership non
   verificata -> nessun probe) e P8 con valori sentinella (il valore in chiaro non
   compare mai in un campo del Finding).
"""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastione.enums import IntrusionLevel, Severity
from bastione.models import (
    Fingerprint,
    Location,
    RawSecret,
    RunContext,
    TargetConfig,
    TextAsset,
)
import bastione.modules.secrets.detectors.cloud_repo as cr


# ─── Test del piano (Task 9, Step 1) ────────────────────────────────────────

def test_aws_akia_high_no_liveness():
    d = cr.AwsAkiaDetector()
    s = d.scan(TextAsset(source="x", content="AKIAIOSFODNN7EXAMPLE"))
    assert s and d.severity == Severity.HIGH
    assert d.validate_liveness(s[0]) is None            # flag only

def test_github_classic_and_pat():
    d = cr.GithubTokenDetector()
    assert d.scan(TextAsset(source="x", content="ghp_" + "a"*36))
    assert d.scan(TextAsset(source="x", content="github_pat_" + "A"*22 + "_" + "b"*40))

def test_github_liveness(monkeypatch):
    d = cr.GithubTokenDetector()
    raw = RawSecret(detector_id="SECRET_GITHUB", value="ghp_"+"a"*36, location=Location(file="x"))
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert d.validate_liveness(raw).alive is True
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    assert d.validate_liveness(raw).alive is False

def test_npm_and_upstash():
    assert cr.NpmTokenDetector().scan(TextAsset(source="x", content="npm_" + "a"*36))
    up = cr.UpstashDetector().scan(TextAsset(source="x", content='url:"https://eu1-cool-cat.upstash.io"'))
    assert up and cr.UpstashDetector().severity == Severity.HIGH


# ─── Valori sentinella (P8) e helper ────────────────────────────────────────

_AWS = "AKIA" + "Q7W8E9R2T3Y4U5I6"                 # AKIA + 16
_GH = "ghp_" + "Sentinel0" * 4                      # ghp_ + 36
_NPM = "npm_" + "Sentinel1" * 4                     # npm_ + 36
_UPSTASH = "https://sentinel-eu1.upstash.io"
_SENTINELS = (_AWS, _GH, _NPM, _UPSTASH)

_GITHUB_USER_URL = "https://api.github.com/user"
_NPM_WHOAMI_URL = "https://registry.npmjs.org/-/whoami"


def _raw(detector_id: str, value: str) -> RawSecret:
    return RawSecret(detector_id=detector_id, value=value, location=Location(file="x"))


def _asset(content: str, source: str = "x") -> TextAsset:
    return TextAsset(source=source, content=content)


# ─── (1) Contratto e registrazione ──────────────────────────────────────────

@pytest.mark.parametrize("cls, detector_id", [
    (cr.AwsAkiaDetector, "SECRET_AWS_AKIA"),
    (cr.GithubTokenDetector, "SECRET_GITHUB"),
    (cr.NpmTokenDetector, "SECRET_NPM"),
    (cr.UpstashDetector, "SECRET_UPSTASH"),
])
def test_detector_contract_and_registration(cls, detector_id):
    """Ogni detector: id/severità del catalogo §4.4 (HIGH), non GDPR, registrato."""
    from bastione.modules.secrets.detectors.base import DETECTORS, Detector

    d = cls()
    assert isinstance(d, Detector)
    assert d.detector_id == detector_id
    assert d.severity == Severity.HIGH
    assert d.gdpr_relevant is False
    assert d.title
    assert detector_id in [x.detector_id for x in DETECTORS]


# ─── (2) Detection: formato dei token ───────────────────────────────────────

def test_scan_returns_rawsecret_with_value_detector_id_and_location():
    out = cr.AwsAkiaDetector().scan(_asset(f'const k="{_AWS}";', source="https://t.example/app.js"))
    assert [s.value for s in out] == [_AWS]
    assert out[0].detector_id == "SECRET_AWS_AKIA"
    assert out[0].location.file == "https://t.example/app.js"


def test_aws_finds_permanent_and_temporary_keys():
    """AKIA (permanenti) e ASIA (temporanee STS), ogni occorrenza distinta."""
    asia = "ASIA" + "Q7W8E9R2T3Y4U5I6"
    out = cr.AwsAkiaDetector().scan(_asset(f"{_AWS} / {asia}"))
    assert [s.value for s in out] == [_AWS, asia]


@pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"])
def test_github_all_classic_token_kinds(prefix):
    token = prefix + "a" * 36
    out = cr.GithubTokenDetector().scan(_asset(f'"{token}"'))
    assert [s.value for s in out] == [token]


def test_github_fine_grained_pat_captured_whole():
    token = "github_pat_" + "11ABCDEFG0" + "x" * 12 + "_" + "y" * 59
    out = cr.GithubTokenDetector().scan(_asset(f'"{token}"'))
    assert [s.value for s in out] == [token]


def test_npm_and_upstash_values():
    npm = cr.NpmTokenDetector().scan(_asset(f"//registry:_authToken={_NPM}"))
    assert [s.value for s in npm] == [_NPM]
    up = cr.UpstashDetector().scan(_asset(f'url:"{_UPSTASH}"'))
    assert [s.value for s in up] == [_UPSTASH]


@pytest.mark.parametrize("detector, content", [
    (cr.AwsAkiaDetector(), "AKIA" + "A" * 15),                  # troppo corta
    (cr.AwsAkiaDetector(), "akia" + "a" * 16),                  # minuscolo
    (cr.AwsAkiaDetector(), "AKIB" + "A" * 16),                  # prefisso sconosciuto
    (cr.GithubTokenDetector(), "ghp_" + "a" * 35),              # troppo corto
    (cr.GithubTokenDetector(), "ghx_" + "a" * 36),              # tipo sconosciuto
    (cr.GithubTokenDetector(), "github_pat_" + "A" * 21),       # fine-grained troppo corto
    (cr.NpmTokenDetector(), "npm_" + "a" * 35),                 # troppo corto
    (cr.NpmTokenDetector(), "npm_" + "-" * 36),                 # alfabeto errato
    (cr.UpstashDetector(), "https://upstash.io"),               # nessun sottodominio
    (cr.UpstashDetector(), "https://eu1-cool-cat.example.com"), # non *.upstash.io
    (cr.UpstashDetector(), "https://eu1-x.upstash.io.evil.com"), # upstash.io solo come etichetta
    (cr.AwsAkiaDetector(), ""),
    (cr.GithubTokenDetector(), ""),
    (cr.NpmTokenDetector(), ""),
    (cr.UpstashDetector(), ""),
])
def test_scan_no_match(detector, content):
    assert detector.scan(_asset(content)) == []


# ─── (3) Liveness di identità: GitHub e npm (PROBE) ─────────────────────────

def test_github_liveness_request_shape_and_p8(monkeypatch):
    """Host fisso (mai derivato dal contenuto scansionato) + token solo nell'header;
    il `detail` del risultato non contiene mai il token (P8)."""
    captured: dict = {}

    def fake(url, headers):
        captured["url"] = url
        captured["headers"] = headers
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(cr, "_identity_get", fake)
    res = cr.GithubTokenDetector().validate_liveness(_raw("SECRET_GITHUB", _GH))
    assert res is not None and res.alive is True and res.mode == "live"
    assert captured["url"] == _GITHUB_USER_URL
    assert captured["headers"]["Authorization"] == f"Bearer {_GH}"
    assert _GH not in res.detail


def test_github_liveness_revoked_mode(monkeypatch):
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    res = cr.GithubTokenDetector().validate_liveness(_raw("SECRET_GITHUB", _GH))
    assert res is not None and res.alive is False and res.mode == "revoked"
    assert _GH not in res.detail


def test_npm_liveness_alive_revoked_and_request_shape(monkeypatch):
    captured: dict = {}

    def fake(status):
        def _get(url, headers):
            captured["url"] = url
            captured["headers"] = headers
            return SimpleNamespace(status_code=status)
        return _get

    d = cr.NpmTokenDetector()
    monkeypatch.setattr(cr, "_identity_get", fake(200))
    alive = d.validate_liveness(_raw("SECRET_NPM", _NPM))
    assert alive is not None and alive.alive is True and alive.mode == "live"
    assert captured["url"] == _NPM_WHOAMI_URL
    assert captured["headers"]["Authorization"] == f"Bearer {_NPM}"
    assert _NPM not in alive.detail

    monkeypatch.setattr(cr, "_identity_get", fake(401))
    revoked = d.validate_liveness(_raw("SECRET_NPM", _NPM))
    assert revoked is not None and revoked.alive is False and revoked.mode == "revoked"
    assert _NPM not in revoked.detail


@pytest.mark.parametrize("status", [301, 302, 403, 404, 429, 500, 503])
@pytest.mark.parametrize("detector, detector_id, value", [
    (cr.GithubTokenDetector(), "SECRET_GITHUB", _GH),
    (cr.NpmTokenDetector(), "SECRET_NPM", _NPM),
])
def test_liveness_unknown_for_uninterpretable_status(monkeypatch, detector, detector_id, value, status):
    """Esito non interpretabile (rate limit, redirect, 5xx...) -> None, mai alive/revoked."""
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=status))
    assert detector.validate_liveness(_raw(detector_id, value)) is None


@pytest.mark.parametrize("detector, detector_id, value", [
    (cr.GithubTokenDetector(), "SECRET_GITHUB", _GH),
    (cr.NpmTokenDetector(), "SECRET_NPM", _NPM),
])
def test_liveness_unknown_when_io_boundary_fails(monkeypatch, detector, detector_id, value):
    """Confine I/O che fallisce (httpx assente / errore di rete) -> None, nessun crash."""
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: None)
    assert detector.validate_liveness(_raw(detector_id, value)) is None


def test_aws_and_upstash_have_no_liveness(monkeypatch):
    """AWS = flag-only (SigV4, §10.2); Upstash = rimandata (R6): zero richieste."""
    calls: list = []
    monkeypatch.setattr(cr, "_identity_get",
                        lambda url, headers: calls.append(url) or SimpleNamespace(status_code=200))
    assert cr.AwsAkiaDetector().validate_liveness(_raw("SECRET_AWS_AKIA", _AWS)) is None
    assert cr.UpstashDetector().validate_liveness(_raw("SECRET_UPSTASH", _UPSTASH)) is None
    assert calls == []


# ─── (4) Confine I/O reale `_identity_get` ──────────────────────────────────

def test_identity_get_never_follows_redirects(monkeypatch):
    """follow_redirects=False (P8/§7): un 3xx non deve inoltrare il token a un altro host."""
    import httpx

    seen: dict = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen.update(kwargs)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(httpx, "get", fake_get)
    resp = cr._identity_get(_GITHUB_USER_URL, {"Authorization": "Bearer t"})
    assert resp is not None and resp.status_code == 200
    assert seen["url"] == _GITHUB_USER_URL
    assert seen["headers"] == {"Authorization": "Bearer t"}
    assert seen["follow_redirects"] is False
    assert seen["timeout"] and seen["timeout"] > 0


def test_identity_get_network_error_degrades_to_none_without_logging_token(monkeypatch, caplog):
    """Errore di rete -> None. P8: h11/httpx possono citare il valore di un header nel
    messaggio dell'eccezione ("Illegal header value b'Bearer ...'"): il log non deve
    contenerlo (si logga il tipo dell'errore, non il messaggio)."""
    import httpx

    def boom(url, **kwargs):
        raise httpx.LocalProtocolError(f"Illegal header value b'Bearer {_GH}'")

    monkeypatch.setattr(httpx, "get", boom)
    with caplog.at_level(logging.DEBUG, logger="bastione.modules.secrets.detectors.cloud_repo"):
        assert cr._identity_get(_GITHUB_USER_URL, {"Authorization": f"Bearer {_GH}"}) is None
    assert "LocalProtocolError" in caplog.text           # l'errore è tracciato (R6: mai silenzio)
    assert _GH not in caplog.text                        # P8: il token non finisce nei log


def test_identity_get_returns_none_without_httpx(monkeypatch):
    """Il confine I/O reale degrada a None se httpx manca (L06)."""
    import builtins

    real_import = builtins.__import__

    def no_httpx(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_httpx)
    assert cr._identity_get(_GITHUB_USER_URL, {}) is None


# ─── (5) SecretsModule end-to-end: gate a richieste-zero + P8 ───────────────

_BASE = "https://staging.example.com/"


@pytest.fixture
def only_cloud_repo_detectors():
    """Riduce DETECTORS ai soli detector cloud/repo, così i test non dipendono dagli
    altri detector M5 registrati nello stesso processo (e ripristina a fine test)."""
    import bastione.modules.secrets.detectors.base as base_mod

    original = list(base_mod.DETECTORS)
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend([
        cr.AwsAkiaDetector(), cr.GithubTokenDetector(),
        cr.NpmTokenDetector(), cr.UpstashDetector(),
    ])
    yield
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend(original)


def _run_module(monkeypatch, *, max_intrusion: IntrusionLevel, ownership_verified: bool):
    import bastione.modules.secrets.module as mod_module
    from bastione.modules.secrets.module import SecretsModule

    content = f'const a="{_AWS}",g="{_GH}",n="{_NPM}",u="{_UPSTASH}";'
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


def _assert_no_sentinel_in_findings(result) -> None:
    """P8: il valore in chiaro non compare in nessun campo del Finding (né nel suo repr)."""
    for f in result.findings:
        dumped = f.model_dump_json() + repr(f)
        for sentinel in _SENTINELS:
            assert sentinel not in dumped


def test_module_read_only_detects_all_with_zero_liveness_requests(monkeypatch, only_cloud_repo_detectors):
    calls: list = []
    monkeypatch.setattr(cr, "_identity_get",
                        lambda url, headers: calls.append(url) or SimpleNamespace(status_code=200))
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=True)

    by_rule = {f.rule_id: f for f in result.findings}
    assert set(by_rule) == {"SECRET_AWS_AKIA", "SECRET_GITHUB", "SECRET_NPM", "SECRET_UPSTASH"}
    assert all(f.severity == Severity.HIGH for f in result.findings)
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)
    assert calls == []                                  # gate: richieste zero
    _assert_no_sentinel_in_findings(result)


def test_module_probe_without_ownership_makes_zero_liveness_requests(monkeypatch, only_cloud_repo_detectors):
    calls: list = []
    monkeypatch.setattr(cr, "_identity_get",
                        lambda url, headers: calls.append(url) or SimpleNamespace(status_code=200))
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)

    assert {f.rule_id for f in result.findings} == {
        "SECRET_AWS_AKIA", "SECRET_GITHUB", "SECRET_NPM", "SECRET_UPSTASH"}
    assert calls == []
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)
    _assert_no_sentinel_in_findings(result)


def test_module_probe_with_ownership_runs_identity_liveness_only_for_github_and_npm(
        monkeypatch, only_cloud_repo_detectors):
    calls: list = []

    def fake(url, headers):
        calls.append(url)
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(cr, "_identity_get", fake)
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)

    # Solo gli host fissi di GitHub e npm; nessuna richiesta per AWS/Upstash.
    assert sorted(calls) == sorted([_GITHUB_USER_URL, _NPM_WHOAMI_URL])
    by_rule = {f.rule_id: f for f in result.findings}
    for rule in ("SECRET_GITHUB", "SECRET_NPM"):
        assert by_rule[rule].intrusion_used == IntrusionLevel.PROBE
        assert "VIVA" in by_rule[rule].description.upper()
    assert by_rule["SECRET_AWS_AKIA"].intrusion_used == IntrusionLevel.READ_ONLY
    assert by_rule["SECRET_UPSTASH"].intrusion_used == IntrusionLevel.READ_ONLY
    _assert_no_sentinel_in_findings(result)


def test_module_probe_revoked_token_is_reported_without_leaking_it(monkeypatch, only_cloud_repo_detectors):
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)

    by_rule = {f.rule_id: f for f in result.findings}
    for rule in ("SECRET_GITHUB", "SECRET_NPM"):
        assert by_rule[rule].intrusion_used == IntrusionLevel.PROBE
        assert "REVOC" in by_rule[rule].description.upper()
    _assert_no_sentinel_in_findings(result)


def test_module_liveness_io_failure_does_not_crash_or_enrich(monkeypatch, only_cloud_repo_detectors):
    """Resilienza: confine I/O che fallisce (None) o che esplode -> la detection resta."""
    monkeypatch.setattr(cr, "_identity_get", lambda url, headers: None)
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    assert {f.rule_id for f in result.findings} == {
        "SECRET_AWS_AKIA", "SECRET_GITHUB", "SECRET_NPM", "SECRET_UPSTASH"}
    assert all(f.intrusion_used == IntrusionLevel.READ_ONLY for f in result.findings)

    def boom(url, headers):
        raise RuntimeError("probe esploso")

    monkeypatch.setattr(cr, "_identity_get", boom)
    result = _run_module(monkeypatch, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    assert {f.rule_id for f in result.findings} == {
        "SECRET_AWS_AKIA", "SECRET_GITHUB", "SECRET_NPM", "SECRET_UPSTASH"}
    _assert_no_sentinel_in_findings(result)
