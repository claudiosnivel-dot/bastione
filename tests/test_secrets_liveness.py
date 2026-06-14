"""Test della liveness service_role — M1 step 2 (§10.2 / §7.1) — OFFLINE.

Due livelli, separati di proposito:

1. **Detector.validate_liveness** (SECRET_SERVICE_ROLE): deriva l'URL dal claim
   `ref` del JWT ed esegue UNA GET read-only privilegiata. Il confine I/O
   (`_probe` a livello modulo in service_role.py) è monkeypatchato — nessun host
   reale contattato. 200 → alive/live, 401/403 → revoked, altro/errore → None.

2. **SecretsModule.run — Stadio 2 (PROBE)**: la liveness gira SOLO se
   max_intrusion ≥ PROBE AND ownership_verified. Gated dal backstop
   `gate.authorize(PROBE, ctx)`. Quando gira, arricchisce il Finding; quando NON
   gira, il comportamento M0 resta IDENTICO (solo detection, nessun probe).

Tutti i test sono OFFLINE: nessuna rete reale (monkeypatch del confine I/O).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import (
    Fingerprint,
    Location,
    ModuleResult,
    RawSecret,
    RunContext,
    TargetConfig,
    TextAsset,
)


# ─── helper: costruzione JWT sintetici ──────────────────────────────────────

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(role: str, ref: str | None = "abcdefghijklmnopqrst") -> str:
    """JWT sintetico (header.payload.signature) con `role` e (opz.) `ref`."""
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    claims: dict = {"iss": "supabase", "role": role, "iat": 1, "exp": 2}
    if ref is not None:
        claims["ref"] = ref
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{_b64url(b'fakesig')}"


def fake_resp(*, status_code: int) -> SimpleNamespace:
    return SimpleNamespace(status_code=status_code)


def fake_page(*, url: str, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(url=url, text=text)


# ─── helper: RunContext minimale ────────────────────────────────────────────

def _make_cfg(name: str = "test-target") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
        ownership_token="tok-123",
    )


def _make_ctx(
    *,
    resolved_urls: list[str] | None = None,
    max_intrusion: IntrusionLevel = IntrusionLevel.READ_ONLY,
    ownership_verified: bool = False,
    cfg: TargetConfig | None = None,
) -> RunContext:
    cfg = cfg or _make_cfg()
    fp = Fingerprint(target=cfg.name, resolved_urls=resolved_urls or [])
    return RunContext(
        target_cfg=cfg,
        fingerprint=fp,
        max_intrusion=max_intrusion,
        run_dir=Path("."),
        ownership_verified=ownership_verified,
    )


@pytest.fixture(autouse=True)
def _reset_detectors():
    """Isola DETECTORS tra i test (come in test_secrets.py)."""
    import bastione.modules.secrets.detectors.base as base_mod
    original = list(base_mod.DETECTORS)
    yield
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend(original)


# ─── (1) Detector.validate_liveness — derivazione URL + esiti ───────────────

def test_validate_liveness_derives_url_from_ref(monkeypatch):
    """L'URL del probe deve derivare dal claim `ref`: https://<ref>.supabase.co/rest/v1/"""
    from bastione.modules.secrets.detectors import service_role as sr

    captured: dict = {}

    def fake_probe(url: str, token: str):
        captured["url"] = url
        captured["token"] = token
        return fake_resp(status_code=200)

    monkeypatch.setattr(sr, "_probe", fake_probe)
    d = sr.ServiceRoleDetector()
    token = make_jwt("service_role", ref="myprojectref")
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE", value=token,
                    location=Location(file="x.js"))
    result = d.validate_liveness(raw)

    assert result is not None
    assert captured["url"] == "https://myprojectref.supabase.co/rest/v1/"
    assert captured["token"] == token


def test_validate_liveness_alive_when_200(monkeypatch):
    """GET privilegiata 200 → LivenessResult(alive=True, mode='live')."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: fake_resp(status_code=200))
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value=make_jwt("service_role"), location=Location(file="x.js"))
    result = d.validate_liveness(raw)
    assert result is not None
    assert result.alive is True
    assert result.mode == "live"


@pytest.mark.parametrize("code", [401, 403])
def test_validate_liveness_revoked_when_401_403(monkeypatch, code):
    """GET 401/403 → LivenessResult(alive=False, mode='revoked')."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: fake_resp(status_code=code))
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value=make_jwt("service_role"), location=Location(file="x.js"))
    result = d.validate_liveness(raw)
    assert result is not None
    assert result.alive is False
    assert result.mode == "revoked"


def test_validate_liveness_unknown_when_other_status(monkeypatch):
    """Status diverso da 200/401/403 → None (sconosciuto)."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: fake_resp(status_code=500))
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value=make_jwt("service_role"), location=Location(file="x.js"))
    assert d.validate_liveness(raw) is None


def test_validate_liveness_unknown_when_probe_none(monkeypatch):
    """Probe ritorna None (httpx assente / errore di rete) → None (degrada)."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: None)
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value=make_jwt("service_role"), location=Location(file="x.js"))
    assert d.validate_liveness(raw) is None


def test_validate_liveness_none_when_ref_missing(monkeypatch):
    """Se il JWT non ha il claim `ref` → None (niente probe, niente crash)."""
    from bastione.modules.secrets.detectors import service_role as sr

    called: list = []
    monkeypatch.setattr(sr, "_probe",
                        lambda url, token: called.append(url) or fake_resp(status_code=200))
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value=make_jwt("service_role", ref=None), location=Location(file="x.js"))
    assert d.validate_liveness(raw) is None
    # Senza ref non si deve nemmeno tentare il probe
    assert called == []


def test_validate_liveness_none_when_jwt_malformed(monkeypatch):
    """Un value non-JWT non deve crashare → None."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: fake_resp(status_code=200))
    d = sr.ServiceRoleDetector()
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE",
                    value="not-a-jwt", location=Location(file="x.js"))
    assert d.validate_liveness(raw) is None


def test_validate_liveness_no_token_in_detail(monkeypatch):
    """P8: il token in chiaro non deve mai comparire nel detail del LivenessResult."""
    from bastione.modules.secrets.detectors import service_role as sr
    monkeypatch.setattr(sr, "_probe", lambda url, token: fake_resp(status_code=200))
    d = sr.ServiceRoleDetector()
    token = make_jwt("service_role")
    raw = RawSecret(detector_id="SECRET_SERVICE_ROLE", value=token,
                    location=Location(file="x.js"))
    result = d.validate_liveness(raw)
    assert result is not None
    assert token not in result.detail


def test_probe_returns_none_without_httpx(monkeypatch):
    """Il confine I/O reale (_probe) degrada a None se httpx manca (L06)."""
    import builtins
    from bastione.modules.secrets.detectors import service_role as sr

    real_import = builtins.__import__

    def no_httpx(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_httpx)
    assert sr._probe("https://x.supabase.co/rest/v1/", "tok") is None


# ─── (2) SecretsModule.run — Stadio 2 gating ────────────────────────────────

def _patch_page_with_token(monkeypatch, token: str, base: str):
    import bastione.modules.secrets.module as mod_module
    pages = {base: fake_page(url=base, text=f'const KEY="{token}";')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))


def test_run_read_only_does_not_call_liveness(monkeypatch):
    """Gate negato (READ_ONLY): la liveness NON deve essere chiamata; M0 identico."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    called: list = []
    monkeypatch.setattr(sr, "_probe",
                        lambda url, tok: called.append(url) or fake_resp(status_code=200))

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.READ_ONLY, ownership_verified=True)
    result = SecretsModule().run(ctx)

    # Detection invariata
    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)
    # Nessun probe di liveness
    assert called == []
    # Il finding resta READ_ONLY
    f = next(f for f in result.findings if f.rule_id == "SECRET_SERVICE_ROLE")
    assert f.intrusion_used == IntrusionLevel.READ_ONLY


def test_run_probe_without_ownership_does_not_call_liveness(monkeypatch):
    """Gate negato (PROBE ma ownership non verificata): nessun probe, gestito."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    called: list = []
    monkeypatch.setattr(sr, "_probe",
                        lambda url, tok: called.append(url) or fake_resp(status_code=200))

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=False)
    result = SecretsModule().run(ctx)

    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)
    assert called == []
    f = next(f for f in result.findings if f.rule_id == "SECRET_SERVICE_ROLE")
    assert f.intrusion_used == IntrusionLevel.READ_ONLY


def test_run_probe_with_ownership_calls_liveness_alive(monkeypatch):
    """Gate aperto (PROBE + ownership): liveness chiamata; finding arricchito (alive)."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    called: list = []
    monkeypatch.setattr(sr, "_probe",
                        lambda url, tok: called.append(url) or fake_resp(status_code=200))

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SecretsModule().run(ctx)

    # La liveness è stata invocata sull'URL derivato dal ref
    assert called and called[0].endswith(".supabase.co/rest/v1/")
    f = next(f for f in result.findings if f.rule_id == "SECRET_SERVICE_ROLE")
    # Finding arricchito: PROBE + descrizione di conferma
    assert f.intrusion_used == IntrusionLevel.PROBE
    assert f.confidence == Confidence.FIRM
    assert "VIVA" in f.description.upper() or "CONFERMATA" in f.description.upper()
    # P8: nessun token in chiaro
    assert token not in f.description
    assert token not in f.evidence


def test_run_probe_with_ownership_revoked(monkeypatch):
    """Gate aperto, liveness 'revoked' (401): finding arricchito come revocato."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    monkeypatch.setattr(sr, "_probe", lambda url, tok: fake_resp(status_code=401))

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SecretsModule().run(ctx)

    f = next(f for f in result.findings if f.rule_id == "SECRET_SERVICE_ROLE")
    assert f.intrusion_used == IntrusionLevel.PROBE
    assert "REVOC" in f.description.upper()
    assert token not in f.description


def test_run_probe_unknown_keeps_finding_read_only(monkeypatch):
    """Liveness sconosciuta (None) → il finding NON viene arricchito (resta READ_ONLY)."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    monkeypatch.setattr(sr, "_probe", lambda url, tok: None)

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SecretsModule().run(ctx)

    f = next(f for f in result.findings if f.rule_id == "SECRET_SERVICE_ROLE")
    # Liveness sconosciuta: il finding di detection resta invariato (READ_ONLY)
    assert f.intrusion_used == IntrusionLevel.READ_ONLY


def test_run_liveness_failure_does_not_crash(monkeypatch):
    """Resilienza: se validate_liveness solleva, la scansione NON deve crashare."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)

    def boom(url, tok):
        raise RuntimeError("probe esploso")

    monkeypatch.setattr(sr, "_probe", boom)

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    # Non deve sollevare
    result = SecretsModule().run(ctx)
    # Il finding di detection resta presente
    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)


def test_run_probe_does_not_add_duplicate_posture(monkeypatch):
    """Stadio 2 NON deve emettere PostureCheck (no duplicazione di
    POSTURE_SERVICE_ROLE_HIDDEN già emesso in NORMALIZE)."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors import service_role as sr
    from bastione.modules.secrets.module import SecretsModule

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    _patch_page_with_token(monkeypatch, token, base)
    monkeypatch.setattr(sr, "_probe", lambda url, tok: fake_resp(status_code=200))

    ctx = _make_ctx(resolved_urls=[base],
                    max_intrusion=IntrusionLevel.PROBE, ownership_verified=True)
    result = SecretsModule().run(ctx)

    assert isinstance(result, ModuleResult)
    assert result.posture_checks == []
