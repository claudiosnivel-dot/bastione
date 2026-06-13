"""Test del modulo secrets (§10 del blueprint) — OFFLINE.

Due livelli, separati di proposito:

1. **Detector** (SECRET_SERVICE_ROLE): logica pura di rilevamento JWT con claim
   role=="service_role". Testate con JWT sintetici costruiti nel test, senza mock.
   Verifica che l'anon JWT venga ignorato (§8/§10: non confondere mai le due chiavi).

2. **SecretsModule**: cabla _fetch + DETECTORS. Il confine I/O (_fetch a livello
   modulo) è monkeypatchato — nessun host reale contattato. Verifica che l'evidence
   nei Finding sia REDATTA (mai il segreto in chiaro, §P8).
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import (
    Fingerprint,
    ModuleResult,
    RunContext,
    TargetConfig,
    TextAsset,
)


# ─── helper: costruzione JWT sintetici ──────────────────────────────────────

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(role: str, ref: str = "abcdefghijklmnopqrst") -> str:
    """JWT sintetico (header.payload.signature) con il claim `role` richiesto."""
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(json.dumps(
        {"iss": "supabase", "ref": ref, "role": role, "iat": 1, "exp": 2}).encode())
    return f"{header}.{payload}.{_b64url(b'fakesig')}"


def fake_resp(*, url: str, text: str = "") -> SimpleNamespace:
    return SimpleNamespace(url=url, text=text)


# ─── helper: RunContext minimale ────────────────────────────────────────────

def _make_cfg(name: str = "test-target") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url="https://staging.example.com",
        environment="staging",
        ownership="owned",
    )


def _make_ctx(
    resolved_urls: list[str] | None = None,
    cfg: TargetConfig | None = None,
) -> RunContext:
    cfg = cfg or _make_cfg()
    fp = Fingerprint(
        target=cfg.name,
        resolved_urls=resolved_urls or [],
    )
    return RunContext(
        target_cfg=cfg,
        fingerprint=fp,
        max_intrusion=IntrusionLevel.READ_ONLY,
        run_dir=Path("."),
        ownership_verified=False,
    )


# ─── fixture: DETECTORS isolati tra i test ──────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_detectors():
    """Ripristina la lista DETECTORS prima e dopo ogni test per evitare
    interferenze da importazioni o registrazioni multiple."""
    import bastione.modules.secrets.detectors.base as base_mod
    original = list(base_mod.DETECTORS)
    yield
    base_mod.DETECTORS.clear()
    base_mod.DETECTORS.extend(original)


# ─── (1) Detector ABC + DETECTORS ───────────────────────────────────────────

def test_detectors_list_populated_after_import():
    """Importare bastione.modules.secrets.detectors deve popolare DETECTORS
    con almeno il detector SERVICE_ROLE (registrato tramite @register_detector)."""
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors.base import DETECTORS
    ids = [d.detector_id for d in DETECTORS]
    assert "SECRET_SERVICE_ROLE" in ids


def test_register_detector_appends_instance():
    """@register_detector deve appendere un'istanza a DETECTORS e ritornare la
    classe invariata (decoratore puro, come @register nei moduli)."""
    from bastione.modules.secrets.detectors.base import (
        DETECTORS,
        Detector,
        register_detector,
    )
    from bastione.enums import Severity
    from bastione.models import TextAsset

    initial_len = len(DETECTORS)

    @register_detector
    class DummyDetector(Detector):
        detector_id = "DUMMY_TEST"
        title = "Dummy detector per test"
        severity = Severity.INFO
        gdpr_relevant = False

        def scan(self, asset: TextAsset) -> list:
            return []

    assert len(DETECTORS) == initial_len + 1
    assert isinstance(DETECTORS[-1], DummyDetector)
    # Deve ritornare la classe, non un wrapper
    assert issubclass(DummyDetector, Detector)


# ─── (2) ServiceRoleDetector — logica pura ──────────────────────────────────

def test_service_role_detector_finds_service_role_jwt():
    """Il detector deve rilevare un JWT con role=="service_role" (§10)."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    detector = ServiceRoleDetector()
    token = make_jwt("service_role")
    asset = TextAsset(source="https://staging.example.com/app.js", content=f'const x="{token}";')
    secrets = detector.scan(asset)
    assert len(secrets) == 1
    assert secrets[0].detector_id == "SECRET_SERVICE_ROLE"
    assert secrets[0].value == token
    assert secrets[0].location.file == asset.source


def test_service_role_detector_ignores_anon_jwt():
    """LOCKED (§8/§10): un JWT con role=="anon" NON è un segreto; ignorarlo."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    detector = ServiceRoleDetector()
    anon = make_jwt("anon")
    asset = TextAsset(source="https://staging.example.com/app.js", content=f'const k="{anon}";')
    secrets = detector.scan(asset)
    assert secrets == []


def test_service_role_detector_ignores_other_roles():
    """JWT con ruoli sconosciuti (non service_role) vengono ignorati."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    detector = ServiceRoleDetector()
    other = make_jwt("admin")
    asset = TextAsset(source="x.js", content=f'"{other}"')
    assert detector.scan(asset) == []


def test_service_role_detector_finds_multiple():
    """Più JWT service_role nello stesso asset → un RawSecret per ciascuno."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    detector = ServiceRoleDetector()
    t1 = make_jwt("service_role", ref="aaa")
    t2 = make_jwt("service_role", ref="bbb")
    asset = TextAsset(source="b.js", content=f'"{t1}" "{t2}"')
    secrets = detector.scan(asset)
    assert len(secrets) == 2
    values = {s.value for s in secrets}
    assert t1 in values and t2 in values


def test_service_role_detector_attributes():
    """Attributi della classe: severity CRITICAL, gdpr_relevant False (§10)."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    d = ServiceRoleDetector()
    assert d.severity == Severity.CRITICAL
    assert d.gdpr_relevant is False
    assert d.detector_id == "SECRET_SERVICE_ROLE"


def test_service_role_detector_validate_liveness_returns_none():
    """validate_liveness è stub: ritorna None (implementazione base, §10)."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    d = ServiceRoleDetector()
    token = make_jwt("service_role")
    raw = d.scan(TextAsset(source="x", content=f'"{token}"'))[0]
    assert d.validate_liveness(raw) is None


def test_service_role_detector_handles_malformed_jwt_gracefully():
    """Un JWT malformato nel content non deve causare crash; viene ignorato."""
    from bastione.modules.secrets.detectors.service_role import ServiceRoleDetector
    detector = ServiceRoleDetector()
    # eyJ... ma payload non è JSON valido
    fake_token = "eyJhbGciOiJIUzI1NiJ9.NOTBASE64!!.sig"
    asset = TextAsset(source="x.js", content=f'token={fake_token}')
    # Non deve sollevare eccezioni
    secrets = detector.scan(asset)
    assert secrets == []


# ─── (3) SecretsModule — should_run ─────────────────────────────────────────

def test_secrets_module_should_run_always_true():
    """should_run deve ritornare True per qualsiasi target (§9/§10)."""
    # Importa direttamente per non dipendere dal REGISTRY globale
    from bastione.modules.secrets.module import SecretsModule
    mod = SecretsModule()
    fp = Fingerprint(target="t", resolved_urls=[])
    cfg = _make_cfg()
    assert mod.should_run(fp, cfg) is True


def test_secrets_module_max_intrusion_is_read_only():
    """max_intrusion del modulo deve essere READ_ONLY (M0, §10)."""
    from bastione.modules.secrets.module import SecretsModule
    assert SecretsModule.max_intrusion == IntrusionLevel.READ_ONLY


# ─── (4) SecretsModule.run — con _fetch monkeypatchato ──────────────────────

def test_run_with_no_resolved_urls_returns_empty():
    """Con fingerprint senza URL, run() deve ritornare 0 finding senza crash."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401 — popola DETECTORS

    ctx = _make_ctx(resolved_urls=[])
    monkeypatched_fetch = lambda url: None  # noqa: E731
    original = mod_module._fetch
    mod_module._fetch = monkeypatched_fetch
    try:
        from bastione.modules.secrets.module import SecretsModule
        result = SecretsModule().run(ctx)
    finally:
        mod_module._fetch = original

    assert isinstance(result, ModuleResult)
    assert result.findings == []
    assert result.posture_checks == []


def test_run_finds_service_role_in_page(monkeypatch):
    """run() deve rilevare una service_role key nella pagina e restituire un Finding."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    # La pagina contiene direttamente il token (nessun bundle JS in questo test)
    pages = {
        base: fake_resp(url=base, text=f'const KEY="{token}";'),
    }
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.rule_id == "SECRET_SERVICE_ROLE"
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.FIRM
    assert f.module == "secrets"
    assert f.owasp == ["A05:2021"]


def test_run_finding_evidence_is_redacted(monkeypatch):
    """L'evidence del Finding NON deve contenere il token in chiaro (P8)."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'secret="{token}"')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert len(result.findings) >= 1
    evidence = result.findings[0].evidence
    # L'evidence NON deve contenere il token in chiaro
    assert token not in evidence
    # Deve contenere qualcosa (non vuota)
    assert len(evidence) > 0


def test_run_scans_same_host_bundles(monkeypatch):
    """run() deve scaricare i bundle JS same-host e scannerizzarli."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    bundle = "https://staging.example.com/assets/app.js"
    pages = {
        base: fake_resp(url=base, text=f'<script src="/assets/app.js"></script>'),
        bundle: fake_resp(url=bundle, text=f'const S="{token}";'),
    }
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)


def test_run_ignores_off_host_bundles(monkeypatch):
    """Owned-only (§7/§4.2): bundle su host esterno non devono essere scaricati."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    off_host = "https://cdn.example.net/vendor.js"
    fetched: list[str] = []

    def recording_fetch(url: str):
        fetched.append(url)
        if url == base:
            return fake_resp(url=base,
                             text=f'<script src="{off_host}"></script>')
        if url == off_host:
            return fake_resp(url=off_host, text=f'const S="{token}";')
        return None

    monkeypatch.setattr(mod_module, "_fetch", recording_fetch)

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert off_host not in fetched
    assert result.findings == []


def test_run_skips_failed_asset_without_crash(monkeypatch):
    """Un asset non scaricabile (None) viene saltato; non crasha gli altri."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    good = "https://staging.example.com/good.js"
    bad = "https://staging.example.com/bad.js"
    pages = {
        base: fake_resp(url=base,
                        text='<script src="/bad.js"></script>'
                             '<script src="/good.js"></script>'),
        bad: None,
        good: fake_resp(url=good, text=f'const S="{token}";'),
    }
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    # Il bundle good deve essere stato scansionato
    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)


def test_run_no_secrets_returns_empty_findings(monkeypatch):
    """Nessun segreto trovato → 0 finding, nessun crash."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    base = "https://staging.example.com/"
    pages = {
        base: fake_resp(url=base, text="<html>niente di interessante</html>"),
    }
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert result.findings == []
    assert result.posture_checks == []


def test_run_finding_has_correct_target_and_location(monkeypatch):
    """Il Finding deve portare target=cfg.name e location.file=url dell'asset."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'secret="{token}"')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    cfg = _make_cfg(name="my-app")
    ctx = _make_ctx(resolved_urls=[base], cfg=cfg)
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.target == "my-app"
    assert f.location.file == base


def test_run_finding_has_finding_id(monkeypatch):
    """Ogni Finding deve avere un finding_id non vuoto (§16)."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'S="{token}"')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert len(result.findings) >= 1
    assert result.findings[0].finding_id != ""


def test_run_degrades_gracefully_when_fetch_unavailable(monkeypatch):
    """Se _fetch non è disponibile (None dappertutto), nessun crash."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    monkeypatch.setattr(mod_module, "_fetch", lambda url: None)
    ctx = _make_ctx(resolved_urls=["https://staging.example.com/"])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)
    assert result.findings == []


# ─── (5) Singolo fetch della pagina (no doppio download) ─────────────────────

def test_run_fetches_each_page_once(monkeypatch):
    """CLEANUP: la pagina deve essere scaricata UNA SOLA volta (§4.7).

    Prima del fix ogni pagina in resolved_urls veniva fetchata due volte: una
    per estrarre i <script src> e una per scansionarla. Riusando la response, il
    conteggio delle chiamate a _fetch per la pagina deve essere esattamente 1.
    Il bundle JS (non in resolved_urls) va invece fetchato (1 volta)."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    bundle = "https://staging.example.com/assets/app.js"
    pages = {
        base: fake_resp(url=base, text='<script src="/assets/app.js"></script>'),
        bundle: fake_resp(url=bundle, text=f'const S="{token}";'),
    }
    call_count: dict[str, int] = {}

    def counting_fetch(url: str):
        call_count[url] = call_count.get(url, 0) + 1
        return pages.get(url)

    monkeypatch.setattr(mod_module, "_fetch", counting_fetch)

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    # La pagina è scaricata esattamente una volta (riuso della response).
    assert call_count[base] == 1
    # Il bundle (non in cache) è scaricato una volta.
    assert call_count[bundle] == 1
    # E il segreto nel bundle è comunque rilevato (la pipeline funziona).
    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)


def test_run_still_scans_page_content_with_single_fetch(monkeypatch):
    """Il singolo fetch non deve perdere segreti presenti nella pagina stessa:
    la pagina viene scaricata una volta E scansionata (cache riusata)."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'const KEY="{token}";')}
    call_count: dict[str, int] = {}

    def counting_fetch(url: str):
        call_count[url] = call_count.get(url, 0) + 1
        return pages.get(url)

    monkeypatch.setattr(mod_module, "_fetch", counting_fetch)

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert call_count[base] == 1
    assert any(f.rule_id == "SECRET_SERVICE_ROLE" for f in result.findings)


# ─── (6) finding_id allineato alla formula LOCKED §16 ────────────────────────

def test_finding_id_excludes_target_locked_formula():
    """CLEANUP: _finding_id deve seguire la formula LOCKED §16 SENZA `target`:

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    (allineato a baseline/diff.py e supabase/module.py)."""
    from bastione.modules.secrets.module import _finding_id
    from bastione.models import Location

    loc = Location(file="https://staging.example.com/assets/app.js")
    expected = hashlib.sha256(
        f"secrets:SECRET_SERVICE_ROLE:{loc.canonical()}".encode()
    ).hexdigest()[:16]

    assert _finding_id("secrets", "SECRET_SERVICE_ROLE", loc) == expected


def test_finding_id_matches_baseline_diff_formula(monkeypatch):
    """Il finding_id del modulo secrets deve coincidere con quello calcolato da
    bastione.baseline.diff.finding_id sullo stesso Finding (drift/dedup §16):
    la formula è unica e LOCKED in tutto il progetto."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.baseline.diff import finding_id as baseline_finding_id

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'S="{token}"')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    ctx = _make_ctx(resolved_urls=[base])
    from bastione.modules.secrets.module import SecretsModule
    result = SecretsModule().run(ctx)

    assert len(result.findings) >= 1
    f = result.findings[0]
    # L'id emesso dal modulo deve essere esattamente quello ricalcolato dalla
    # baseline (stessa formula LOCKED, target escluso).
    assert f.finding_id == baseline_finding_id(f)


def test_finding_id_independent_of_target(monkeypatch):
    """Due target diversi con lo stesso segreto nella stessa location producono
    lo STESSO finding_id (target escluso dalla formula LOCKED §16)."""
    import bastione.modules.secrets.module as mod_module
    import bastione.modules.secrets.detectors  # noqa: F401

    token = make_jwt("service_role")
    base = "https://staging.example.com/"
    pages = {base: fake_resp(url=base, text=f'S="{token}"')}
    monkeypatch.setattr(mod_module, "_fetch", lambda url: pages.get(url))

    from bastione.modules.secrets.module import SecretsModule

    ctx_a = _make_ctx(resolved_urls=[base], cfg=_make_cfg(name="target-a"))
    ctx_b = _make_ctx(resolved_urls=[base], cfg=_make_cfg(name="target-b"))
    fa = SecretsModule().run(ctx_a).findings[0]
    fb = SecretsModule().run(ctx_b).findings[0]

    assert fa.target != fb.target
    assert fa.finding_id == fb.finding_id
