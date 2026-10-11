# tests/test_zap_active.py
from pathlib import Path
import pytest
from bastione.enums import IntrusionLevel, Severity
from bastione.gate import IntrusionDenied
from bastione.models import (ApiEndpoint, AuthConfig, Fingerprint, RunContext,
                             TargetConfig, TestAccount)


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _cfg():
    auth = AuthConfig(
        test_accounts=[TestAccount(label="A", mode="token", token_env="T_A")],
        api_endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list")])
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned", ownership_token="tok", auth=auth)


def _ctx(*, max_intrusion=IntrusionLevel.MUTATING, ownership_verified=True, run_dir=None):
    return RunContext(target_cfg=_cfg(), fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=max_intrusion, run_dir=run_dir or Path("."),
                      ownership_verified=ownership_verified)


def _sessions_patch(monkeypatch):
    import bastione.modules.zap_active.module as m
    from bastione.models import AuthSession
    monkeypatch.setattr(m, "acquire_session",
                        lambda acc, *, _http=None: AuthSession(account_label=acc.label,
                                                               headers={"Authorization": "Bearer x"},
                                                               acquired_ok=True))


def test_module_name_and_intrusion():
    from bastione.modules.zap_active.module import ZapActiveModule
    assert ZapActiveModule.name == "zap_active"
    assert ZapActiveModule.max_intrusion == IntrusionLevel.MUTATING


def test_below_mutating_skipped_no_scan(monkeypatch):
    import bastione.modules.zap_active.module as m
    from bastione.modules.zap_active.module import ZapActiveModule
    called = []
    monkeypatch.setattr(m, "_run_zap_active", lambda *a, **k: called.append(a) or None)
    res = ZapActiveModule().run(_ctx(max_intrusion=IntrusionLevel.PROBE))
    assert len(res.findings) == 1 and res.findings[0].rule_id == "ZAP_ACTIVE_SKIPPED"
    assert called == []


def test_gate_denied_aborts(monkeypatch):
    """authorize(MUTATING) negato -> IntrusionDenied propaga (run aborta), niente scan."""
    import bastione.modules.zap_active.module as m
    from bastione.modules.zap_active.module import ZapActiveModule
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/zap")
    _sessions_patch(monkeypatch)
    def deny(level, ctx):
        if level >= IntrusionLevel.MUTATING:
            raise IntrusionDenied("negato (test)")
    monkeypatch.setattr(m, "authorize", deny)
    called = []
    monkeypatch.setattr(m, "_run_zap_active", lambda *a, **k: called.append(a) or [])
    with pytest.raises(IntrusionDenied):
        ZapActiveModule().run(_ctx())
    assert called == []


def test_zap_absent_skipped(monkeypatch):
    import bastione.modules.zap_active.module as m
    from bastione.modules.zap_active.module import ZapActiveModule
    monkeypatch.setattr(m.shutil, "which", lambda name: None)
    _sessions_patch(monkeypatch)
    res = ZapActiveModule().run(_ctx())
    assert res.findings[0].rule_id == "ZAP_ACTIVE_SKIPPED"


def test_parses_alerts_into_findings(monkeypatch):
    import bastione.modules.zap_active.module as m
    from bastione.modules.zap_active.module import ZapActiveModule
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/zap")
    _sessions_patch(monkeypatch)
    alerts = [
        {"pluginId": "40012", "name": "Reflected XSS", "risk": "High",
         "url": "https://staging.example.com/api/orders?q=1"},
        {"pluginId": "10202", "name": "Anti-CSRF token missing", "risk": "Medium",
         "url": "https://staging.example.com/api/orders"},
    ]
    monkeypatch.setattr(m, "_run_zap_active", lambda base, sh, eps, out: alerts)
    res = ZapActiveModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert "40012" in rids and "10202" in rids
    xss = next(f for f in res.findings if f.rule_id == "40012")
    assert xss.severity == Severity.HIGH
    assert xss.intrusion_used == IntrusionLevel.MUTATING


def test_run_zap_active_none_returns_empty(monkeypatch):
    import bastione.modules.zap_active.module as m
    from bastione.modules.zap_active.module import ZapActiveModule
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/zap")
    _sessions_patch(monkeypatch)
    monkeypatch.setattr(m, "_run_zap_active", lambda base, sh, eps, out: None)
    res = ZapActiveModule().run(_ctx())
    assert res.findings == [] and res.posture_checks == []


# ── regressione policy vincolata ENFORCED (non solo documentale) ──────────────
# La costante _EXCLUDED_ASCAN dev'essere applicata DA CODICE (disableScanners
# prima di ascan/scan), non solo citata nei docstring. Questi test esercitano il
# path REALE di _run_zap_active con un httpx fittizio iniettato in sys.modules.

class _FakeResp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._p = payload if payload is not None else {"alerts": []}

    def json(self):
        return self._p


class _FakeHttpx:
    """httpx fittizio: registra ogni GET (url, params) per ispezione (offline)."""
    def __init__(self, fail_disable=False):
        self.calls = []  # list[(url, params)]
        self._fail_disable = fail_disable

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, dict(params or {})))
        if url.endswith("/ascan/action/disableScanners/"):
            return _FakeResp(status_code=500 if self._fail_disable else 200)
        if url.endswith("/ascan/action/scan/"):
            return _FakeResp(status_code=200, payload={"scan": "0"})
        if url.endswith("/ascan/view/status/"):
            return _FakeResp(status_code=200, payload={"status": "100"})
        if url.endswith("/core/view/alerts/"):
            return _FakeResp(status_code=200, payload={"alerts": []})
        return _FakeResp(status_code=200)


def _install_fake_httpx(monkeypatch, fake):
    import sys
    monkeypatch.setitem(sys.modules, "httpx", fake)


def test_excluded_scanner_ids_not_empty_and_covers_categories():
    """_EXCLUDED_ASCAN deve espandersi in scanner-id concreti (mai lista vuota)."""
    import bastione.modules.zap_active.module as m
    ids = m._excluded_scanner_ids()
    assert ids, "la policy di esclusione non deve essere vuota"
    # ogni categoria distruttiva contribuisce almeno un id
    for cat in m._EXCLUDED_ASCAN.split(","):
        assert m._EXCLUDED_SCANNER_IDS.get(cat.strip()), f"categoria {cat} senza scanner-id"


def test_real_path_applies_exclusion_policy_before_scan(monkeypatch):
    """Path reale: la policy vincolata (disableScanners) è chiamata PRIMA di ascan/scan
    e include gli scanner-id distruttivi di _EXCLUDED_ASCAN."""
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080")
    monkeypatch.setenv("BASTIONE_ZAP_API_KEY", "k")
    fake = _FakeHttpx()
    _install_fake_httpx(monkeypatch, fake)
    out = str(Path(".") / "zap-active.json")
    res = m._run_zap_active("https://staging.example.com",
                            {"Authorization": "Bearer x"}, ["/api/orders"], out)
    assert res == []  # alerts vuoti dal daemon fittizio
    urls = [u for u, _ in fake.calls]
    # ordine: disableScanners PRIMA di ascan/scan
    i_disable = next(i for i, u in enumerate(urls) if u.endswith("/ascan/action/disableScanners/"))
    i_scan = next(i for i, u in enumerate(urls) if u.endswith("/ascan/action/scan/"))
    assert i_disable < i_scan, "la policy vincolata va applicata PRIMA dello scan"
    # gli scanner-id distruttivi sono passati alla disableScanners
    _, disable_params = fake.calls[i_disable]
    passed_ids = set(disable_params.get("ids", "").split(","))
    assert set(m._excluded_scanner_ids()) <= passed_ids
    # lo scan gira SOLO sulla policy vincolata
    _, scan_params = fake.calls[i_scan]
    assert scan_params.get("scanPolicyName") == m._CONSTRAINED_POLICY


def test_real_path_fail_closed_when_policy_not_applied(monkeypatch):
    """Se disableScanners fallisce, lo scan NON parte (fail-closed) e ritorna None:
    nessuna regola distruttiva può girare contro il target."""
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080")
    fake = _FakeHttpx(fail_disable=True)
    _install_fake_httpx(monkeypatch, fake)
    out = str(Path(".") / "zap-active.json")
    res = m._run_zap_active("https://staging.example.com",
                            {"Authorization": "Bearer x"}, ["/api/orders"], out)
    assert res is None  # degrado fail-closed
    urls = [u for u, _ in fake.calls]
    assert not any(u.endswith("/ascan/action/scan/") for u in urls), \
        "nessun active scan deve partire se la policy vincolata non è applicata"


def test_real_path_no_addr_returns_none_no_calls(monkeypatch):
    """Senza BASTIONE_ZAP_ADDR: nessuna chiamata e None (degrado §4.7)."""
    import bastione.modules.zap_active.module as m
    monkeypatch.delenv("BASTIONE_ZAP_ADDR", raising=False)
    fake = _FakeHttpx()
    _install_fake_httpx(monkeypatch, fake)
    res = m._run_zap_active("https://staging.example.com", {}, [], "out.json")
    assert res is None and fake.calls == []


# ── Task 4: verifica wiring via orchestrator ──────────────────────────────────
def test_m4_lanes_registered_via_orchestrator():
    import importlib
    from bastione.orchestrator import _ensure_modules_loaded
    from bastione.modules.base import REGISTRY
    # Forza la ri-registrazione (i decoratori @register girano sull'import):
    # test_modules_base.py svuota REGISTRY nel teardown; importlib.reload
    # riesegue il corpo del modulo (e quindi il @register) a prescindere
    # da sys.modules, garantendo che i 3 moduli siano presenti.
    import bastione.modules.login_hardening.module as lh_mod
    import bastione.modules.server_exposure.module as se_mod
    import bastione.modules.zap_active.module as za_mod
    importlib.reload(lh_mod)
    importlib.reload(se_mod)
    importlib.reload(za_mod)
    _ensure_modules_loaded()
    assert {"login_hardening", "server_exposure", "zap_active"} <= set(REGISTRY)
    assert REGISTRY["zap_active"].max_intrusion.name == "MUTATING"
    assert REGISTRY["login_hardening"].max_intrusion.name == "PROBE"


# ── Task 12 (M5): zap_active dice la verità (§4.6) ────────────────────────────
class _FakeHttpx2:
    """Fake ZAP daemon per i fix M5. Registra (url, params) e risponde a tutti gli
    endpoint usati: disableScanners, replacer add/remove, accessUrl, scan, status, alerts,
    removeScanPolicy. `alerts_payload` e `status_seq` configurabili."""
    HTTPError = Exception
    def __init__(self, alerts=None, status_seq=("100",)):
        self.calls = []; self._alerts = alerts or []; self._status = list(status_seq)
    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params or {}))
        if url.endswith("/ascan/action/scan/"):
            return _J({"scan": "1"})
        if url.endswith("/ascan/view/status/"):
            return _J({"status": self._status.pop(0) if len(self._status) > 1 else self._status[0]})
        if url.endswith("/core/view/alerts/"):
            return _J({"alerts": self._alerts})
        return _J({})
class _J:
    # status_code=200 di default: `_apply_excluded_policy` lo controlla su
    # disableScanners (che _FakeHttpx2 serve dal ramo generico).
    def __init__(self, p, status_code=200): self._p = p; self.status_code = status_code
    def json(self): return self._p

def test_session_header_applied_before_scan(monkeypatch, tmp_path):
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080")
    monkeypatch.setenv("BASTIONE_ZAP_API_KEY", "k")
    fake = _FakeHttpx2(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {"Authorization": "Bearer x"},
                      ["/api/orders"], str(tmp_path / "o.json"))
    urls = [u for u, _ in fake.calls]
    i_rule = next(i for i, u in enumerate(urls) if u.endswith("/replacer/action/addRule/"))
    i_scan = next(i for i, u in enumerate(urls) if u.endswith("/ascan/action/scan/"))
    assert i_rule < i_scan                                   # (a) sessione prima dello scan
    _, rp = fake.calls[i_rule]
    assert rp.get("matchString") == "Authorization" and rp.get("matchType") == "REQ_HEADER"

def test_endpoints_seeded_before_scan(monkeypatch, tmp_path):
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    fake = _FakeHttpx2(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {}, ["/api/orders", "/api/notes"], str(tmp_path/"o.json"))
    seeded = [p.get("url") for u, p in fake.calls if u.endswith("/core/action/accessUrl/")]
    assert "https://staging.example/api/orders" in seeded and "https://staging.example/api/notes" in seeded

def test_waits_for_status_before_alerts(monkeypatch, tmp_path):     # (c)
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    monkeypatch.setattr(m.time, "sleep", lambda *_: None)
    fake = _FakeHttpx2(status_seq=("50", "100")); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {}, [], str(tmp_path/"o.json"))
    urls = [u for u, _ in fake.calls]
    i_status = next(i for i, u in enumerate(urls) if u.endswith("/ascan/view/status/"))
    i_alerts = next(i for i, u in enumerate(urls) if u.endswith("/core/view/alerts/"))
    assert i_status < i_alerts

def test_teardown_in_finally_even_on_error(monkeypatch, tmp_path):   # (d)
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY","k")
    class _Boom(_FakeHttpx2):
        def get(self, url, params=None, timeout=None):
            if url.endswith("/core/view/alerts/"): raise RuntimeError("boom")
            return super().get(url, params, timeout)
    fake = _Boom(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {"Authorization": "x"}, [], str(tmp_path/"o.json"))
    urls = [u for u, _ in fake.calls]
    assert any(u.endswith("/replacer/action/removeRule/") for u in urls)
    assert any(u.endswith("/ascan/action/removeScanPolicy/") for u in urls)

def test_cookie_session_passed_to_boundary(monkeypatch):            # cookie non più scartati
    import bastione.modules.zap_active.module as m
    from bastione.models import AuthSession
    monkeypatch.setattr(m, "acquire_session", lambda acc, *, _http=None: AuthSession(
        account_label=acc.label, cookies={"sid": "abc"}, acquired_ok=True))
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/zap")
    seen = {}
    monkeypatch.setattr(m, "_run_zap_active", lambda base, sh, eps, out: seen.setdefault("sh", sh) or [])
    m.ZapActiveModule().run(_ctx())
    assert "Cookie" in seen["sh"] and "sid=abc" in seen["sh"]["Cookie"]


def test_teardown_removes_rules_added_before_partial_failure(monkeypatch, tmp_path):
    """La 2a addRule fallisce: la 1a regola (che porta la credenziale) va rimossa
    comunque nel finally — cleanup garantito anche su fallimento parziale (§4.6)."""
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY", "k")
    class _BoomSecondRule(_FakeHttpx2):
        n = 0
        def get(self, url, params=None, timeout=None):
            if url.endswith("/replacer/action/addRule/"):
                type(self).n += 1
                if type(self).n == 2:
                    self.calls.append((url, params or {}))
                    raise RuntimeError("addRule boom")
            return super().get(url, params, timeout)
    fake = _BoomSecondRule(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    out = m._run_zap_active("https://staging.example",
                            {"Authorization": "Bearer x", "Cookie": "sid=y"}, [],
                            str(tmp_path / "o.json"))
    assert out is None                                       # degrado, nessuno scan
    removed = [p.get("description") for u, p in fake.calls
               if u.endswith("/replacer/action/removeRule/")]
    assert "bastione-auth-0" in removed
    assert not any(u.endswith("/ascan/action/scan/") for u, _ in fake.calls)


def test_session_rules_scoped_to_target_origin(monkeypatch, tmp_path):
    """La credenziale è iniettata solo verso l'origin del target (owned-only §7)."""
    import re as _re
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_ADDR", "http://127.0.0.1:8080"); monkeypatch.setenv("BASTIONE_ZAP_API_KEY", "k")
    fake = _FakeHttpx2(); monkeypatch.setitem(__import__("sys").modules, "httpx", fake)
    m._run_zap_active("https://staging.example", {"Authorization": "Bearer x"}, [],
                      str(tmp_path / "o.json"))
    scope = next(p["url"] for u, p in fake.calls if u.endswith("/replacer/action/addRule/"))
    assert _re.search(scope, "https://staging.example/api/orders")
    assert _re.search(scope, "https://staging.example")
    assert not _re.search(scope, "https://staging.example.evil.com/x")
    assert not _re.search(scope, "https://evil.example/?u=https://staging.example/")



@pytest.mark.parametrize("raw,expected", [("600", 600), (" 900 ", 900), ("30m", 1800),
                                          ("", 1800), ("-5", 1800), ("0", 1800)])
def test_scan_deadline_env_parse_never_raises(monkeypatch, raw, expected):
    import bastione.modules.zap_active.module as m
    monkeypatch.setenv("BASTIONE_ZAP_SCAN_TIMEOUT", raw)
    assert m._scan_deadline() == expected
