"""Test della corsia IDOR autenticato (M4.1).

Tutto OFFLINE: il confine I/O `_http_request` (modulo-livello) e `acquire_session`
sono monkeypatchati. Nessun target live, nessuna rete. App sintetiche in-memory
(isolata vs bucata) verificano l'oracolo cross-tenant. Guardrail §7/§28:
self-gate, gate-first authorize(MUTATING), cleanup garantito (§11.2), P8 (mai i
dati di A né i token in un campo Finding)."""
from pathlib import Path

import pytest

from bastione.enums import IntrusionLevel, Severity
from bastione.models import (
    ApiEndpoint, AuthConfig, Fingerprint, RunContext, TargetConfig, TestAccount,
)


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _auth(accounts=2, endpoints=None):
    accs = [TestAccount(label=l, mode="token", token_env=f"T_{l}")
            for l in (["A", "B"][:accounts])]
    return AuthConfig(test_accounts=accs,
                      api_endpoints=endpoints or [
                          ApiEndpoint(method="GET", path_template="/api/orders", kind="list")])


def _cfg(auth=None):
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned",
                        ownership_token="tok", auth=auth or _auth())


def _ctx(*, cfg=None, max_intrusion=IntrusionLevel.MUTATING,
         ownership_verified=True, run_dir=None):
    cfg = cfg or _cfg()
    fp = Fingerprint(target=cfg.name, resolved_urls=[])
    return RunContext(target_cfg=cfg, fingerprint=fp, max_intrusion=max_intrusion,
                      run_dir=run_dir or Path("."), ownership_verified=ownership_verified)


# ── Task 5: skeleton / registrazione / self-gate / SKIPPED ──────────────────

def test_idor_module_name_and_intrusion():
    from bastione.modules.idor.module import IdorModule
    assert IdorModule.name == "idor"
    assert IdorModule.max_intrusion == IntrusionLevel.MUTATING


def test_idor_registered():
    import importlib
    import bastione.modules.idor.module as m
    importlib.reload(m)
    from bastione.modules.base import REGISTRY
    assert "idor" in REGISTRY


def test_should_run_needs_two_accounts_and_endpoints():
    from bastione.modules.idor.module import IdorModule
    fp = Fingerprint(target="t", resolved_urls=[])
    assert IdorModule().should_run(fp, _cfg()) is True
    assert IdorModule().should_run(fp, _cfg(auth=_auth(accounts=1))) is False
    assert IdorModule().should_run(fp, TargetConfig(
        name="t", base_url="https://s.example.com", environment="staging",
        ownership="owned")) is False


def test_run_read_only_emits_skipped_no_requests(monkeypatch):
    import bastione.modules.idor.module as m
    from bastione.modules.idor.module import IdorModule
    called = []
    monkeypatch.setattr(m, "_http_request",
                        lambda *a, **k: called.append(a) or None)
    result = IdorModule().run(_ctx(max_intrusion=IntrusionLevel.READ_ONLY,
                                   ownership_verified=False))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "IDOR_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.finding_id != ""
    assert called == []


# ── Task 6: READ cross-tenant probe + oracolo isolamento ────────────────────

def _sessions_patch(monkeypatch):
    """acquire_session → sessioni fittizie A/B con header-ruolo riconoscibile."""
    import bastione.modules.idor.module as m
    from bastione.models import AuthSession
    def fake_acquire(account, *, _http=None):
        return AuthSession(account_label=account.label,
                           headers={"X-Test-Role": account.label}, acquired_ok=True)
    monkeypatch.setattr(m, "acquire_session", fake_acquire)


def _install_app(monkeypatch, *, leaky: bool):
    """App sintetica: GET /api/orders (list) e /api/orders/{id} (read).
    A possiede l'ordine id=1. `leaky=True` serve i dati di A a chiunque."""
    import bastione.modules.idor.module as m

    class _R:
        def __init__(self, status, payload):
            self.status_code = status; self._p = payload
        def json(self): return self._p

    def router(method, url, *, json=None, headers=None, cookies=None):
        role = (headers or {}).get("X-Test-Role")  # "A"/"B"/None(anon)
        if url.endswith("/api/orders"):
            # list: A vede [1]; B/anon vedono [1] solo se leaky
            if role == "A" or leaky:
                return _R(200, [{"id": 1, "owner": "A"}])
            return _R(200, [])
        if url.endswith("/api/orders/1"):
            if role == "A" or leaky:
                return _R(200, {"id": 1, "owner": "A", "total": 999})
            return _R(403, {})
        return _R(404, {})

    monkeypatch.setattr(m, "_http_request", router)


def test_read_probe_isolated_app_no_finding(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    from bastione.models import ApiEndpoint
    _sessions_patch(monkeypatch)
    _install_app(monkeypatch, leaky=False)
    auth = _auth(endpoints=[
        ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
        ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    read_findings = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
    assert read_findings == []
    assert any(p.check_id.startswith("POSTURE_TENANT_ISOLATION") and p.passed
               for p in result.posture_checks)


def test_read_probe_leaky_app_emits_critical(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    from bastione.models import ApiEndpoint
    from bastione.enums import Severity
    _sessions_patch(monkeypatch)
    _install_app(monkeypatch, leaky=True)
    auth = _auth(endpoints=[
        ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
        ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    reads = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
    assert reads, "atteso almeno un finding cross-tenant READ"
    assert reads[0].severity == Severity.CRITICAL
    # P8: il valore-dato di A (999) non compare nell'evidence/description
    assert "999" not in reads[0].evidence
    assert "999" not in reads[0].description


# ── Task 13 (M5): sessione a COOKIE rispettata (§4.6) ───────────────────────

def _install_cookie_app(monkeypatch, *, leaky: bool):
    """App sintetica a sessione COOKIE: senza cookie `sid` ogni richiesta è 401 (il
    ruolo arriva SOLO dal cookie). Se i cookie venissero scartati, A non vedrebbe
    nemmeno i propri ordini → nessun id da sondare → nessun finding: il test di
    regressione è quindi discriminante (RED prima del fix Task 13)."""
    import bastione.modules.idor.module as m
    from bastione.models import AuthSession
    def fake_acquire(account, *, _http=None):
        return AuthSession(account_label=account.label, cookies={"sid": account.label},
                           acquired_ok=True)
    monkeypatch.setattr(m, "acquire_session", fake_acquire)

    class _R:
        def __init__(self, status, payload): self.status_code = status; self._p = payload
        def json(self): return self._p
    def router(method, url, *, json=None, headers=None, cookies=None):
        role = (cookies or {}).get("sid")
        if role is None:
            return _R(401, {})
        if url.endswith("/api/orders"):
            if role == "A" or leaky:
                return _R(200, [{"id": 1, "owner": "A"}])
            return _R(200, [])
        if url.endswith("/api/orders/1"):
            if role == "A" or leaky:
                return _R(200, {"id": 1, "owner": "A", "total": 999})
            return _R(403, {})
        return _R(404, {})
    monkeypatch.setattr(m, "_http_request", router)


def test_cookie_session_is_respected(monkeypatch):
    """Sessione a COOKIE applicata: con app leaky l'IDOR si trova (prima del fix i
    cookie erano scartati → 401 ovunque → nessun finding)."""
    from bastione.models import ApiEndpoint
    from bastione.modules.idor.module import IdorModule
    _install_cookie_app(monkeypatch, leaky=True)
    auth = _auth(endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
                            ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    reads = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
    assert reads
    assert "999" not in reads[0].evidence and "sid" not in reads[0].evidence   # P8


def test_cookie_session_isolated_app_no_finding(monkeypatch):
    """Variante protetta a cookie: app isolata → nessun IDOR, posture di isolamento ok."""
    from bastione.models import ApiEndpoint
    from bastione.modules.idor.module import IdorModule
    _install_cookie_app(monkeypatch, leaky=False)
    auth = _auth(endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
                            ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    assert not [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
    assert any(p.check_id.startswith("POSTURE_TENANT_ISOLATION") and p.passed
               for p in result.posture_checks)


# ── Task 7: WRITE cross-tenant — canary usa-e-getta + cleanup garantito ─────

from bastione.gate import IntrusionDenied


def _install_write_app(monkeypatch, *, leaky_write: bool, cleanup_ok: bool = True):
    """App sintetica con create/delete. A crea la canary (id=7). B prova DELETE:
    accettato solo se leaky_write. Cleanup di A: confermato se cleanup_ok."""
    import bastione.modules.idor.module as m

    class _R:
        def __init__(self, status, payload=None):
            self.status_code = status; self._p = payload if payload is not None else {}
        def json(self): return self._p

    state = {"canary_exists": False}

    def router(method, url, *, json=None, headers=None, cookies=None):
        role = (headers or {}).get("X-Test-Role")
        if method == "POST" and url.endswith("/api/notes") and role == "A":
            state["canary_exists"] = True
            return _R(201, {"id": 7})
        if url.endswith("/api/notes/7"):
            if method == "DELETE" and role == "B":
                if leaky_write:
                    state["canary_exists"] = False
                    return _R(204)
                return _R(403)
            if method == "DELETE" and role == "A":   # cleanup di A
                if cleanup_ok:
                    state["canary_exists"] = False
                    return _R(204)
                return _R(500)
            if method == "GET" and role == "A":      # verifica persistenza
                return _R(200, {"id": 7}) if state["canary_exists"] else _R(404)
        return _R(404)

    monkeypatch.setattr(m, "_http_request", router)
    return state


def _write_auth():
    from bastione.models import ApiEndpoint
    return _auth(endpoints=[
        ApiEndpoint(method="POST", path_template="/api/notes", kind="create"),
        ApiEndpoint(method="DELETE", path_template="/api/notes/{id}", kind="delete")])


def test_write_probe_isolated_no_finding_canary_cleaned(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    _sessions_patch(monkeypatch)
    state = _install_write_app(monkeypatch, leaky_write=False)
    result = IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))
    writes = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_WRITE"]
    fails = [f for f in result.findings if f.rule_id == "IDOR_CLEANUP_FAILED"]
    assert writes == []
    assert fails == []
    assert state["canary_exists"] is False  # canary ripulita


def test_write_probe_leaky_emits_critical(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    from bastione.enums import Severity
    _sessions_patch(monkeypatch)
    _install_write_app(monkeypatch, leaky_write=True)
    result = IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))
    writes = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_WRITE"]
    assert writes and writes[0].severity == Severity.CRITICAL
    assert writes[0].intrusion_used.name == "MUTATING"


def test_write_probe_cleanup_failure_emits_cleanup_failed(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    _sessions_patch(monkeypatch)
    _install_write_app(monkeypatch, leaky_write=False, cleanup_ok=False)
    result = IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))
    assert any(f.rule_id == "IDOR_CLEANUP_FAILED" for f in result.findings)


def test_write_probe_no_create_endpoint_skipped(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    from bastione.models import ApiEndpoint
    _sessions_patch(monkeypatch)
    _install_app(monkeypatch, leaky=False)  # solo list/read, niente create
    auth = _auth(endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list")])
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    assert any(f.rule_id == "IDOR_WRITE_SKIPPED_NO_CANARY" for f in result.findings)


def test_write_probe_gate_denied_aborts(monkeypatch):
    """authorize(MUTATING) negato (es. non staging) → IntrusionDenied propaga (la run aborta)."""
    import bastione.modules.idor.module as m
    from bastione.modules.idor.module import IdorModule
    _sessions_patch(monkeypatch)
    _install_write_app(monkeypatch, leaky_write=False)
    def deny(level, ctx):
        from bastione.enums import IntrusionLevel
        if level >= IntrusionLevel.MUTATING:
            raise IntrusionDenied("MUTATING negato (test)")
    monkeypatch.setattr(m, "authorize", deny)
    with pytest.raises(IntrusionDenied):
        IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))


# ── Task 8: oracolo §15 (public) READ→soppresso + P8 esplicito ──────────────

def test_public_endpoint_read_is_suppressed(monkeypatch):
    from bastione.modules.idor.module import IdorModule
    from bastione.models import ApiEndpoint, AuthConfig, TestAccount
    _sessions_patch(monkeypatch)
    _install_app(monkeypatch, leaky=True)  # /api/orders leggibile da tutti
    auth = AuthConfig(
        test_accounts=[TestAccount(label="A", mode="token", token_env="T_A"),
                       TestAccount(label="B", mode="token", token_env="T_B")],
        api_endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list")],
        public_endpoints=["/api/orders"])  # dichiarato pubblico di proposito
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    reads = [f for f in result.findings if f.rule_id == "IDOR_CROSS_TENANT_READ"]
    assert reads == []  # soppresso (§15)
    assert any(p.check_id.startswith("POSTURE_TENANT_ISOLATION") and p.passed
               for p in result.posture_checks)


def test_p8_no_token_in_any_finding_field(monkeypatch):
    """Nessun token di sessione trapela in alcun campo Finding."""
    import bastione.modules.idor.module as m
    from bastione.modules.idor.module import IdorModule
    from bastione.models import AuthSession
    SENT = "SECRET_SESSION_TOKEN_VALUE"
    def fake_acquire(account, *, _http=None):
        return AuthSession(account_label=account.label,
                           headers={"Authorization": f"Bearer {SENT}", "X-Test-Role": account.label},
                           acquired_ok=True)
    monkeypatch.setattr(m, "acquire_session", fake_acquire)
    _install_write_app(monkeypatch, leaky_write=True)
    result = IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))
    for f in result.findings:
        for field in (f.evidence, f.title, f.description, (f.remediation_ref or "")):
            assert SENT not in field


# ── Robustezza §4.7: sessioni A/B non acquisite + risposte degeneri ──────────

def test_sessions_not_acquired_emits_skipped_no_requests(monkeypatch):
    """Sessione B non acquisita (acquired_ok=False) → IDOR_SKIPPED INFO, nessuna
    richiesta READ/WRITE (ramo difensivo module.py: sessions['B'] is None)."""
    import bastione.modules.idor.module as m
    from bastione.modules.idor.module import IdorModule
    from bastione.models import AuthSession
    called = []
    # A acquisita, B NO → il guard deve scattare prima di qualsiasi I/O.
    def fake_acquire(account, *, _http=None):
        ok = account.label != "B"
        return AuthSession(account_label=account.label,
                           headers={"X-Test-Role": account.label}, acquired_ok=ok)
    monkeypatch.setattr(m, "acquire_session", fake_acquire)
    monkeypatch.setattr(m, "_http_request",
                        lambda *a, **k: called.append(a) or None)
    result = IdorModule().run(_ctx(cfg=_cfg(auth=_write_auth())))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "IDOR_SKIPPED"
    assert f.severity == Severity.INFO
    assert f.finding_id != ""
    # nessuna fase READ/WRITE: il confine I/O non è mai chiamato.
    assert called == []


def _install_degenerate_app(monkeypatch, *, mode):
    """Router degenere (§4.7), ISOLATO per ruolo (B/anon non vedono i dati di A:
    nessun leak reale). `mode` inietta una forma di body degenere SOLO nelle
    risposte ad A, per esercitare i guard senza fabbricare un finding spurio:
    - 'none'        : _http_request ritorna sempre None (nessuna risposta utile)
    - 'raises'      : il json() di A solleva ValueError
    - 'nondict'     : i body di A sono liste-di-non-dict / stringhe (no .get)
    - 'no_id'       : list di record dict senza 'id'; create ritorna lista (no id)
    - 'leaky_raises': B/anon ricevono 200 ma json() solleva → _nonempty deve
                      degradare a False (niente crash, niente leak spurio)
    Nessuno deve far crashare run() né produrre READ/WRITE spurii."""
    import bastione.modules.idor.module as m

    class _Rnone:  # json() ben formato ma con shape degenere
        def __init__(self, status, payload):
            self.status_code = status; self._p = payload
        def json(self): return self._p

    class _Rraises:
        def __init__(self, status):
            self.status_code = status
        def json(self): raise ValueError("body non-JSON degenere")

    def router(method, url, *, json=None, headers=None, cookies=None):
        if mode == "none":
            return None  # tutto None: nessuna fase progredisce
        role = (headers or {}).get("X-Test-Role")
        # Isolamento: B/anon NON ottengono dati di A (403/empty) → niente leak.
        if role != "A":
            if method in ("GET",) and (url.endswith("/api/orders")
                                       or url.endswith("/api/orders/1")):
                # leaky_raises: 200 a B/anon ma json() solleva → _nonempty=False
                # (il guard except deve evitare crash E finding spurio).
                if mode == "leaky_raises":
                    return _Rraises(200)
                return _Rnone(403, {})
            return _Rnone(404, {})
        # Risposte ad A con shape degenere a seconda del mode.
        if mode == "leaky_raises":
            # A risponde bene (list con id=1 → enqueue /api/orders/1 per il replay).
            if url.endswith("/api/orders"):
                return _Rnone(200, [{"id": 1, "owner": "A"}])
            return _Rnone(200, {"id": 1, "owner": "A"})
        if mode == "raises":
            return _Rraises(200)
        if mode == "nondict":
            if url.endswith("/api/orders") or url.endswith("/api/notes"):
                return _Rnone(200, ["riga-non-dict", 42])  # list di non-dict
            return _Rnone(200, "corpo-stringa-non-dict")   # read/create non-dict
        if mode == "no_id":
            if method == "POST":
                return _Rnone(201, [{"foo": "bar"}])        # create → lista (no .get)
            if url.endswith("/api/orders"):
                return _Rnone(200, [{"owner": "A"}, {"owner": "B"}])  # record senza id
            return _Rnone(200, {"owner": "A"})              # read senza id
        return _Rnone(404, {})

    monkeypatch.setattr(m, "_http_request", router)


@pytest.mark.parametrize("mode", ["none", "raises", "nondict", "no_id", "leaky_raises"])
def test_degenerate_responses_no_crash_no_spurious_findings(monkeypatch, mode):
    """Risposte degeneri (None / json() che solleva / body non-dict / id assente)
    non crashano e non producono IDOR_CROSS_TENANT_READ/WRITE spurii (§4.7)."""
    from bastione.modules.idor.module import IdorModule
    from bastione.models import ApiEndpoint
    _sessions_patch(monkeypatch)
    _install_degenerate_app(monkeypatch, mode=mode)
    # superficie ricca: list + read + create + delete, per esercitare tutti i rami.
    auth = _auth(endpoints=[
        ApiEndpoint(method="GET", path_template="/api/orders", kind="list"),
        ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read"),
        ApiEndpoint(method="POST", path_template="/api/notes", kind="create"),
        ApiEndpoint(method="DELETE", path_template="/api/notes/{id}", kind="delete")])
    # non deve sollevare
    result = IdorModule().run(_ctx(cfg=_cfg(auth=auth)))
    spurious = [f for f in result.findings
                if f.rule_id in ("IDOR_CROSS_TENANT_READ", "IDOR_CROSS_TENANT_WRITE")]
    assert spurious == []
    # al più lo skip dichiarato del WRITE (nessuna canary creabile su input degenere)
    assert all(f.rule_id in ("IDOR_WRITE_SKIPPED_NO_CANARY",)
               or f.rule_id.startswith("IDOR_") for f in result.findings)
