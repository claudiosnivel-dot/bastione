import builtins
import sys

from bastione.models import TestAccount


class _Resp:
    def __init__(self, status_code=200, payload=None, cookies=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.cookies = cookies or {}
    def json(self):
        return self._payload


def test_token_mode_reads_env_builds_bearer(monkeypatch):
    import bastione.auth.session as s
    monkeypatch.setenv("BASTIONE_IDOR_B_TOKEN", "tok-xyz")
    acc = TestAccount(label="B", mode="token", token_env="BASTIONE_IDOR_B_TOKEN")
    # nessuna rete in token mode → _http non deve essere chiamato
    sess = s.acquire_session(acc, _http=lambda *a, **k: (_ for _ in ()).throw(AssertionError("no net")))
    assert sess.acquired_ok is True
    assert sess.headers["Authorization"] == "Bearer tok-xyz"


def test_token_mode_missing_env_not_acquired(monkeypatch):
    import bastione.auth.session as s
    monkeypatch.delenv("BASTIONE_IDOR_B_TOKEN", raising=False)
    acc = TestAccount(label="B", mode="token", token_env="BASTIONE_IDOR_B_TOKEN")
    sess = s.acquire_session(acc, _http=lambda *a, **k: None)
    assert sess.acquired_ok is False


def test_login_post_extracts_json_token(monkeypatch):
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    acc = TestAccount(label="A", mode="login_post",
                      login_url="https://staging.example.com/api/auth/login",
                      email="a@example.com", password_env="PW",
                      session_json_path="access_token")
    captured = {}
    def fake_http(method, url, *, json=None, headers=None):
        captured["method"] = method; captured["json"] = json
        return _Resp(200, {"access_token": "jwt-123"})
    sess = s.acquire_session(acc, _http=fake_http)
    assert sess.acquired_ok is True
    assert sess.headers["Authorization"] == "Bearer jwt-123"
    assert captured["method"] == "POST"
    assert captured["json"] == {"email": "a@example.com", "password": "pw"}


def test_login_post_failure_not_acquired(monkeypatch):
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    acc = TestAccount(label="A", mode="login_post", login_url="https://s/api/login",
                      email="a@example.com", password_env="PW", session_json_path="access_token")
    sess = s.acquire_session(acc, _http=lambda *a, **k: _Resp(401, {}))
    assert sess.acquired_ok is False


def test_p8_token_not_in_repr(monkeypatch):
    import bastione.auth.session as s
    monkeypatch.setenv("T", "supersecrettoken")
    acc = TestAccount(label="B", mode="token", token_env="T")
    sess = s.acquire_session(acc, _http=lambda *a, **k: None)
    assert "supersecrettoken" not in repr(sess)


def _login_post_acc():
    return TestAccount(
        label="A", mode="login_post",
        login_url="https://staging.example.com/api/auth/login",
        email="a@example.com", password_env="PW", session_json_path="access_token")


def test_http_request_returns_none_without_httpx(monkeypatch):
    """REGRESSIONE: il confine I/O REALE (_http_request) degrada a None se httpx
    manca (ramo `except ImportError`), senza sollevare (§4.7)."""
    import bastione.auth.session as s
    real_import = builtins.__import__

    def no_httpx(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_httpx)
    assert s._http_request("POST", "https://staging.example.com/api/auth/login",
                           json={"email": "a@example.com", "password": "pw"}) is None


def test_http_request_returns_none_without_httpx_via_sys_modules(monkeypatch):
    """REGRESSIONE: httpx=None in sys.modules → _http_request ritorna None, nessun crash."""
    import bastione.auth.session as s
    monkeypatch.setitem(sys.modules, "httpx", None)
    assert s._http_request("POST", "https://staging.example.com/api/auth/login") is None


def test_acquire_session_login_post_no_httpx_not_acquired(monkeypatch):
    """REGRESSIONE: percorso REALE login_post (senza _http=) con httpx assente →
    acquired_ok=False, nessuna eccezione propagata. Esercita _http_request reale."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    real_import = builtins.__import__

    def no_httpx(name, *args, **kwargs):
        if name == "httpx":
            raise ImportError("no httpx")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_httpx)
    sess = s.acquire_session(_login_post_acc())
    assert sess.acquired_ok is False


def test_acquire_session_never_raises_with_raising_http(monkeypatch):
    """REGRESSIONE (difetto 1): un _http iniettato che SOLLEVA non deve propagare;
    il contratto "mai solleva" (§4.7) degrada a acquired_ok=False. Nessun segreto
    nell'eccezione/log (P8)."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")

    def boom(*a, **k):
        raise RuntimeError("boom")

    sess = s.acquire_session(_login_post_acc(), _http=boom)
    assert sess.acquired_ok is False
    assert sess.account_label == "A"


def test_login_post_session_cookie_present(monkeypatch):
    """Ramo session_cookie: cookie presente → acquired_ok=True con cookie estratto."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    acc = TestAccount(label="A", mode="login_post",
                      login_url="https://staging.example.com/api/auth/login",
                      email="a@example.com", password_env="PW",
                      session_cookie="sid")
    resp = _Resp(200, {}, cookies={"sid": "cookie-val"})
    sess = s.acquire_session(acc, _http=lambda *a, **k: resp)
    assert sess.acquired_ok is True
    assert sess.cookies == {"sid": "cookie-val"}


def test_login_post_session_cookie_absent_not_acquired(monkeypatch):
    """Ramo session_cookie: cookie atteso assente → acquired_ok=False."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    acc = TestAccount(label="A", mode="login_post",
                      login_url="https://staging.example.com/api/auth/login",
                      email="a@example.com", password_env="PW",
                      session_cookie="sid")
    resp = _Resp(200, {}, cookies={})
    sess = s.acquire_session(acc, _http=lambda *a, **k: resp)
    assert sess.acquired_ok is False


def test_login_post_json_raises_not_acquired(monkeypatch):
    """Ramo session_json_path: resp.json() che solleva → token None → not acquired,
    nessuna eccezione propagata (§4.7)."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")

    class _BadResp:
        status_code = 200
        def json(self):
            raise ValueError("not json")

    sess = s.acquire_session(_login_post_acc(), _http=lambda *a, **k: _BadResp())
    assert sess.acquired_ok is False


def test_login_post_json_missing_key_not_acquired(monkeypatch):
    """Ramo session_json_path: chiave del token assente nel JSON → not acquired."""
    import bastione.auth.session as s
    monkeypatch.setenv("PW", "pw")
    sess = s.acquire_session(_login_post_acc(),
                             _http=lambda *a, **k: _Resp(200, {"other": "x"}))
    assert sess.acquired_ok is False
