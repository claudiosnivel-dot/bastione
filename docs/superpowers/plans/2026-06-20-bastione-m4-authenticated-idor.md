# Bastione M4 — Modalità autenticata + IDOR cross-tenant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Esecuzione in Bastione (LOCKED):** lo sviluppo Bastione è **workflow-first** (`BASTIONE-WORKFLOWS.md`). I **builder NON eseguono git**: lasciano le modifiche nel working tree; lo **step "Commit" di ogni task lo esegue l'ORCHESTRATORE** dopo il ground-truth `python -m pytest -q` + blind-review. I builder che editano lo **stesso file** vanno **sequenziati** (ownership di file).

**Goal:** Far evolvere Bastione da auditor della superficie anon ad **attaccante autorizzato della superficie autenticata** su app owned (architettura stile titanseo: Supabase lato server, login wall) — fondamenta "modalità autenticata" (M4.0) + corsia **IDOR cross-tenant READ+WRITE** (M4.1).

**Architecture:** Sottosistema custom che riusa gate §7, oracolo §15, canary §11.2, pattern moduli §9/§14, modelli §5, testabilità offline. Tre pezzi: `auth/session.py` (acquisizione sessione, confine I/O monkeypatchabile), `recon/api_surface.py` (scoperta API da bundle + dichiarata), `modules/idor/module.py` (probe cross-tenant + oracolo + canary write con cleanup garantito). L'oracolo cross-tenant è il differenziatore: nessuno scanner pronto conosce la tua tenancy.

**Tech Stack:** Python 3.14, Pydantic v2, typer (CLI), httpx (I/O, opzionale/degradabile), pytest. **NO uv** — i test si lanciano con `python -m pytest -q` (su Windows).

## Global Constraints

- **Guardrail §7/§28 (LOCKED), iniettati in OGNI prompt builder/fixer:** produzione = blocco assoluto; owned-only; READ_ONLY di default; **WRITE cross-tenant = MUTATING staging-only + ownership_token + `--i-own-this-its-staging` + gate-first `authorize(MUTATING, ctx)`**; niente bypass auth, niente brute-force (login SOLO con credenziali di test fornite); **P8** (mai i valori-dato di A né i token di sessione in un campo Finding o nei log/repr); resilienza→`MODULE_ERROR`/`*_SKIPPED` INFO, mai crash/skip silenzioso.
- **I builder NON eseguono git.** Lo step Commit è dell'orchestratore (path espliciti).
- **Tutto OFFLINE nei test:** i confini I/O (`_http_request`, `_get`/`_write`/`_delete_cleanup`) sono **funzioni modulo-livello monkeypatchate**; nessun target live, nessuna rete, nessuna installazione.
- **Segreti via ENV, mai nel TOML:** la config porta i **nomi** delle env var (`token_env`, `password_env`); i valori si leggono con `os.getenv` a runtime (pattern `notify/telegram.py`).
- **`finding_id` LOCKED (§16):** `sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]`.
- **Ground-truth = l'orchestratore** riesegue `python -m pytest -q` (mai il self-report dell'agente) + blind-review adversariale (correctness · sicurezza/P8/guardrail · robustezza/cleanup).
- **Modulo `idor`:** `name="idor"`, `max_intrusion=IntrusionLevel.MUTATING`. READ a PROBE, WRITE a MUTATING (self-gate interno).

---

## File Structure

| File | Responsabilità | Task |
|---|---|---|
| `bastione/models.py` (modifica) | + `TestAccount`, `ApiEndpoint`, `AuthConfig`, `AuthSession`, `ApiSurface`; `TargetConfig.auth`; `Fingerprint.discovered_api_paths` | 1, 3, 4 |
| `bastione/config.py` (modifica) | `_flatten`: parsing `[auth]` (test_accounts, api_endpoints, public_endpoints) | 2 |
| `bastione/auth/__init__.py` (nuovo) | package | 3 |
| `bastione/auth/session.py` (nuovo) | `_http_request` (confine I/O) + `acquire_session` (token / login_post) | 3 |
| `bastione/recon/api_surface.py` (nuovo) | `extract_api_paths` (puro) + `build_api_surface` | 4 |
| `bastione/recon/fingerprint.py` (modifica) | popola `discovered_api_paths` come `discovered_tables` | 4 |
| `bastione/modules/idor/__init__.py` (nuovo) | package | 5 |
| `bastione/modules/idor/module.py` (nuovo) | `IdorModule`: self-gate, READ probe, WRITE canary+cleanup, oracolo §15, `_skipped`, `_finding_id` | 5,6,7,8 |
| `bastione/orchestrator.py` (modifica) | `_ensure_modules_loaded` += idor | 5 |
| `bastione/cli.py` (modifica) | `doctor`/`list-modules` mostrano idor (nessun tool esterno) | 9 |
| `tests/test_config_auth.py` (nuovo) | config models + parsing | 1,2 |
| `tests/test_auth_session.py` (nuovo) | acquire_session | 3 |
| `tests/test_api_surface.py` (nuovo) | estrazione + build | 4 |
| `tests/test_idor.py` (nuovo) | IDOR read/write/oracolo/cleanup/P8/gate | 5,6,7,8 |
| `tests/test_cli.py` / `test_orchestrator.py` (modifica) | wiring idor | 9 |

**Decomposizione per ondate (workflow):** Task 1→2 sequenziali (stesso `models.py`/`config.py`); Task 3 e 4 paralleli (file disgiunti) ma 3 e 4 toccano anche `models.py` → sequenziare i tocchi a `models.py` (1→3→4) e parallelizzare il resto. Task 5→6→7→8 sequenziali (stesso `modules/idor/module.py`). Task 9 ultimo. Blind-review dopo ogni gruppo.

---

## Task 1: Config models — TestAccount, ApiEndpoint, AuthConfig + TargetConfig.auth

**Files:**
- Modify: `bastione/models.py` (aggiungi modelli + campo `auth` a `TargetConfig`)
- Test: `tests/test_config_auth.py`

**Interfaces:**
- Produces:
  - `TestAccount(label:str, mode:Literal["token","login_post"], token_env:str|None, token_header:str="Authorization", token_prefix:str="Bearer ", login_url:str|None, email:str|None, password_env:str|None, session_json_path:str|None, session_cookie:str|None)`
  - `ApiEndpoint(method:str, path_template:str, kind:Literal["list","read","create","update","delete"], public:bool=False)`
  - `AuthConfig(test_accounts:list[TestAccount]=[], api_endpoints:list[ApiEndpoint]=[], public_endpoints:list[str]=[])`
  - `TargetConfig.auth: AuthConfig | None = None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_auth.py
from bastione.models import AuthConfig, ApiEndpoint, TestAccount, TargetConfig


def _base_cfg_kwargs():
    return dict(name="t", base_url="https://staging.example.com",
                environment="staging", ownership="owned")


def test_test_account_token_mode_defaults():
    a = TestAccount(label="B", mode="token", token_env="BASTIONE_IDOR_B_TOKEN")
    assert a.label == "B"
    assert a.token_header == "Authorization"
    assert a.token_prefix == "Bearer "
    assert a.login_url is None


def test_test_account_login_post_mode():
    a = TestAccount(label="A", mode="login_post",
                    login_url="https://staging.example.com/api/auth/login",
                    email="a@example.com", password_env="BASTIONE_IDOR_A_PW",
                    session_json_path="access_token")
    assert a.mode == "login_post"
    assert a.session_json_path == "access_token"


def test_api_endpoint_kind_and_public_default():
    e = ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")
    assert e.public is False
    assert e.kind == "read"


def test_targetconfig_auth_defaults_none_and_accepts_authconfig():
    cfg = TargetConfig(**_base_cfg_kwargs())
    assert cfg.auth is None
    auth = AuthConfig(
        test_accounts=[TestAccount(label="A", mode="token", token_env="X"),
                       TestAccount(label="B", mode="token", token_env="Y")],
        api_endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list")],
        public_endpoints=["/api/health"])
    cfg2 = TargetConfig(**_base_cfg_kwargs(), auth=auth)
    assert len(cfg2.auth.test_accounts) == 2
    assert cfg2.auth.public_endpoints == ["/api/health"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config_auth.py -q`
Expected: FAIL con `ImportError: cannot import name 'AuthConfig'` (i modelli non esistono ancora).

- [ ] **Step 3: Write minimal implementation**

In `bastione/models.py`, aggiungi (vicino a `TargetConfig`, riusando l'import `Literal` già presente; aggiungi `from pydantic import Field` se non presente):

```python
class TestAccount(BaseModel):          # M4.0 — un account di test per il probe autenticato
    label: str                         # es. "A", "B"
    mode: Literal["token", "login_post"]
    # mode="token": il token è in una env var (mai nel TOML), P8
    token_env: str | None = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "      # "" per cookie/raw
    # mode="login_post":
    login_url: str | None = None
    email: str | None = None
    password_env: str | None = None    # nome env var con la password (mai in chiaro)
    session_json_path: str | None = None  # chiave del JSON di risposta col token (es. "access_token")
    session_cookie: str | None = None  # nome del cookie di sessione (alternativa)


class ApiEndpoint(BaseModel):          # M4.0 — un endpoint dell'API applicativa
    method: str                        # GET/POST/PUT/PATCH/DELETE
    path_template: str                 # es. "/api/orders/{id}"
    kind: Literal["list", "read", "create", "update", "delete"]
    public: bool = False               # dichiarato pubblico-di-proposito → oracolo soppresso (§15)


class AuthConfig(BaseModel):           # M4.0 — sezione [auth] del TOML
    test_accounts: list[TestAccount] = []
    api_endpoints: list[ApiEndpoint] = []
    public_endpoints: list[str] = []   # path/prefissi pubblici-di-proposito (§15)
```

E aggiungi a `TargetConfig` il campo:

```python
    auth: AuthConfig | None = None     # [auth] — modalità autenticata (M4.0)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_config_auth.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit** *(eseguito dall'orchestratore)*

```bash
git add bastione/models.py tests/test_config_auth.py
git commit -m "feat(models): TestAccount/ApiEndpoint/AuthConfig + TargetConfig.auth (M4.0)"
```

---

## Task 2: Config parsing — _flatten della sezione [auth]

**Files:**
- Modify: `bastione/config.py` (funzione `_flatten`)
- Test: `tests/test_config_auth.py` (estende)

**Interfaces:**
- Consumes: `AuthConfig`, `TestAccount`, `ApiEndpoint` (Task 1).
- Produces: un TOML con `[auth]` → `TargetConfig.auth` popolato. Mappatura: `[[auth.test_accounts]]`→`test_accounts`, `[[auth.api_endpoints]]`→`api_endpoints`, `[auth.suppression].public_endpoints`→`public_endpoints`.

- [ ] **Step 1: Write the failing test**

```python
# append a tests/test_config_auth.py
import tomllib
from bastione.config import _flatten
from bastione.models import TargetConfig

_AUTH_TOML = """
name = "t"
base_url = "https://staging.example.com"
environment = "staging"
ownership = "owned"

[[auth.test_accounts]]
label = "A"
mode = "login_post"
login_url = "https://staging.example.com/api/auth/login"
email = "a@example.com"
password_env = "BASTIONE_IDOR_A_PW"
session_json_path = "access_token"

[[auth.test_accounts]]
label = "B"
mode = "token"
token_env = "BASTIONE_IDOR_B_TOKEN"

[[auth.api_endpoints]]
method = "GET"
path_template = "/api/orders"
kind = "list"

[[auth.api_endpoints]]
method = "POST"
path_template = "/api/notes"
kind = "create"

[auth.suppression]
public_endpoints = ["/api/health", "/api/public/*"]
"""


def test_flatten_parses_auth_section():
    data = tomllib.loads(_AUTH_TOML)
    cfg = TargetConfig(**_flatten(data))
    assert cfg.auth is not None
    labels = {a.label for a in cfg.auth.test_accounts}
    assert labels == {"A", "B"}
    kinds = {e.kind for e in cfg.auth.api_endpoints}
    assert kinds == {"list", "create"}
    assert cfg.auth.public_endpoints == ["/api/health", "/api/public/*"]


def test_flatten_no_auth_section_leaves_auth_none():
    data = tomllib.loads(
        'name="t"\nbase_url="https://s.example.com"\n'
        'environment="staging"\nownership="owned"\n')
    cfg = TargetConfig(**_flatten(data))
    assert cfg.auth is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config_auth.py -q`
Expected: FAIL su `test_flatten_parses_auth_section` (`cfg.auth is None`, perché `_flatten` non legge ancora `[auth]`).

- [ ] **Step 3: Write minimal implementation**

In `bastione/config.py`, dentro `_flatten`, prima di `return kwargs`, aggiungi (seguendo il pattern di `expectations`/`supabase`):

```python
    auth = data.get("auth")
    if auth is not None:
        auth_kwargs: dict = {}
        if "test_accounts" in auth:
            auth_kwargs["test_accounts"] = auth["test_accounts"]
        if "api_endpoints" in auth:
            auth_kwargs["api_endpoints"] = auth["api_endpoints"]
        # public_endpoints vive in una sotto-tabella per TOML valido dopo un
        # array-of-tables (una chiave nuda dopo [[auth.api_endpoints]] finirebbe
        # in quell'ultima tabella). Accettiamo entrambe le forme per robustezza.
        suppression = auth.get("suppression") or {}
        if "public_endpoints" in suppression:
            auth_kwargs["public_endpoints"] = suppression["public_endpoints"]
        elif "public_endpoints" in auth:
            auth_kwargs["public_endpoints"] = auth["public_endpoints"]
        kwargs["auth"] = auth_kwargs
```

(Pydantic costruisce `AuthConfig` da `auth_kwargs`, e ricorsivamente `TestAccount`/`ApiEndpoint` dalle liste di dict — come fa già per `expectations`→`list[TableExpectation]`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_config_auth.py -q`
Expected: PASS (6 passed totali nel file).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/config.py tests/test_config_auth.py
git commit -m "feat(config): parsing sezione [auth] -> TargetConfig.auth (M4.0)"
```

---

## Task 3: AuthSession model + acquire_session

**Files:**
- Modify: `bastione/models.py` (+ `AuthSession`)
- Create: `bastione/auth/__init__.py` (vuoto), `bastione/auth/session.py`
- Test: `tests/test_auth_session.py`

**Interfaces:**
- Consumes: `TestAccount` (Task 1).
- Produces:
  - `AuthSession(account_label:str, headers:dict[str,str], cookies:dict[str,str], acquired_ok:bool)` — `headers`/`cookies` con `Field(repr=False)` (P8: i token non finiscono nel repr/log).
  - `auth.session._http_request(method, url, *, json=None, headers=None) -> response|None` (confine I/O monkeypatchabile).
  - `auth.session.acquire_session(account: TestAccount, *, _http=None) -> AuthSession` (mai solleva; `acquired_ok=False` su fallimento).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_auth_session.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_auth_session.py -q`
Expected: FAIL con `ModuleNotFoundError: No module named 'bastione.auth'`.

- [ ] **Step 3: Write minimal implementation**

`bastione/models.py` — aggiungi (usa `Field(repr=False)`; `from pydantic import Field` se assente):

```python
class AuthSession(BaseModel):          # M4.0 — sessione acquisita per un account
    account_label: str
    headers: dict[str, str] = Field(default_factory=dict, repr=False)   # P8: token fuori dal repr
    cookies: dict[str, str] = Field(default_factory=dict, repr=False)   # P8
    acquired_ok: bool = False
```

`bastione/auth/__init__.py` — file vuoto.

`bastione/auth/session.py`:

```python
"""Acquisizione sessione per la modalità autenticata (M4.0).

Confine I/O `_http_request` monkeypatchato nei test (offline) — come `_fetch`
(§8) e `_post` (§11.2). I segreti (token/password) si leggono da ENV a runtime,
mai dal TOML (P8). `acquire_session` non solleva mai: degrada a
`acquired_ok=False` (§4.7)."""
from __future__ import annotations

import logging
import os

from bastione.models import AuthSession, TestAccount

log = logging.getLogger("bastione.auth.session")
_HTTP_TIMEOUT = 15.0


def _http_request(method: str, url: str, *, json=None, headers=None):
    """Confine I/O (monkeypatchato nei test). Ritorna la response o None (degrado §4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: auth non disponibile (M4.0)")
        return None
    try:
        return httpx.request(method, url, json=json, headers=headers,
                             timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001 — degrado grazioso
        log.warning("auth %s %s fallita: %s", method, url, exc)
        return None


def acquire_session(account: TestAccount, *, _http=None) -> AuthSession:
    """Acquisisce una sessione per `account`. Mai solleva (§4.7)."""
    http = _http or _http_request
    if account.mode == "token":
        token = os.getenv(account.token_env) if account.token_env else None
        if not token:
            log.info("auth: token assente (env %r) per %r", account.token_env, account.label)
            return AuthSession(account_label=account.label, acquired_ok=False)
        return AuthSession(
            account_label=account.label,
            headers={account.token_header: f"{account.token_prefix}{token}"},
            acquired_ok=True)

    if account.mode == "login_post":
        password = os.getenv(account.password_env) if account.password_env else None
        if not (account.login_url and account.email and password):
            log.info("auth: login_post incompleto per %r", account.label)
            return AuthSession(account_label=account.label, acquired_ok=False)
        resp = http("POST", account.login_url,
                    json={"email": account.email, "password": password})
        if resp is None or getattr(resp, "status_code", 0) >= 400:
            return AuthSession(account_label=account.label, acquired_ok=False)
        if account.session_json_path:
            try:
                token = resp.json().get(account.session_json_path)
            except Exception:  # noqa: BLE001
                token = None
            if not token:
                return AuthSession(account_label=account.label, acquired_ok=False)
            return AuthSession(account_label=account.label,
                               headers={"Authorization": f"Bearer {token}"},
                               acquired_ok=True)
        if account.session_cookie:
            cookies = getattr(resp, "cookies", {}) or {}
            val = cookies.get(account.session_cookie)
            if not val:
                return AuthSession(account_label=account.label, acquired_ok=False)
            return AuthSession(account_label=account.label,
                               cookies={account.session_cookie: val},
                               acquired_ok=True)

    return AuthSession(account_label=account.label, acquired_ok=False)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_auth_session.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/models.py bastione/auth/__init__.py bastione/auth/session.py tests/test_auth_session.py
git commit -m "feat(auth): AuthSession + acquire_session (token/login_post), P8 (M4.0)"
```

---

## Task 4: Scoperta superficie API — extract_api_paths + build_api_surface + Fingerprint.discovered_api_paths

**Files:**
- Modify: `bastione/models.py` (+ `ApiSurface`; `Fingerprint.discovered_api_paths: list[str] = []`)
- Create: `bastione/recon/api_surface.py`
- Modify: `bastione/recon/fingerprint.py` (popola `discovered_api_paths` come `discovered_tables`)
- Test: `tests/test_api_surface.py`

**Interfaces:**
- Consumes: `ApiEndpoint`, `Fingerprint`, `TargetConfig` (Task 1).
- Produces:
  - `Fingerprint.discovered_api_paths: list[str]`
  - `recon.api_surface.extract_api_paths(text:str) -> list[str]` (puro, dedup+sort)
  - `ApiSurface(endpoints:list[ApiEndpoint], extracted_paths:list[str])`
  - `recon.api_surface.build_api_surface(fp:Fingerprint, cfg:TargetConfig) -> ApiSurface`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_api_surface.py
from bastione.models import ApiEndpoint, Fingerprint, TargetConfig, AuthConfig
from bastione.recon.api_surface import extract_api_paths, build_api_surface


def _cfg(endpoints=None):
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned",
                        auth=AuthConfig(api_endpoints=endpoints or []))


def test_extract_api_paths_from_bundle():
    js = """fetch('/api/orders').then(r=>r.json());
            const u = "/api/users/42"; axios.post("/api/notes", body);
            Array.from('abc'); location = '/login';"""
    paths = extract_api_paths(js)
    assert "/api/orders" in paths
    assert "/api/users/42" in paths
    assert "/api/notes" in paths
    # non-/api path non incluso; dedup+sort deterministico
    assert "/login" not in paths
    assert paths == sorted(set(paths))


def test_build_api_surface_declared_is_ground_truth_plus_assist():
    declared = [ApiEndpoint(method="GET", path_template="/api/orders", kind="list")]
    fp = Fingerprint(target="t", resolved_urls=[], discovered_api_paths=["/api/secret-admin"])
    surface = build_api_surface(fp, _cfg(declared))
    assert [e.path_template for e in surface.endpoints] == ["/api/orders"]
    assert "/api/secret-admin" in surface.extracted_paths


def test_build_api_surface_no_auth_empty():
    fp = Fingerprint(target="t", resolved_urls=[])
    cfg = TargetConfig(name="t", base_url="https://s.example.com",
                       environment="staging", ownership="owned")
    surface = build_api_surface(fp, cfg)
    assert surface.endpoints == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_surface.py -q`
Expected: FAIL con `ModuleNotFoundError: No module named 'bastione.recon.api_surface'`.

- [ ] **Step 3: Write minimal implementation**

`bastione/models.py` — aggiungi a `Fingerprint` il campo (dopo `discovered_tables`):

```python
    # Path API applicativi (`/api/...`) referenziati nei bundle same-host (M4.0).
    # Assist alla scoperta della superficie autenticata; la ground truth sono gli
    # endpoint dichiarati in [auth] (§5/§15). Default [] → backward-compatible.
    discovered_api_paths: list[str] = []
```

E un nuovo modello:

```python
class ApiSurface(BaseModel):           # M4.0 — superficie API per il probe autenticato
    endpoints: list[ApiEndpoint] = []  # ground truth (dichiarati in [auth])
    extracted_paths: list[str] = []    # assist: path /api/... estratti dal bundle
```

`bastione/recon/api_surface.py`:

```python
"""Scoperta della superficie API applicativa (M4.0).

`extract_api_paths` è una funzione PURA (nessun I/O): lavora sul testo del bundle
già in memoria (owned-only §7), come `extract_table_names` (§8). La ground truth
del probe sono gli endpoint DICHIARATI in [auth] (con metodo+kind); i path estratti
dal bundle sono un ASSIST per la copertura (analogo a SUPABASE_SCHEMA_VIA_BUNDLE)."""
from __future__ import annotations

import re

from bastione.models import ApiSurface, Fingerprint, TargetConfig

# Letterali stringa che iniziano per /api/ in un bundle JS. Caratteri ammessi in un
# path (lettere, cifre, _-/{}. ); url completi e spazi non matchano (non sono path).
_API_PATH_RE = re.compile(r"""['"](/api/[A-Za-z0-9_\-/{}.]+)['"]""")


def extract_api_paths(text: str) -> list[str]:
    """Path `/api/...` referenziati nel bundle (dedup + sort deterministico)."""
    return sorted({m.group(1) for m in _API_PATH_RE.finditer(text)})


def build_api_surface(fp: Fingerprint, cfg: TargetConfig) -> ApiSurface:
    """Combina endpoint DICHIARATI (ground truth) + path estratti (assist)."""
    declared = list(cfg.auth.api_endpoints) if (cfg.auth and cfg.auth.api_endpoints) else []
    return ApiSurface(endpoints=declared, extracted_paths=list(fp.discovered_api_paths))
```

`bastione/recon/fingerprint.py` — popola `discovered_api_paths` accanto a `discovered_tables`. Trova dove `discovered_tables` viene aggregato sui bundle same-host e aggiungi l'analogo. Esempio del punto da estendere (adatta ai nomi reali nel file):

```python
from bastione.recon.api_surface import extract_api_paths   # in testa al file

# ... dentro fingerprint(), nello stesso loop che fa extract_table_names sui bundle:
        api_paths_acc.update(extract_api_paths(bundle_text))
# ... e alla costruzione del Fingerprint:
        discovered_api_paths=sorted(api_paths_acc),
```

(Se l'aggregazione di `discovered_tables` usa un set `tables_acc`, replica con `api_paths_acc: set[str] = set()` inizializzato accanto.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_api_surface.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Run regression (recon non rotto)**

Run: `python -m pytest tests/test_fingerprint.py -q`
Expected: PASS (tutti verdi — `discovered_api_paths` ha default `[]`, backward-compatible).

- [ ] **Step 6: Commit** *(orchestratore)*

```bash
git add bastione/models.py bastione/recon/api_surface.py bastione/recon/fingerprint.py tests/test_api_surface.py
git commit -m "feat(recon): scoperta superficie API (extract_api_paths + build_api_surface) (M4.0)"
```

---

## Task 5: IdorModule skeleton — registrazione, self-gate, SKIPPED, helper

**Files:**
- Create: `bastione/modules/idor/__init__.py` (vuoto), `bastione/modules/idor/module.py`
- Modify: `bastione/orchestrator.py` (`_ensure_modules_loaded` += idor)
- Test: `tests/test_idor.py`

**Interfaces:**
- Consumes: `Module`/`register` (§9), `authorize`/`IntrusionDenied` (§7), `RunContext`/`Finding`/`Location`/`ModuleResult` (§5), `AuthConfig` (Task 1).
- Produces:
  - `IdorModule(name="idor", max_intrusion=IntrusionLevel.MUTATING)`, `should_run`, `run`.
  - Module-level helpers: `_finding_id(module, rule_id, location)`, `_http_request(method, url, *, json, headers)` (confine I/O monkeypatchabile).
  - `IdorModule._skipped(target, motivo) -> ModuleResult` (Finding `IDOR_SKIPPED` INFO).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_idor.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_idor.py -q`
Expected: FAIL con `ModuleNotFoundError: No module named 'bastione.modules.idor'`.

- [ ] **Step 3: Write minimal implementation**

`bastione/modules/idor/__init__.py` — vuoto.

`bastione/modules/idor/module.py`:

```python
"""IdorModule — probe cross-tenant / IDOR autenticato (M4.1).

Attaccante autorizzato: con due account di TEST owned (A, B) prova a violare
l'isolamento tra tenant. READ a PROBE (B/anon legge i dati di A), WRITE a MUTATING
su risorsa-canary usa-e-getta creata da A (mai dati reali), con cleanup garantito
(§11.2). Oracolo riusa §15 (endpoint dichiarati pubblici → soppressi). P8: mai i
valori-dato di A né i token in un campo Finding. Tutto offline-testabile: il confine
I/O `_http_request` è monkeypatchato nei test.

Guardrail §7/§28: niente bypass auth, niente brute-force; login SOLO con le
credenziali di test fornite via ENV. WRITE gate-first `authorize(MUTATING, ctx)`."""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import (
    Finding, Fingerprint, Location, ModuleResult, RunContext, TargetConfig,
)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.idor")
_HTTP_TIMEOUT = 15.0


def _http_request(method: str, url: str, *, json=None, headers=None):
    """Confine I/O (monkeypatchato nei test). Ritorna response o None (§4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: idor non disponibile (M4.1)")
        return None
    try:
        return httpx.request(method, url, json=json, headers=headers,
                             timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("idor %s %s fallita: %s", method, url, exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, LOCKED)."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@register
class IdorModule(Module):
    """Probe cross-tenant / IDOR autenticato (M4.1). MUTATING 🔴 (il WRITE)."""

    name = "idor"
    max_intrusion = IntrusionLevel.MUTATING

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Vero se ≥2 account di test E ≥1 endpoint API dichiarato (valutazione
        leggera, nessun I/O)."""
        auth = cfg.auth
        return bool(auth and len(auth.test_accounts) >= 2 and auth.api_endpoints)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Self-gate → READ probe (PROBE) → WRITE canary (MUTATING). Sotto PROBE o
        senza ownership: `IDOR_SKIPPED` INFO, nessuna richiesta (M0 invariato)."""
        target = ctx.target_cfg.name
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "idor richiede --max-intrusion >= probe e ownership verificata "
                "(§7): probe cross-tenant saltato, run read-only invariata.")
        # READ + WRITE implementati nei task 6/7 (qui solo lo skeleton).
        return ModuleResult(findings=[], posture_checks=[])

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Finding INFO `IDOR_SKIPPED` (§4.7/§26): skip DICHIARATO, non nascosto."""
        location = Location(endpoint="idor")
        finding = Finding(
            finding_id=_finding_id("idor", "IDOR_SKIPPED", location),
            module="idor", rule_id="IDOR_SKIPPED",
            title="Probe IDOR saltato",
            severity=Severity.INFO, confidence=Confidence.FIRM,
            target=target, location=location, evidence=motivo,
            description=(f"Il probe IDOR (M4.1) è stato saltato: {motivo} "
                         "Skip dichiarato esplicitamente (§4.7/§26): verifica NON eseguita."),
            intrusion_used=IntrusionLevel.READ_ONLY)
        return ModuleResult(findings=[finding], posture_checks=[])
```

`bastione/orchestrator.py` — in `_ensure_modules_loaded`, aggiungi in ordine alfabetico:

```python
    import bastione.modules.idor.module  # noqa: F401  (M4.1 IDOR autenticato)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_idor.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/idor/__init__.py bastione/modules/idor/module.py bastione/orchestrator.py tests/test_idor.py
git commit -m "feat(idor): skeleton modulo + self-gate + IDOR_SKIPPED + wiring (M4.1)"
```

---

## Task 6: READ cross-tenant probe + oracolo isolamento

**Files:**
- Modify: `bastione/modules/idor/module.py` (metodi `_acquire_sessions`, `_read_probe`, findings/posture)
- Test: `tests/test_idor.py` (estende)

**Interfaces:**
- Consumes: `acquire_session` (Task 3), `AuthSession` (Task 3), `_http_request` (Task 5).
- Produces:
  - Finding `IDOR_CROSS_TENANT_READ` (CRITICAL, FIRM, `intrusion_used=PROBE`).
  - PostureCheck `POSTURE_TENANT_ISOLATION_<path>` (passed=True quando regge).
  - metodi `_acquire_sessions(ctx) -> dict[str, AuthSession]`, `_read_probe(ctx, surface, sessions, findings, posture)`.

**Meccanico (oracolo):** per ogni endpoint `kind in {"list","read"}`: come **A** GET → raccogli gli URL/ID risorsa di A; rigioca ogni GET **come B** e **come anon** → se 2xx con corpo non-vuoto coerente per quell'ID di A ⇒ `IDOR_CROSS_TENANT_READ`. 403/404/vuoto ⇒ isolamento OK. Confronto per ID risorsa; **P8**: l'evidence riporta solo `{method, path, ruolo, id}`, mai il corpo/dati di A.

- [ ] **Step 1: Write the failing test**

```python
# append a tests/test_idor.py — app sintetica in-memory (isolata vs bucata)
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

    def router(method, url, *, json=None, headers=None):
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_idor.py -q`
Expected: FAIL (il `run` skeleton ritorna findings=[]: nessun READ finding, nessuna posture).

- [ ] **Step 3: Write minimal implementation**

In `bastione/modules/idor/module.py`, aggiungi l'import in testa:

```python
from bastione.auth.session import acquire_session
from bastione.models import AuthSession, PostureCheck
```

Sostituisci il corpo di `run` (dopo il self-gate) con l'acquisizione sessioni + READ probe, e aggiungi i metodi:

```python
    def run(self, ctx: RunContext) -> ModuleResult:
        target = ctx.target_cfg.name
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(target, "idor richiede --max-intrusion >= probe e "
                                 "ownership verificata (§7): probe cross-tenant saltato.")
        from bastione.recon.api_surface import build_api_surface
        surface = build_api_surface(ctx.fingerprint, ctx.target_cfg)
        sessions = self._acquire_sessions(ctx)
        if sessions.get("A") is None or sessions.get("B") is None:
            return self._skipped(target, "sessioni di test A/B non acquisite "
                                 "(credenziali env assenti?): probe saltato.")
        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        self._read_probe(ctx, surface, sessions, findings, posture)
        # WRITE probe → Task 7
        return ModuleResult(findings=findings, posture_checks=posture)

    def _acquire_sessions(self, ctx: RunContext) -> dict[str, "AuthSession | None"]:
        out: dict[str, AuthSession | None] = {"anon": None}
        for acc in ctx.target_cfg.auth.test_accounts:
            sess = acquire_session(acc)
            out[acc.label] = sess if sess.acquired_ok else None
        return out

    def _request(self, method: str, url: str, sess: "AuthSession | None"):
        headers = dict(sess.headers) if sess else {}
        return _http_request(method, url, headers=headers)

    def _read_probe(self, ctx, surface, sessions, findings, posture) -> None:
        base = ctx.target_cfg.base_url.rstrip("/")
        a = sessions["A"]
        public = set((ctx.target_cfg.auth.public_endpoints or []))
        # 1) come A: raccogli gli URL risorsa leggibili (list/read)
        a_urls: list[str] = []
        for ep in surface.endpoints:
            if ep.kind not in ("list", "read"):
                continue
            url = base + ep.path_template
            if "{id}" in ep.path_template:
                continue  # gli ID concreti vengono dalla list (sotto)
            resp = self._request("GET", url, a)
            if resp is not None and getattr(resp, "status_code", 0) == 200:
                a_urls.append(url)
                for rid in self._ids_from(resp):
                    for read_ep in surface.endpoints:
                        if read_ep.kind == "read" and "{id}" in read_ep.path_template:
                            a_urls.append(base + read_ep.path_template.replace("{id}", str(rid)))
        # 2) rigioca come B e anon
        for url in dict.fromkeys(a_urls):  # dedup, ordine stabile
            path = url[len(base):]
            if self._is_public(path, public):
                posture.append(self._isolation_posture(path, ctx.target_cfg.name, suppressed=True))
                continue
            leaked_by = None
            for role in ("B", "anon"):
                resp = self._request("GET", url, sessions.get(role))
                if resp is not None and getattr(resp, "status_code", 0) == 200 \
                        and self._nonempty(resp):
                    leaked_by = role
                    break
            if leaked_by:
                findings.append(self._read_finding(path, leaked_by, ctx.target_cfg.name))
            else:
                posture.append(self._isolation_posture(path, ctx.target_cfg.name, suppressed=False))

    @staticmethod
    def _ids_from(resp) -> list:
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return []
        if isinstance(body, list):
            return [r.get("id") for r in body if isinstance(r, dict) and r.get("id") is not None]
        return []

    @staticmethod
    def _nonempty(resp) -> bool:
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return False
        return bool(body)

    @staticmethod
    def _is_public(path: str, public: set[str]) -> bool:
        for p in public:
            if p.endswith("*") and path.startswith(p[:-1]):
                return True
            if path == p:
                return True
        return False

    def _read_finding(self, path: str, role: str, target: str) -> Finding:
        location = Location(endpoint=path)
        attacker = "anonimo (non autenticato)" if role == "anon" else "un altro utente (B)"
        # P8: SOLO path + ruolo, mai i dati di A.
        evidence = f"GET {path} accessibile a {attacker} (risorsa di un altro tenant)"
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CROSS_TENANT_READ", location),
            module="idor", rule_id="IDOR_CROSS_TENANT_READ",
            title=f"Lettura cross-tenant su {path}",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location, evidence=evidence,
            description=(f"Una richiesta GET a {path} eseguita come {attacker} restituisce "
                         "i dati appartenenti a un altro tenant: l'autorizzazione lato server "
                         "non isola i tenant (Broken Access Control, OWASP A01). Il valore dei "
                         "dati NON è incluso qui (P8). Verifica la authz dell'endpoint."),
            remediation_ref="IDOR_CROSS_TENANT_READ", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.PROBE)

    @staticmethod
    def _isolation_posture(path: str, target: str, *, suppressed: bool) -> PostureCheck:
        detail = ("endpoint dichiarato pubblico (§15): isolamento non richiesto"
                  if suppressed else "B/anon non accedono alle risorse di A")
        return PostureCheck(
            check_id=f"POSTURE_TENANT_ISOLATION_{path}",
            title=f"Isolamento tenant su {path}", passed=True,
            severity_if_failed=Severity.CRITICAL, target=target, detail=detail,
            remediation_ref="IDOR_CROSS_TENANT_READ")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_idor.py -q`
Expected: PASS (tutti i test idor verdi, inclusi i 2 nuovi).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/idor/module.py tests/test_idor.py
git commit -m "feat(idor): READ cross-tenant probe + oracolo isolamento + P8 (M4.1)"
```

---

## Task 7: WRITE cross-tenant — canary usa-e-getta + cleanup garantito

**Files:**
- Modify: `bastione/modules/idor/module.py` (`_write_probe`, `_canary_*`)
- Test: `tests/test_idor.py` (estende)

**Interfaces:**
- Consumes: `authorize`/`IntrusionDenied` (§7), sessioni (Task 6).
- Produces:
  - Finding `IDOR_CROSS_TENANT_WRITE` (CRITICAL, MUTATING), `IDOR_CLEANUP_FAILED` (CRITICAL), `IDOR_WRITE_SKIPPED_NO_CANARY` (INFO).
  - metodo `_write_probe(ctx, surface, sessions, findings, posture)`.

**Meccanico (canary §11.2):** self-gate `if max_intrusion < MUTATING: return`. **`authorize(MUTATING, ctx)` PRIMA di tutto** (propaga `IntrusionDenied` → la run aborta, non si declassa). Come **A**: `POST` su endpoint `create` con marker → registra l'URL della canary (da `id` nella risposta). Come **B**: `PUT`/`DELETE` sull'URL della canary → se 2xx e persiste (riletto come A) ⇒ `IDOR_CROSS_TENANT_WRITE`. **`try/finally`**: come A elimina la canary; se il DELETE di cleanup non è confermato ⇒ `IDOR_CLEANUP_FAILED`. Nessun endpoint `create` ⇒ `IDOR_WRITE_SKIPPED_NO_CANARY` INFO.

- [ ] **Step 1: Write the failing test**

```python
# append a tests/test_idor.py
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

    def router(method, url, *, json=None, headers=None):
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_idor.py -q`
Expected: FAIL (nessun WRITE probe ancora; i 5 nuovi test falliscono).

- [ ] **Step 3: Write minimal implementation**

In `bastione/modules/idor/module.py`, aggiungi l'import `from bastione.gate import authorize, IntrusionDenied`. In `run`, dopo `self._read_probe(...)` aggiungi:

```python
        self._write_probe(ctx, surface, sessions, findings, posture)
```

E i metodi (il `marker` è un literal fisso per i test deterministici; in produzione derivare un marker non-segreto):

```python
    _CANARY_MARKER = "bastione-idor-canary"

    def _write_probe(self, ctx, surface, sessions, findings, posture) -> None:
        # SELF-GATE: niente WRITE se il tetto non è MUTATING (read-only invariato).
        if ctx.max_intrusion < IntrusionLevel.MUTATING:
            return
        # GATE-FIRST: authorize PRIMA di qualsiasi scrittura. Propaga IntrusionDenied
        # (la run aborta, non si declassa — §7/§22).
        authorize(IntrusionLevel.MUTATING, ctx)

        base = ctx.target_cfg.base_url.rstrip("/")
        target = ctx.target_cfg.name
        create_ep = next((e for e in surface.endpoints if e.kind == "create"), None)
        delete_ep = next((e for e in surface.endpoints if e.kind == "delete"), None)
        if create_ep is None or delete_ep is None:
            findings.append(self._write_skipped_no_canary(target))
            return

        a, b = sessions["A"], sessions["B"]
        # 1) come A: crea la canary usa-e-getta (marker, mai dati reali)
        resp = self._request_json("POST", base + create_ep.path_template, a,
                                  {"title": self._CANARY_MARKER})
        canary_id = self._id_from(resp)
        if canary_id is None:
            findings.append(self._write_skipped_no_canary(target))
            return
        canary_url = base + delete_ep.path_template.replace("{id}", str(canary_id))
        read_url = canary_url  # GET come A per verificare persistenza/cleanup
        cleaned = False
        try:
            # 2) come B: prova a CANCELLARE la canary di A
            del_b = self._request("DELETE", canary_url, b)
            if del_b is not None and getattr(del_b, "status_code", 0) in (200, 204):
                # verifica che sia DAVVERO sparita (riletta come A)
                check = self._request("GET", read_url, a)
                gone = check is not None and getattr(check, "status_code", 0) == 404
                if gone:
                    cleaned = True  # B l'ha cancellata → niente da ripulire
                    findings.append(self._write_finding(delete_ep.path_template, target))
        finally:
            # 3) cleanup GARANTITO come A (se non già cancellata da B)
            if not cleaned:
                dc = self._request("DELETE", canary_url, a)
                ok = dc is not None and getattr(dc, "status_code", 0) in (200, 204)
                if not ok:
                    findings.append(self._cleanup_failed(delete_ep.path_template,
                                                         canary_id, target))

    def _request_json(self, method, url, sess, body):
        headers = dict(sess.headers) if sess else {}
        return _http_request(method, url, json=body, headers=headers)

    @staticmethod
    def _id_from(resp):
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return None
        return body.get("id") if isinstance(body, dict) else None

    def _write_finding(self, path_template: str, target: str) -> Finding:
        location = Location(endpoint=path_template)
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CROSS_TENANT_WRITE", location),
            module="idor", rule_id="IDOR_CROSS_TENANT_WRITE",
            title=f"Scrittura cross-tenant su {path_template}",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence=(f"DELETE {path_template} su una risorsa-canary di A è stato accettato "
                      "come utente B (modifica cross-tenant)"),
            description=("Un altro utente (B) ha potuto cancellare/modificare una risorsa "
                         "creata da A: l'authz di scrittura non isola i tenant (Broken Access "
                         "Control, OWASP A01). Testato su risorsa-canary usa-e-getta (mai dati "
                         "reali). Il caso peggiore di IDOR: distruzione/manomissione dati. (P8)"),
            remediation_ref="IDOR_CROSS_TENANT_WRITE", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING)

    def _cleanup_failed(self, path_template: str, canary_id, target: str) -> Finding:
        location = Location(endpoint=path_template)
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CLEANUP_FAILED", location),
            module="idor", rule_id="IDOR_CLEANUP_FAILED",
            title="Cleanup della canary IDOR non confermato (rimozione manuale)",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence=(f"canary id={canary_id} su {path_template}: DELETE di cleanup non "
                      f"confermato. Rimozione manuale: DELETE {path_template} (id={canary_id})."),
            description=("Il probe WRITE ha creato una risorsa-canary ma il cleanup automatico "
                         f"NON è confermato. Resta una canary da rimuovere a mano (id={canary_id}, "
                         f"marker '{self._CANARY_MARKER}'). (§11.2)"),
            remediation_ref="IDOR_CROSS_TENANT_WRITE", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING)

    def _write_skipped_no_canary(self, target: str) -> Finding:
        location = Location(endpoint="idor-write")
        return Finding(
            finding_id=_finding_id("idor", "IDOR_WRITE_SKIPPED_NO_CANARY", location),
            module="idor", rule_id="IDOR_WRITE_SKIPPED_NO_CANARY",
            title="Probe WRITE IDOR saltato: nessun endpoint create dichiarato",
            severity=Severity.INFO, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence="nessun endpoint kind='create' (+ 'delete') dichiarato in [auth]",
            description=("Il probe WRITE cross-tenant è stato SALTATO: senza un endpoint "
                         "'create' (per la canary) e 'delete', non si testa la scrittura alla "
                         "cieca (cleanup-safe §11.2). Verifica INCOMPLETA, dichiarata (§4.7)."),
            intrusion_used=IntrusionLevel.READ_ONLY)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_idor.py -q`
Expected: PASS (tutti i test idor, inclusi i 5 nuovi del WRITE).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/idor/module.py tests/test_idor.py
git commit -m "feat(idor): WRITE cross-tenant canary usa-e-getta + cleanup garantito (M4.1)"
```

---

## Task 8: Oracolo §15 (endpoint pubblici) READ→soppresso + P8 esplicito sul WRITE

**Files:**
- Modify: `bastione/modules/idor/module.py` (assicura soppressione READ su public; conferma P8)
- Test: `tests/test_idor.py` (estende)

**Interfaces:**
- Consumes: `_is_public` / `_isolation_posture` (Task 6).
- Produces: comportamento di soppressione verificato + asserzione P8 forte.

**Nota:** la soppressione READ su `public_endpoints` è già implementata in `_read_probe` (Task 6, ramo `_is_public`). Questo task la **blocca con un test** e aggiunge l'asserzione P8 sentinella (nessun dato di A, nessun token in alcun campo).

- [ ] **Step 1: Write the failing test**

```python
# append a tests/test_idor.py
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
```

- [ ] **Step 2: Run test to verify it fails (o passa subito la soppressione)**

Run: `python -m pytest tests/test_idor.py -q`
Expected: la soppressione (`test_public_endpoint_read_is_suppressed`) potrebbe già passare (logica in Task 6); il test P8 deve passare. Se la soppressione fallisce, correggi `_is_public`/il ramo in `_read_probe`.

- [ ] **Step 3: Implementazione (se serve)**

Se il test di soppressione fallisce, verifica che in `_read_probe` il ramo `_is_public(path, public)` venga valutato **prima** del replay come B/anon e produca SOLO `_isolation_posture(..., suppressed=True)` senza alcun finding. (Codice già in Task 6 — qui è verifica.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_idor.py -q`
Expected: PASS (tutti i test idor).

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/idor/module.py tests/test_idor.py
git commit -m "test(idor): soppressione §15 endpoint pubblici + P8 token-no-leak (M4.1)"
```

---

## Task 9: Wiring CLI — doctor / list-modules mostrano idor

**Files:**
- Modify: `bastione/cli.py` (se serve) — verifica che `list-modules` mostri `idor=mutating` e che `doctor` resti onesto (idor non richiede tool esterni)
- Test: `tests/test_cli.py` (estende) o `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `_ensure_modules_loaded` (già include idor, Task 5), `REGISTRY`.

- [ ] **Step 1: Write the failing test**

```python
# append a tests/test_cli.py (o un nuovo tests/test_idor_wiring.py)
from typer.testing import CliRunner
from bastione.cli import app

runner = CliRunner()


def test_list_modules_shows_idor_mutating():
    result = runner.invoke(app, ["list-modules"])
    assert result.exit_code == 0
    assert "idor" in result.stdout
    assert "mutating" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `python -m pytest tests/test_cli.py -k idor -q`
Expected: PASS se Task 5 ha già wired idor in `_ensure_modules_loaded` (list-modules lo elenca automaticamente leggendo REGISTRY). Se FAIL (idor assente), verifica l'import in `_ensure_modules_loaded`.

- [ ] **Step 3: Implementazione (se serve)**

idor non dipende da tool esterni → **non** va aggiunto a `_EXTERNAL_TOOLS` in `doctor`. `list-modules` lo mostra già leggendo `REGISTRY` (max_intrusion=mutating). Nessuna modifica a `cli.py` attesa oltre a ciò che è già in Task 5. Se il test fallisce, l'unica fix è garantire l'import in `_ensure_modules_loaded`.

- [ ] **Step 4: Run the FULL suite (ground-truth orchestratore)**

Run: `python -m pytest -q`
Expected: PASS — tutti i test preesistenti (859) + i nuovi M4 verdi, nessuna regressione.

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/cli.py tests/test_cli.py
git commit -m "feat(cli): idor in list-modules; full suite verde (M4.0+M4.1)"
```

---

## Self-Review (eseguita)

**1. Spec coverage** — ogni sezione della spec ha un task:
- §3.1 auth/session → Task 3 ✓ · §3.2 api_surface → Task 4 ✓ · §3.4 config/models → Task 1,2 + Fingerprint Task 4 ✓ · §3.5 READ probe → Task 6 ✓ · §3.5 WRITE canary+cleanup → Task 7 ✓ · §4 nuovi rule_id → Task 5–7 ✓ · oracolo §15 → Task 8 ✓ · gate/guardrail → Task 5 (self-gate/SKIPPED), Task 7 (authorize MUTATING gate-first) ✓ · P8 → Task 3,6,8 ✓ · testabilità offline app sintetiche → Task 6,7 ✓ · wiring → Task 5,9 ✓.
- **Gap colmato:** `Fingerprint.discovered_api_paths` non era esplicito nella spec → aggiunto in Task 4 (mirroring `discovered_tables`) per permettere a `build_api_surface` di avere l'assist dal bundle.
- **Fuori scope confermato:** Supabase Auth diretto, browser headless auto-crawl, M4.2/4.3/4.4 — non in questo piano (coerente con spec §1).

**2. Placeholder scan** — nessun "TBD/TODO/handle edge cases"; ogni step ha codice reale o comando concreto.

**3. Type consistency** — `acquire_session(account, *, _http=None)`, `_http_request(method, url, *, json, headers)`, `_finding_id(module, rule_id, location)`, `AuthSession(account_label, headers, cookies, acquired_ok)`, `ApiSurface(endpoints, extracted_paths)`, `IdorModule.run(ctx)` coerenti tra i task. I rule_id (`IDOR_SKIPPED`, `IDOR_CROSS_TENANT_READ`, `IDOR_CROSS_TENANT_WRITE`, `IDOR_CLEANUP_FAILED`, `IDOR_WRITE_SKIPPED_NO_CANARY`) coerenti tra implementazione e test.

**Domande aperte (non bloccanti, dalla spec §9):** forma esatta del confronto READ (qui: 2xx + corpo non-vuoto per l'ID di A); cap sul numero di ID campionati per endpoint (qui: tutti gli `id` della list — in un hardening futuro, cap configurabile); path_template multi-parametro (qui: solo `{id}` singolo). Da rifinire in implementazione se emergono in blind-review.

---

*Allineato a `BASTIONE-BLUEPRINT-v2.md` (§5/§6/§7/§8/§11.2/§14/§15/§16/§17/§23/§25/§29), `BASTIONE-WORKFLOWS.md`, e alla spec `docs/superpowers/specs/2026-06-20-bastione-m4-authenticated-idor-design.md`.*
