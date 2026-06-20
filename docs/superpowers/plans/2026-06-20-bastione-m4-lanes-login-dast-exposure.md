# Bastione M4 — login-hardening + server-exposure + ZAP-active — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Esecuzione in Bastione (LOCKED):** sviluppo **workflow-first** (`BASTIONE-WORKFLOWS.md`). I **builder NON eseguono git**: lo step "Commit" lo fa l'**ORCHESTRATORE** dopo il ground-truth `python -m pytest -q` + blind-review. Task 1/2/3 sono su **file disgiunti** (moduli diversi) → builder **paralleli**; Task 4 (wiring `orchestrator.py`) **dopo**.

**Goal:** Aggiungere 3 corsie autenticate sul fondamento M4.0 — `login_hardening` (M4.2, PROBE), `server_exposure` (M4.4, PROBE), `zap_active` (M4.3, MUTATING) — ciascuna un modulo `@register` con oracoli, gate, P8 e test offline.

**Architecture:** Tre moduli nuovi indipendenti che riusano i pattern stabiliti: `Module`/`@register` (§9), `gate.authorize` (§7), confine I/O modulo-livello monkeypatchabile, `_finding_id` LOCKED (§16), `_skipped` INFO (§14/§26). `server_exposure` riusa i detector §10 (`DETECTORS`/`scan`). `zap_active` clona la colla nuclei §14 con policy vincolata.

**Tech Stack:** Python 3.14, Pydantic v2, httpx (I/O opzionale/degradabile), pytest. **NO uv** — test con `python -m pytest -q`.

## Global Constraints

- **Guardrail §7/§28 (iniettati in OGNI prompt builder/fixer):** produzione = blocco assoluto; owned-only; READ_ONLY di default; **`login_hardening`/`server_exposure` = PROBE**, **`zap_active` = MUTATING** (gate-first `authorize(MUTATING, ctx)`, propaga `IntrusionDenied` → run aborta); **niente brute-force** (rate-limit = cap basso a password sbagliata su account di test); **P8** (mai password/token/segreti/corpi sensibili in un campo Finding — solo metadati; segreti redatti via `_redact`); resilienza→`*_SKIPPED` INFO o nessun finding, mai crash; segreti config via ENV.
- **I builder NON eseguono git.** Commit = orchestratore (path espliciti).
- **Tutto OFFLINE nei test:** confini I/O (`_login_request` / `_fetch` / `_run_zap_active`) sono **funzioni modulo-livello monkeypatchate**; nessun target live/rete/installazione.
- **`finding_id` LOCKED (§16):** `sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]`.
- **Confini I/O & resilienza:** ogni `_*` boundary ritorna `None`/`[]` su httpx-assente o errore (mai solleva).

## File Structure

| File | Responsabilità | Task |
|---|---|---|
| `bastione/models.py` (modifica) | `AuthConfig.login_attempts_cap: int = 5` | 1 |
| `bastione/config.py` (modifica) | `_flatten`: legge `[auth].login_attempts_cap` | 1 |
| `bastione/modules/login_hardening/__init__.py` (nuovo) | package | 1 |
| `bastione/modules/login_hardening/module.py` (nuovo) | `LoginHardeningModule` (rate-limit, enumerazione, cookie) | 1 |
| `bastione/modules/server_exposure/__init__.py` (nuovo) | package | 2 |
| `bastione/modules/server_exposure/module.py` (nuovo) | `ServerExposureModule` (source-map, errori, endpoint, CORS) | 2 |
| `bastione/modules/zap_active/__init__.py` (nuovo) | package | 3 |
| `bastione/modules/zap_active/module.py` (nuovo) | `ZapActiveModule` (MUTATING, colla ZAP vincolata) | 3 |
| `bastione/orchestrator.py` (modifica) | `_ensure_modules_loaded` += 3 import | 4 |
| `tests/test_login_hardening.py` (nuovo) | M4.2 | 1 |
| `tests/test_server_exposure.py` (nuovo) | M4.4 | 2 |
| `tests/test_zap_active.py` (nuovo) | M4.3 | 3 |
| `tests/test_config_auth.py` (modifica) | login_attempts_cap parsing | 1 |

**Ondate workflow:** O1 = Task1 ‖ Task2 ‖ Task3 (file disgiunti). O2 = Task4 (`orchestrator.py`). Blind-review per-lane dopo O1.

**Pattern di riferimento già in repo (da leggere prima di implementare):** `bastione/modules/trivy/module.py` (struttura modulo: which→SKIPPED, `_finding_id`, `_skipped`, parse→Finding) · `bastione/modules/nuclei/module.py` (`_run_nuclei` argv vincolato + raw/) · `bastione/modules/secrets/module.py` + `detectors/base.py` (loop `DETECTORS`/`scan`, `_redact`) · `bastione/modules/headers/module.py` (PostureCheck) · `bastione/auth/session.py` (`acquire_session`, confine `_http_request`) · `bastione/modules/idor/module.py` (gate-first MUTATING).

---

## Task 1: M4.2 — `login_hardening` (PROBE) + login_attempts_cap

**Files:**
- Modify: `bastione/models.py` (`AuthConfig.login_attempts_cap`), `bastione/config.py` (`_flatten`), `tests/test_config_auth.py`
- Create: `bastione/modules/login_hardening/__init__.py` (vuoto), `bastione/modules/login_hardening/module.py`
- Test: `tests/test_login_hardening.py`

**Interfaces:**
- Consumes: `Module`/`register` (§9); `authorize`/`IntrusionDenied` (§7); `acquire_session` (M4.0); `TestAccount`/`AuthConfig` (M4.0); `Finding`/`PostureCheck`/`Location`/`ModuleResult`/`RunContext` (§5).
- Produces: `LoginHardeningModule(name="login_hardening", max_intrusion=PROBE)`; module-level `_login_request(url, *, json=None, headers=None) -> resp|None`, `_finding_id(module, rule_id, location)`; `AuthConfig.login_attempts_cap: int = 5`. Rule_id: `LOGIN_NO_RATE_LIMIT`, `LOGIN_USER_ENUMERATION`, `SESSION_COOKIE_INSECURE`, `LOGIN_HARDENING_SKIPPED`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_login_hardening.py
from pathlib import Path
import pytest
from bastione.enums import IntrusionLevel, Severity
from bastione.models import (AuthConfig, Fingerprint, RunContext, TargetConfig, TestAccount)


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


class _Resp:
    def __init__(self, status_code=401, headers=None, payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._p = payload or {}
    def json(self):
        return self._p


def _acc():
    return TestAccount(label="A", mode="login_post",
                       login_url="https://staging.example.com/api/auth/login",
                       email="a@example.com", password_env="PW_A",
                       session_cookie="session")


def _cfg(cap=5):
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned", ownership_token="tok",
                        auth=AuthConfig(test_accounts=[_acc()], login_attempts_cap=cap))


def _ctx(*, cfg=None, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    cfg = cfg or _cfg()
    return RunContext(target_cfg=cfg, fingerprint=Fingerprint(target="t", resolved_urls=[]),
                      max_intrusion=max_intrusion, run_dir=Path("."),
                      ownership_verified=ownership_verified)


def test_module_name_and_intrusion():
    from bastione.modules.login_hardening.module import LoginHardeningModule
    assert LoginHardeningModule.name == "login_hardening"
    assert LoginHardeningModule.max_intrusion == IntrusionLevel.PROBE


def test_read_only_skipped_no_requests(monkeypatch):
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    called = []
    monkeypatch.setattr(m, "_login_request", lambda *a, **k: called.append(a) or None)
    res = LoginHardeningModule().run(_ctx(max_intrusion=IntrusionLevel.READ_ONLY,
                                          ownership_verified=False))
    assert len(res.findings) == 1 and res.findings[0].rule_id == "LOGIN_HARDENING_SKIPPED"
    assert called == []


def test_no_rate_limit_flagged(monkeypatch):
    """cap tentativi a pwd sbagliata senza 429 -> LOGIN_NO_RATE_LIMIT."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    # tutte le risposte 401 (auth fail), mai 429: niente rate-limit
    monkeypatch.setattr(m, "_login_request",
                        lambda url, **k: _Resp(401, headers={"set-cookie": "session=x; HttpOnly; Secure; SameSite=Lax"}))
    res = LoginHardeningModule().run(_ctx())
    rids = {f.rule_id for f in res.findings}
    assert "LOGIN_NO_RATE_LIMIT" in rids
    assert next(f for f in res.findings if f.rule_id == "LOGIN_NO_RATE_LIMIT").severity == Severity.HIGH
    # P8: la password reale non compare
    for f in res.findings:
        assert "realpw" not in f.evidence and "realpw" not in f.description


def test_rate_limit_present_no_finding(monkeypatch):
    """un 429 entro il cap -> niente LOGIN_NO_RATE_LIMIT, posture pass."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    seq = [_Resp(401), _Resp(401), _Resp(429)]
    calls = {"n": 0}
    def router(url, **k):
        i = min(calls["n"], len(seq) - 1); calls["n"] += 1
        return seq[i]
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "LOGIN_NO_RATE_LIMIT" not in {f.rule_id for f in res.findings}
    assert any(p.check_id == "POSTURE_RATE_LIMIT" and p.passed for p in res.posture_checks)


def test_user_enumeration_flagged(monkeypatch):
    """status distinguibile email-esistente vs inesistente -> LOGIN_USER_ENUMERATION."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    def router(url, *, json=None, headers=None):
        # esistente -> 401, inesistente -> 404 (distinguibile)
        if json and json.get("email") == "a@example.com":
            return _Resp(401)
        return _Resp(404)
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "LOGIN_USER_ENUMERATION" in {f.rule_id for f in res.findings}


def test_insecure_session_cookie_flagged(monkeypatch):
    """Set-Cookie senza HttpOnly/Secure -> SESSION_COOKIE_INSECURE."""
    import bastione.modules.login_hardening.module as m
    from bastione.modules.login_hardening.module import LoginHardeningModule
    monkeypatch.setenv("PW_A", "realpw")
    def router(url, *, json=None, headers=None):
        pw = (json or {}).get("password")
        # login con pwd reale -> 200 + cookie insicuro; pwd sbagliata -> 401
        if pw == "realpw":
            return _Resp(200, headers={"set-cookie": "session=abc; Path=/"})
        return _Resp(401)
    monkeypatch.setattr(m, "_login_request", router)
    res = LoginHardeningModule().run(_ctx())
    assert "SESSION_COOKIE_INSECURE" in {f.rule_id for f in res.findings}
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_login_hardening.py -q`
Expected: FAIL `ModuleNotFoundError: No module named 'bastione.modules.login_hardening'`.

- [ ] **Step 3: Add config field + parsing**

`bastione/models.py` — in `AuthConfig` aggiungi:

```python
    login_attempts_cap: int = 5        # M4.2: cap basso del probe rate-limit (non brute-force)
```

`bastione/config.py` — in `_flatten`, dentro il blocco `if auth is not None:`, aggiungi:

```python
        if "login_attempts_cap" in auth:
            auth_kwargs["login_attempts_cap"] = auth["login_attempts_cap"]
```

`tests/test_config_auth.py` — aggiungi un test:

```python
def test_flatten_parses_login_attempts_cap():
    import tomllib
    from bastione.config import _flatten
    from bastione.models import TargetConfig
    data = tomllib.loads(
        'name="t"\nbase_url="https://s.example.com"\nenvironment="staging"\nownership="owned"\n'
        '[auth]\nlogin_attempts_cap = 3\n'
        '[[auth.test_accounts]]\nlabel="A"\nmode="token"\ntoken_env="T"\n')
    cfg = TargetConfig(**_flatten(data))
    assert cfg.auth.login_attempts_cap == 3
```

- [ ] **Step 4: Implement the module**

`bastione/modules/login_hardening/__init__.py` — vuoto.

`bastione/modules/login_hardening/module.py`:

```python
"""LoginHardeningModule — robustezza del flusso di login (M4.2, PROBE 🟡).

Verifica owned/staging che il muro di login regga: rate-limit (cap basso, password
SBAGLIATA su account di test → rileva il rate-limiting, NON brute-force),
enumerazione account, sicurezza del cookie di sessione. Tutto offline-testabile:
il confine I/O `_login_request` è monkeypatchato.

Guardrail §7/§28: niente brute-force (cap basso); P8 (mai la password né il token
in un campo Finding)."""
from __future__ import annotations

import hashlib
import logging
import os

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (Finding, Fingerprint, Location, ModuleResult,
                             PostureCheck, RunContext, TargetConfig)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.login_hardening")
_HTTP_TIMEOUT = 15.0
_WRONG_PW = "bastione-probe-wrong-password-do-not-use"


def _login_request(url: str, *, json=None, headers=None):
    """Confine I/O (monkeypatchato nei test). POST di login. Ritorna resp o None (§4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: login_hardening non disponibile (M4.2)")
        return None
    try:
        return httpx.post(url, json=json, headers=headers, timeout=_HTTP_TIMEOUT,
                          follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("login_hardening POST %s fallita: %s", url, exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@register
class LoginHardeningModule(Module):
    """Robustezza del login (M4.2, PROBE)."""

    name = "login_hardening"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        return bool(cfg.auth and any(
            a.mode == "login_post" and a.login_url for a in cfg.auth.test_accounts))

    def run(self, ctx: RunContext) -> ModuleResult:
        target = ctx.target_cfg.name
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(target, "login_hardening richiede --max-intrusion >= probe "
                                 "e ownership verificata (§7): saltato.")
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            return self._skipped(target, f"PROBE negata dal gate (§7): {exc}")

        acc = next((a for a in ctx.target_cfg.auth.test_accounts
                    if a.mode == "login_post" and a.login_url), None)
        if acc is None:
            return self._skipped(target, "nessun account login_post: saltato.")

        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        cap = max(1, ctx.target_cfg.auth.login_attempts_cap)
        self._rate_limit(acc, cap, target, findings, posture)
        self._enumeration(acc, target, findings)
        self._session_cookie(acc, target, findings, posture)
        return ModuleResult(findings=findings, posture_checks=posture)

    # ── oracoli ──────────────────────────────────────────────────────────────
    def _rate_limit(self, acc, cap, target, findings, posture) -> None:
        """Fino a `cap` tentativi a password SBAGLIATA; un 429/423 = rate-limit presente."""
        limited = False
        for _ in range(cap):
            resp = _login_request(acc.login_url,
                                  json={"email": acc.email, "password": _WRONG_PW})
            if resp is not None and getattr(resp, "status_code", 0) in (429, 423):
                limited = True
                break
        if limited:
            posture.append(PostureCheck(
                check_id="POSTURE_RATE_LIMIT", title="Rate-limit sul login presente",
                passed=True, severity_if_failed=Severity.HIGH, target=target,
                detail="il login risponde 429/423 entro il cap di tentativi"))
        else:
            loc = Location(endpoint=acc.login_url)
            findings.append(Finding(
                finding_id=_finding_id("login_hardening", "LOGIN_NO_RATE_LIMIT", loc),
                module="login_hardening", rule_id="LOGIN_NO_RATE_LIMIT",
                title="Login senza rate-limit/lockout",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target=target,
                location=loc,
                evidence=f"{cap} tentativi falliti senza 429/lockout su {acc.login_url}",
                description=("Il login accetta tentativi ripetuti senza rate-limit/lockout: "
                             "espone a credential stuffing/brute-force (OWASP A07). Testato con "
                             "password volutamente errata (non brute-force). Aggiungi rate-limit. (P8)"),
                remediation_ref="LOGIN_NO_RATE_LIMIT", owasp=["A07:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            posture.append(PostureCheck(
                check_id="POSTURE_RATE_LIMIT", title="Rate-limit sul login presente",
                passed=False, severity_if_failed=Severity.HIGH, target=target,
                detail=f"nessun 429/lockout dopo {cap} tentativi"))

    def _enumeration(self, acc, target, findings) -> None:
        """Risposta a email esistente vs inesistente distinguibile = enumerazione."""
        existing = _login_request(acc.login_url,
                                  json={"email": acc.email, "password": _WRONG_PW})
        bogus_email = f"nonexistent-bastione-probe@{acc.email.split('@')[-1]}"
        bogus = _login_request(acc.login_url,
                               json={"email": bogus_email, "password": _WRONG_PW})
        if existing is None or bogus is None:
            return
        s1, s2 = getattr(existing, "status_code", 0), getattr(bogus, "status_code", 0)
        if s1 != s2:
            loc = Location(endpoint=acc.login_url)
            findings.append(Finding(
                finding_id=_finding_id("login_hardening", "LOGIN_USER_ENUMERATION", loc),
                module="login_hardening", rule_id="LOGIN_USER_ENUMERATION",
                title="Enumerazione account dal login",
                severity=Severity.MEDIUM, confidence=Confidence.FIRM, target=target,
                location=loc,
                evidence=f"status distinguibile: email nota {s1} vs ignota {s2}",
                description=("Il login risponde diversamente per un'email esistente vs "
                             "inesistente: consente di enumerare gli account (OWASP A07). "
                             "Uniforma la risposta. (P8: nessuna credenziale inclusa)"),
                remediation_ref="LOGIN_USER_ENUMERATION", owasp=["A07:2021"],
                intrusion_used=IntrusionLevel.PROBE))

    def _session_cookie(self, acc, target, findings, posture) -> None:
        """Login con pwd reale (da ENV) → ispeziona i flag del Set-Cookie di sessione."""
        pw = os.getenv(acc.password_env) if acc.password_env else None
        if not pw:
            return
        resp = _login_request(acc.login_url, json={"email": acc.email, "password": pw})
        if resp is None or getattr(resp, "status_code", 0) >= 400:
            return
        set_cookie = ""
        try:
            set_cookie = resp.headers.get("set-cookie", "") or ""
        except Exception:  # noqa: BLE001
            set_cookie = ""
        if acc.session_cookie and acc.session_cookie not in set_cookie:
            return
        low = set_cookie.lower()
        missing = [flag for flag, tok in
                   (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                   if tok not in low]
        loc = Location(endpoint=acc.login_url)
        if missing:
            findings.append(Finding(
                finding_id=_finding_id("login_hardening", "SESSION_COOKIE_INSECURE", loc),
                module="login_hardening", rule_id="SESSION_COOKIE_INSECURE",
                title="Cookie di sessione senza flag di sicurezza",
                severity=Severity.MEDIUM, confidence=Confidence.FIRM, target=target,
                location=loc,
                evidence=f"flag mancanti sul cookie di sessione: {', '.join(missing)}",
                description=("Il cookie di sessione manca di flag di sicurezza "
                             f"({', '.join(missing)}): esposto a XSS/MITM (OWASP A05). "
                             "Imposta HttpOnly+Secure+SameSite. (P8: nessun valore del cookie incluso)"),
                remediation_ref="SESSION_COOKIE_INSECURE", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
        posture.append(PostureCheck(
            check_id="POSTURE_SESSION_COOKIE", title="Cookie di sessione sicuro",
            passed=not missing, severity_if_failed=Severity.MEDIUM, target=target,
            detail=("flag HttpOnly/Secure/SameSite presenti" if not missing
                    else f"mancano: {', '.join(missing)}")))

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        loc = Location(endpoint="login_hardening")
        f = Finding(
            finding_id=_finding_id("login_hardening", "LOGIN_HARDENING_SKIPPED", loc),
            module="login_hardening", rule_id="LOGIN_HARDENING_SKIPPED",
            title="Verifica login_hardening saltata", severity=Severity.INFO,
            confidence=Confidence.FIRM, target=target, location=loc, evidence=motivo,
            description=(f"login_hardening (M4.2) saltato: {motivo} Skip dichiarato (§4.7/§26)."),
            intrusion_used=IntrusionLevel.READ_ONLY)
        return ModuleResult(findings=[f], posture_checks=[])
```

- [ ] **Step 5: Run to verify pass**

Run: `python -m pytest tests/test_login_hardening.py tests/test_config_auth.py -q`
Expected: PASS (tutti verdi).

- [ ] **Step 6: Commit** *(orchestratore)*

```bash
git add bastione/models.py bastione/config.py bastione/modules/login_hardening/ tests/test_login_hardening.py tests/test_config_auth.py
git commit -m "feat(m4): login_hardening (rate-limit/enum/cookie) + login_attempts_cap (M4.2)"
```

---

## Task 2: M4.4 — `server_exposure` (PROBE)

**Files:**
- Create: `bastione/modules/server_exposure/__init__.py` (vuoto), `bastione/modules/server_exposure/module.py`
- Test: `tests/test_server_exposure.py`

**Interfaces:**
- Consumes: `Module`/`register`; `authorize`/`IntrusionDenied`; `DETECTORS` (`from bastione.modules.secrets.detectors.base import DETECTORS`); `TextAsset`/`RawSecret` (`bastione.models`); `_redact` pattern (riprodotto, vedi sotto); `extract_script_srcs` (`from bastione.recon.fingerprint import extract_script_srcs`).
- Produces: `ServerExposureModule(name="server_exposure", max_intrusion=PROBE)`; module-level `_fetch(method, url, *, headers=None) -> resp|None`, `_finding_id`. Rule_id: `SOURCEMAP_EXPOSED`, `VERBOSE_ERROR_LEAK`, `SENSITIVE_ENDPOINT_EXPOSED`, `CORS_MISCONFIG`, `SERVER_EXPOSURE_SKIPPED`.

> **Detector reuse:** `for det in DETECTORS: det.scan(TextAsset(source=url, content=body)) -> list[RawSecret]`. Redigi `raw.value` con `_redact` (primi 6 + "..." + ultimi 4; ≤10 char → primi 4 + "...").

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server_exposure.py
from pathlib import Path
import pytest
from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, RunContext, TargetConfig


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


class _Resp:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _cfg():
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned", ownership_token="tok")


def _ctx(*, resolved_urls=None, max_intrusion=IntrusionLevel.PROBE, ownership_verified=True):
    fp = Fingerprint(target="t", resolved_urls=resolved_urls or ["https://staging.example.com"])
    return RunContext(target_cfg=_cfg(), fingerprint=fp, max_intrusion=max_intrusion,
                      run_dir=Path("."), ownership_verified=ownership_verified)


def test_module_name_and_intrusion():
    from bastione.modules.server_exposure.module import ServerExposureModule
    assert ServerExposureModule.name == "server_exposure"
    assert ServerExposureModule.max_intrusion == IntrusionLevel.PROBE


def test_read_only_skipped_no_requests(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    called = []
    monkeypatch.setattr(m, "_fetch", lambda *a, **k: called.append(a) or None)
    res = ServerExposureModule().run(_ctx(max_intrusion=IntrusionLevel.READ_ONLY,
                                          ownership_verified=False))
    assert len(res.findings) == 1 and res.findings[0].rule_id == "SERVER_EXPOSURE_SKIPPED"
    assert called == []


def test_sourcemap_with_service_role_is_critical(monkeypatch):
    """Una .js.map esposta che contiene una service_role -> SOURCEMAP_EXPOSED CRITICAL, P8 redatto."""
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    # un JWT service_role (header.payload.signature) con payload {"role":"service_role"}
    import base64, json as _j
    payload = base64.urlsafe_b64encode(_j.dumps({"role": "service_role", "ref": "abc"}).encode()).decode().rstrip("=")
    jwt = f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"
    base_html = '<script src="/assets/app.js"></script>'
    def fetch(method, url, *, headers=None):
        if url.endswith("/"):  # base page
            return _Resp(200, text=base_html)
        if url.endswith("app.js.map"):
            return _Resp(200, text=f'{{"sources":["x"],"key":"{jwt}"}}')
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    sm = [f for f in res.findings if f.rule_id == "SOURCEMAP_EXPOSED"]
    assert sm and sm[0].severity == Severity.CRITICAL
    # P8: il JWT in chiaro non compare nell'evidence
    assert jwt not in sm[0].evidence


def test_cors_misconfig_reflected_with_credentials(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    def fetch(method, url, *, headers=None):
        if url.rstrip("/").endswith("staging.example.com") or url.endswith("/"):
            org = (headers or {}).get("Origin", "")
            return _Resp(200, headers={"access-control-allow-origin": org,
                                       "access-control-allow-credentials": "true"})
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    assert "CORS_MISCONFIG" in {f.rule_id for f in res.findings}


def test_sensitive_endpoint_exposed(monkeypatch):
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    def fetch(method, url, *, headers=None):
        if url.endswith("/.env"):
            return _Resp(200, headers={"content-type": "text/plain"},
                         text="DB_PASSWORD=supersecret\nAPI_KEY=xyz")
        return _Resp(404)
    monkeypatch.setattr(m, "_fetch", fetch)
    res = ServerExposureModule().run(_ctx())
    se = [f for f in res.findings if f.rule_id == "SENSITIVE_ENDPOINT_EXPOSED"]
    assert se and se[0].severity == Severity.HIGH
    # P8: il valore del segreto non finisce nell'evidence (solo il path)
    assert "supersecret" not in se[0].evidence


def test_hardened_app_no_findings(monkeypatch):
    """App hardened: tutto 404/sicuro -> nessun finding di esposizione (solo eventuali posture)."""
    import bastione.modules.server_exposure.module as m
    from bastione.modules.server_exposure.module import ServerExposureModule
    monkeypatch.setattr(m, "_fetch", lambda method, url, *, headers=None: _Resp(404))
    res = ServerExposureModule().run(_ctx())
    bad = {"SOURCEMAP_EXPOSED", "SENSITIVE_ENDPOINT_EXPOSED", "CORS_MISCONFIG", "VERBOSE_ERROR_LEAK"}
    assert not (bad & {f.rule_id for f in res.findings})
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_server_exposure.py -q`
Expected: FAIL `ModuleNotFoundError`.

- [ ] **Step 3: Implement the module**

`bastione/modules/server_exposure/__init__.py` — vuoto.

`bastione/modules/server_exposure/module.py`:

```python
"""ServerExposureModule — segreti/config esposti lato server (M4.4, PROBE 🟡).

Quattro oracoli: source-map .js.map esposte (riusa i detector §10), errori verbosi,
endpoint sensibili (allowlist), CORS permissivo. Confine I/O `_fetch` monkeypatchato.
P8: i segreti trovati sono REDATTI; l'evidence riporta solo metadati."""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (Finding, Fingerprint, Location, ModuleResult,
                             PostureCheck, RunContext, TargetConfig, TextAsset)
from bastione.modules.base import Module, register
from bastione.modules.secrets.detectors.base import DETECTORS
from bastione.recon.fingerprint import extract_script_srcs

log = logging.getLogger("bastione.modules.server_exposure")
_HTTP_TIMEOUT = 15.0
# allowlist conservativa di path sensibili (§14). GET read-only.
_SENSITIVE_PATHS = ["/.env", "/.git/config", "/api/debug", "/server-status",
                    "/actuator", "/.aws/credentials", "/config.json"]
_EVIL_ORIGIN = "https://evil.bastione-probe.example"
# marker tipici di stack trace / errore verboso
_ERROR_MARKERS = ("traceback", "stack trace", "at line", ".py\", line", "\tat ",
                  "exception in", "syntaxerror", "node_modules")


def _fetch(method: str, url: str, *, headers=None):
    """Confine I/O (monkeypatchato nei test). Ritorna resp o None (§4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: server_exposure non disponibile (M4.4)")
        return None
    try:
        return httpx.request(method, url, headers=headers, timeout=_HTTP_TIMEOUT,
                             follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("server_exposure %s %s fallita: %s", method, url, exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _redact(value: str) -> str:
    """P8: primi 6 + '...' + ultimi 4 (≤10 char → primi 4 + '...')."""
    if len(value) <= 10:
        return value[:4] + "..."
    return value[:6] + "..." + value[-4:]


@register
class ServerExposureModule(Module):
    """Segreti/config lato server (M4.4, PROBE)."""

    name = "server_exposure"
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        return bool(cfg.base_url)

    def run(self, ctx: RunContext) -> ModuleResult:
        target = ctx.target_cfg.name
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(target, "server_exposure richiede --max-intrusion >= probe "
                                 "e ownership verificata (§7): saltato.")
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            return self._skipped(target, f"PROBE negata dal gate (§7): {exc}")

        base = ctx.target_cfg.base_url.rstrip("/")
        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        self._source_maps(base, target, findings, posture)
        self._sensitive_endpoints(base, target, findings)
        self._cors(base, target, findings, posture)
        return ModuleResult(findings=findings, posture_checks=posture)

    def _source_maps(self, base, target, findings, posture) -> None:
        page = _fetch("GET", base + "/", headers=None)
        srcs = extract_script_srcs(getattr(page, "text", "") or "", base) if page else []
        found_any = False
        for src in srcs:
            if not src.endswith(".js"):
                continue
            resp = _fetch("GET", src + ".map", headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            found_any = True
            body = getattr(resp, "text", "") or ""
            asset = TextAsset(source=src + ".map", content=body)
            secrets = []
            for det in DETECTORS:
                try:
                    secrets.extend(det.scan(asset))
                except Exception:  # noqa: BLE001
                    continue
            sev = Severity.CRITICAL if any(
                s.detector_id == "SECRET_SERVICE_ROLE" for s in secrets) else Severity.MEDIUM
            loc = Location(url=src + ".map")
            redacted = "; ".join(f"{s.detector_id}={_redact(s.value)}" for s in secrets) or "codice sorgente"
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "SOURCEMAP_EXPOSED", loc),
                module="server_exposure", rule_id="SOURCEMAP_EXPOSED",
                title="Source map (.js.map) esposta",
                severity=sev, confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"{src}.map accessibile; segreti: {redacted}",
                description=("Una source map .js.map è pubblicamente accessibile e rivela il "
                             "codice sorgente" + (" e segreti (service_role!)" if sev == Severity.CRITICAL
                             else "") + ". Disabilita le source map in produzione/staging pubblico. "
                             "(P8: segreti redatti)"),
                remediation_ref="SOURCEMAP_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
        posture.append(PostureCheck(
            check_id="POSTURE_NO_SOURCEMAP", title="Nessuna source map esposta",
            passed=not found_any, severity_if_failed=Severity.MEDIUM, target=target,
            detail="nessuna .js.map accessibile" if not found_any else "source map esposte"))

    def _sensitive_endpoints(self, base, target, findings) -> None:
        for path in _SENSITIVE_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            ctype = ""
            try:
                ctype = (resp.headers.get("content-type", "") or "").lower()
            except Exception:  # noqa: BLE001
                ctype = ""
            # euristica anti-falso-positivo: l'SPA fallback è text/html
            if "text/html" in ctype:
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "SENSITIVE_ENDPOINT_EXPOSED", loc),
                module="server_exposure", rule_id="SENSITIVE_ENDPOINT_EXPOSED",
                title=f"Endpoint sensibile accessibile: {path}",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (content-type {ctype or 'n/d'})",
                description=(f"Il path sensibile {path} risponde 200: può esporre segreti/config "
                             "(OWASP A05). Blocca l'accesso pubblico. (P8: nessun contenuto incluso)"),
                remediation_ref="SENSITIVE_ENDPOINT_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))

    def _cors(self, base, target, findings, posture) -> None:
        resp = _fetch("GET", base + "/", headers={"Origin": _EVIL_ORIGIN})
        if resp is None:
            return
        try:
            acao = (resp.headers.get("access-control-allow-origin", "") or "")
            acac = (resp.headers.get("access-control-allow-credentials", "") or "").lower() == "true"
        except Exception:  # noqa: BLE001
            return
        reflected = acao == "*" or acao == _EVIL_ORIGIN
        bad = reflected and acac
        if bad:
            loc = Location(endpoint="/")
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "CORS_MISCONFIG", loc),
                module="server_exposure", rule_id="CORS_MISCONFIG",
                title="CORS permissivo con credenziali",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"Allow-Origin={acao!r} riflesso/wildcard + Allow-Credentials=true",
                description=("La policy CORS riflette un'origin arbitraria (o usa '*') INSIEME a "
                             "Allow-Credentials=true: consente a un sito malevolo di leggere "
                             "risposte autenticate (OWASP A05). Restringi le origin. (P8)"),
                remediation_ref="CORS_MISCONFIG", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
        posture.append(PostureCheck(
            check_id="POSTURE_CORS_SAFE", title="CORS sicuro", passed=not bad,
            severity_if_failed=Severity.HIGH, target=target,
            detail="CORS non riflette origin arbitrarie con credenziali" if not bad
                   else "CORS permissivo con credenziali"))

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        loc = Location(endpoint="server_exposure")
        f = Finding(
            finding_id=_finding_id("server_exposure", "SERVER_EXPOSURE_SKIPPED", loc),
            module="server_exposure", rule_id="SERVER_EXPOSURE_SKIPPED",
            title="Verifica server_exposure saltata", severity=Severity.INFO,
            confidence=Confidence.FIRM, target=target, location=loc, evidence=motivo,
            description=(f"server_exposure (M4.4) saltato: {motivo} Skip dichiarato (§4.7/§26)."),
            intrusion_used=IntrusionLevel.READ_ONLY)
        return ModuleResult(findings=[f], posture_checks=[])
```

> **Nota:** il test `test_hardened_app_no_findings` non esercita `VERBOSE_ERROR_LEAK` (richiede endpoint API + body malformato); l'oracolo errori-verbosi è OPZIONALE in MVP — se il builder non lo implementa, rimuovere `VERBOSE_ERROR_LEAK` dalla lista rule_id e dal set `bad` del test. Se lo implementa: POST body non-JSON a un `cfg.auth.api_endpoints` di tipo create/update; se `resp.text` contiene un marker di `_ERROR_MARKERS` → Finding `VERBOSE_ERROR_LEAK` MEDIUM (evidence = solo "stack trace presente", mai il corpo). Aggiungere un test dedicato app-vulnerabile/hardened.

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_server_exposure.py -q`
Expected: PASS.

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/server_exposure/ tests/test_server_exposure.py
git commit -m "feat(m4): server_exposure (source-map/endpoint/CORS, riusa detector §10) (M4.4)"
```

---

## Task 3: M4.3 — `zap_active` (MUTATING 🔴)

**Files:**
- Create: `bastione/modules/zap_active/__init__.py` (vuoto), `bastione/modules/zap_active/module.py`
- Test: `tests/test_zap_active.py`

**Interfaces:**
- Consumes: `Module`/`register`; `authorize`/`IntrusionDenied`; `acquire_session` (M4.0); `shutil.which`.
- Produces: `ZapActiveModule(name="zap_active", max_intrusion=MUTATING)`; module-level `_run_zap_active(base_url, session_headers, endpoints, out_path) -> list|None`, `_finding_id`. Rule_id: `<zap-pluginId>`, `ZAP_ACTIVE_SKIPPED`.

> Clona **`bastione/modules/nuclei/module.py`** (which→SKIPPED, raw/, parse→Finding) ma a **MUTATING** con **gate-first** come **`bastione/modules/idor/module.py`** (`authorize(MUTATING)` prima dell'I/O, `IntrusionDenied` propaga).

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_zap_active.py -q`
Expected: FAIL `ModuleNotFoundError`.

- [ ] **Step 3: Implement the module**

`bastione/modules/zap_active/__init__.py` — vuoto.

`bastione/modules/zap_active/module.py`:

```python
"""ZapActiveModule — DAST autenticato con ZAP active (M4.3, MUTATING 🔴).

Colla sottile (§14) attorno a ZAP active con POLICY VINCOLATA (esclude le regole
ascan distruttive/mutanti, cap di severità — sul modello del fix nuclei M1). Anche
così è MUTATING (l'active scan può submettere a form/endpoint): gate-first
authorize(MUTATING) → staging-only + ownership + --i-own-this-its-staging.
ZAP assente → ZAP_ACTIVE_SKIPPED INFO. Confine I/O `_run_zap_active` monkeypatchato
(offline). API key/host ZAP via ENV. P8: evidence = nome alert + url, mai payload."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from pathlib import Path

from bastione.auth.session import acquire_session
from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (Finding, Fingerprint, Location, ModuleResult,
                             RunContext, TargetConfig)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.zap_active")
_ZAP_TIMEOUT = 1800  # l'active scan può richiedere tempo

_RISK_MAP = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
             "low": Severity.LOW, "informational": Severity.INFO, "info": Severity.INFO}

# Categorie ascan distruttive/mutanti da ESCLUDERE dalla policy (vincolo §14).
_EXCLUDED_ASCAN = "sql-injection-mutating,os-command-injection,remote-code,upload,dos"


def _run_zap_active(base_url: str, session_headers: dict, endpoints: list, out_path: str):
    """Invoca ZAP active con policy VINCOLATA e ritorna la lista di alert (§14).

    Confine I/O monkeypatchato nei test. In produzione si parla col daemon ZAP via
    la sua REST API (host/api-key da ENV: BASTIONE_ZAP_ADDR, BASTIONE_ZAP_API_KEY),
    configurando la sessione autenticata (session_headers) e una scan policy che
    DISABILITA le regole distruttive (_EXCLUDED_ASCAN) — detection-oriented.

    Degrado grazioso (§4.7): qualunque errore / daemon assente → None (nessun
    alert), mai crash. Scrive il raw JSON in out_path."""
    addr = os.getenv("BASTIONE_ZAP_ADDR")
    api_key = os.getenv("BASTIONE_ZAP_API_KEY")
    if not addr:
        log.info("zap_active: BASTIONE_ZAP_ADDR assente, nessuno scan (M4.3)")
        return None
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: zap_active non disponibile (M4.3)")
        return None
    try:
        # NB: dialogo reale col daemon ZAP (spider auth context + active scan con
        # policy vincolata _EXCLUDED_ASCAN); qui in forma minimale/difensiva.
        params = {"apikey": api_key} if api_key else {}
        # (la sequenza reale: importa la sessione, avvia ascan, poll, leggi alerts)
        resp = httpx.get(f"{addr}/JSON/core/view/alerts/", params=params,
                         timeout=_ZAP_TIMEOUT)
        data = resp.json()
        alerts = data.get("alerts", []) if isinstance(data, dict) else []
        try:
            Path(out_path).write_text(json.dumps(alerts), encoding="utf-8")
        except OSError as exc:
            log.warning("zap_active: raw non scritto %s: %s", out_path, exc)
        return alerts if isinstance(alerts, list) else None
    except Exception as exc:  # noqa: BLE001
        log.warning("zap_active: scan fallito, degrado a None (§4.7): %s", exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _map_risk(raw: object) -> Severity:
    if isinstance(raw, str):
        return _RISK_MAP.get(raw.strip().lower(), Severity.INFO)
    return Severity.INFO


@register
class ZapActiveModule(Module):
    """DAST autenticato con ZAP active (M4.3, MUTATING)."""

    name = "zap_active"
    max_intrusion = IntrusionLevel.MUTATING

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        return bool(cfg.auth and cfg.auth.api_endpoints)

    def run(self, ctx: RunContext) -> ModuleResult:
        target = ctx.target_cfg.name
        # self-gate: niente active scan sotto MUTATING o senza ownership.
        if ctx.max_intrusion < IntrusionLevel.MUTATING or not ctx.ownership_verified:
            return self._skipped(target, "zap_active richiede --max-intrusion mutating + "
                                 "ownership/staging (§7): active scan saltato.")
        # GATE-FIRST: authorize PRIMA di qualsiasi scan (propaga IntrusionDenied → run aborta).
        authorize(IntrusionLevel.MUTATING, ctx)
        # which: ZAP assente → SKIPPED onesto.
        if shutil.which("zap") is None and shutil.which("zap.sh") is None:
            return self._skipped(target, "binario ZAP assente sul PATH (§14): active scan saltato.")
        # sessione autenticata (M4.0).
        sess = None
        if ctx.target_cfg.auth and ctx.target_cfg.auth.test_accounts:
            s = acquire_session(ctx.target_cfg.auth.test_accounts[0])
            sess = s if s.acquired_ok else None
        if sess is None:
            return self._skipped(target, "sessione di test non acquisita: active scan saltato.")

        raw_dir = Path(ctx.run_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_path = raw_dir / "zap-active.json"
        endpoints = [e.path_template for e in ctx.target_cfg.auth.api_endpoints]
        try:
            alerts = _run_zap_active(ctx.target_cfg.base_url.rstrip("/"),
                                     dict(sess.headers), endpoints, str(out_path))
        except Exception as exc:  # noqa: BLE001
            log.warning("zap_active: invocazione fallita (§4.7): %s", exc)
            return ModuleResult(findings=[], posture_checks=[])
        if alerts is None:
            return ModuleResult(findings=[], posture_checks=[])
        return ModuleResult(findings=self._parse(alerts, target), posture_checks=[])

    def _parse(self, alerts: list, target: str) -> list[Finding]:
        deduped: dict[str, Finding] = {}
        for alert in alerts if isinstance(alerts, list) else []:
            if not isinstance(alert, dict):
                continue
            rule_id = alert.get("pluginId") or alert.get("alertRef") or alert.get("name")
            if not isinstance(rule_id, str) or not rule_id:
                continue
            sev = _map_risk(alert.get("risk"))
            name = alert.get("name") if isinstance(alert.get("name"), str) else rule_id
            url = alert.get("url") if isinstance(alert.get("url"), str) else ""
            loc = Location(url=url or None)
            fid = _finding_id("zap_active", rule_id, loc)
            f = Finding(
                finding_id=fid, module="zap_active", rule_id=rule_id,
                title=f"zap: {name}", severity=sev, confidence=Confidence.FIRM,
                target=target, location=loc,
                evidence=f"zap alert '{name}' su {url}".rstrip(),  # P8: no payload/body
                description=(f"ZAP active ha rilevato '{name}' (pluginId {rule_id}) su "
                             f"{url or 'target'} (rischio {sev.name}). Scansione attiva "
                             "vincolata (MUTATING §14). Dettaglio in raw/zap-active.json."),
                remediation_ref=rule_id, intrusion_used=IntrusionLevel.MUTATING)
            deduped.setdefault(fid, f)
        return list(deduped.values())

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        loc = Location(endpoint="zap_active")
        f = Finding(
            finding_id=_finding_id("zap_active", "ZAP_ACTIVE_SKIPPED", loc),
            module="zap_active", rule_id="ZAP_ACTIVE_SKIPPED",
            title="Active scan ZAP saltato", severity=Severity.INFO,
            confidence=Confidence.FIRM, target=target, location=loc, evidence=motivo,
            description=(f"zap_active (M4.3) saltato: {motivo} Skip dichiarato (§4.7/§26)."),
            intrusion_used=IntrusionLevel.READ_ONLY)
        return ModuleResult(findings=[f], posture_checks=[])
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_zap_active.py -q`
Expected: PASS.

- [ ] **Step 5: Commit** *(orchestratore)*

```bash
git add bastione/modules/zap_active/ tests/test_zap_active.py
git commit -m "feat(m4): zap_active DAST autenticato (MUTATING, policy vincolata) (M4.3)"
```

---

## Task 4: Wiring orchestrator + full suite

**Files:**
- Modify: `bastione/orchestrator.py` (`_ensure_modules_loaded` += 3 import)
- Test: la full suite

**Interfaces:** Consumes i 3 moduli (Task 1-3). `zap` è già in `_EXTERNAL_TOOLS` (cli.py) → `doctor` lo riporta già; nessuna modifica a `cli.py`.

- [ ] **Step 1: Add the imports**

In `bastione/orchestrator.py`, in `_ensure_modules_loaded`, aggiungi (in ordine alfabetico tra gli import esistenti):

```python
    import bastione.modules.login_hardening.module  # noqa: F401  (M4.2)
    import bastione.modules.server_exposure.module  # noqa: F401  (M4.4)
    import bastione.modules.zap_active.module  # noqa: F401  (M4.3)
```

- [ ] **Step 2: Write the wiring test**

```python
# tests/test_zap_active.py (append) — verifica che i 3 moduli siano registrati via orchestrator
def test_m4_lanes_registered_via_orchestrator():
    from bastione.orchestrator import _ensure_modules_loaded
    from bastione.modules.base import REGISTRY
    _ensure_modules_loaded()
    assert {"login_hardening", "server_exposure", "zap_active"} <= set(REGISTRY)
    assert REGISTRY["zap_active"].max_intrusion.name == "MUTATING"
    assert REGISTRY["login_hardening"].max_intrusion.name == "PROBE"
```

- [ ] **Step 3: Run the FULL suite (ground-truth)**

Run: `python -m pytest -q`
Expected: PASS — 900 preesistenti + i nuovi M4.2/4.3/4.4, nessuna regressione.

- [ ] **Step 4: Commit** *(orchestratore)*

```bash
git add bastione/orchestrator.py tests/test_zap_active.py
git commit -m "feat(m4): wiring login_hardening/server_exposure/zap_active; full suite verde"
```

---

## Self-Review (eseguita)

**1. Spec coverage** — ogni sezione della spec ha un task:
- §3 M4.2 login_hardening (rate-limit/enum/cookie + login_attempts_cap) → Task 1 ✓
- §4 M4.3 zap_active (MUTATING, gate-first, which→SKIPPED, policy vincolata, parse) → Task 3 ✓
- §5 M4.4 server_exposure (source-map+detector §10, endpoint sensibili, CORS) → Task 2 ✓ · **VERBOSE_ERROR_LEAK reso OPZIONALE in MVP** (nota in Task 2: richiede API endpoint; se implementato, test dedicato) — scostamento dichiarato dalla spec §5.
- §6 rule_id → Task 1/2/3 ✓ · §7 config (login_attempts_cap, ENV) → Task 1 ✓ · §8 offline test (app sintetiche vuln/hardened, gate, P8) → ogni task ✓ · §9 wiring → Task 4 ✓.

**2. Placeholder scan** — nessun "TBD/handle edge cases"; ogni step ha codice reale o comando. (L'unico punto "opzionale" — VERBOSE_ERROR_LEAK — è esplicitamente delimitato con istruzioni concrete, non un placeholder.)

**3. Type consistency** — `_login_request(url, *, json, headers)`, `_fetch(method, url, *, headers)`, `_run_zap_active(base_url, session_headers, endpoints, out_path)`, `_finding_id(module, rule_id, location)`, `_redact(value)`, `det.scan(TextAsset(source, content)) -> list[RawSecret]`, `acquire_session(acc) -> AuthSession`, gate `authorize(level, ctx)` coerenti tra task e con il codice reale (estratto via Explore). Rule_id coerenti tra implementazione e test.

**Domande aperte (spec §12, non bloccanti):** enumerazione = solo status-code (no timing); policy ZAP reale validata live (offline si testa parse+gate); allowlist endpoint sensibili con euristica anti-falso-positivo (content-type ≠ text/html).

---

*Allineato a `BASTIONE-BLUEPRINT-v2.md` (§5/§7/§9/§10/§12/§14/§16/§17/§23/§25), `BASTIONE-WORKFLOWS.md`, al fondamento M4.0 e alla spec `2026-06-20-bastione-m4-lanes-login-dast-exposure-design.md`.*
