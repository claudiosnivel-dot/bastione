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
        try:
            resp = http("POST", account.login_url,
                        json={"email": account.email, "password": password})
        except Exception as exc:  # noqa: BLE001 — il contratto "mai solleva" (§4.7)
            # vale per QUALUNQUE _http iniettato, non solo per il default che già
            # cattura. Nessun segreto nel log (solo metadati, P8).
            log.warning("auth POST %s fallita: %s", account.login_url, exc)
            return AuthSession(account_label=account.label, acquired_ok=False)
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
