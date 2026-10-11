"""Supabase auth posture (§4.3/§11.1.5) — READ_ONLY.

Confronta la configurazione PUBBLICA di GoTrue (`GET /auth/v1/settings`, endpoint
documentato → READ_ONLY, R1) con le attese dichiarate (R7). Sostituisce il
signup-probe POST di Fable (D3: niente creazione utenti). Onestà (R6): settings non
leggibili → AUTH_SETTINGS_NOT_READABLE INFO. Lettura difensiva dei campi.
"""
from __future__ import annotations

import hashlib
import logging

from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.models import Finding, Location, PostureCheck, RunContext

log = logging.getLogger("bastione.supabase.auth_posture")
_HTTP_TIMEOUT = 15.0


def _get(url: str, headers: dict):
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: auth posture non disponibile (§11.1.5)")
        return None
    try:
        return httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # P8: solo il TIPO dell'errore (il messaggio può ripetere un valore d'header).
        log.warning("auth settings GET %s fallita: %s", url, type(exc).__name__)
        return None


def _finding_id(module, rule_id, location) -> str:
    return hashlib.sha256(
        f"{module}:{rule_id}:{location.canonical()}".encode()).hexdigest()[:16]


def _finding(rule_id, title, sev, desc, loc, target, conf=Confidence.FIRM) -> Finding:
    return Finding(
        finding_id=_finding_id("supabase", rule_id, loc), module="supabase", rule_id=rule_id,
        title=title, severity=sev, confidence=conf, target=target, location=loc,
        evidence=f"GET /auth/v1/settings: {title}", description=desc,
        remediation_ref=rule_id, owasp=["A05:2021"], intrusion_used=IntrusionLevel.READ_ONLY)


def _anon_signin_flag(s: dict) -> bool | None:
    """Flag del sign-in anonimo nella risposta di `GET /auth/v1/settings`.

    GoTrue lo espone ANNIDATO come `external.anonymous_users`, accanto agli altri
    provider (`external.email`, `external.google`, …) — il nome piatto
    `..._EXTERNAL_ANONYMOUS_USERS_ENABLED` è quello della ENV var del server, non una
    chiave della risposta. None = flag assente (GoTrue senza sign-in anonimo)."""
    ext = s.get("external")
    if isinstance(ext, dict) and "anonymous_users" in ext:
        return bool(ext.get("anonymous_users"))
    return None


def run_auth_posture_checks(ctx: RunContext, base: str, headers: dict[str, str], target: str):
    findings: list[Finding] = []
    posture: list[PostureCheck] = []
    cfg = ctx.target_cfg
    loc = Location(endpoint="/auth/v1/settings", url=cfg.supabase_url or base)
    resp = _get(f"{base}/auth/v1/settings", headers)
    if resp is None or getattr(resp, "status_code", None) != 200:
        findings.append(_finding(
            "AUTH_SETTINGS_NOT_READABLE", "Configurazione auth non leggibile", Severity.INFO,
            "GET /auth/v1/settings non ha risposto 200: la configurazione auth non è "
            "verificabile (R6). Verifica INCOMPLETA.", loc, target, conf=Confidence.TENTATIVE))
        return findings, posture
    try:
        s = resp.json()
    except (ValueError, TypeError):
        s = None
    if not isinstance(s, dict):
        findings.append(_finding(
            "AUTH_SETTINGS_NOT_READABLE", "Configurazione auth non interpretabile", Severity.INFO,
            "GET /auth/v1/settings ha risposto 200 ma non JSON-oggetto (R6).", loc, target,
            conf=Confidence.TENTATIVE))
        return findings, posture

    exp = cfg.expect_auth
    as_declared = True

    # 1) signup aperto (oracle-first R7)
    if "disable_signup" in s:
        signup_open = not bool(s.get("disable_signup"))
        if signup_open:
            want = exp.signup_open if exp else None
            if want is True:
                pass  # atteso
            elif want is False:
                as_declared = False
                findings.append(_finding(
                    "SIGNUP_OPEN", "Registrazione self-service aperta", Severity.MEDIUM,
                    "Il signup pubblico è attivo (`disable_signup=false`) ma la matrice "
                    "dichiara signup_open=false: violazione (§15).", loc, target))
            else:
                # location distinta per sotto-check: i due "non dichiarato" non devono
                # condividere il finding_id (il dedup ne scarterebbe uno, R6).
                findings.append(_finding(
                    "AUTH_EXPECTATION_UNDECLARED", "Signup aperto — attesa non dichiarata",
                    Severity.INFO,
                    "Il signup pubblico è attivo ma il TOML non dichiara se è voluto. "
                    "Dichiara `[expectations.auth] signup_open=true|false` (R7).",
                    loc.model_copy(update={"endpoint": "/auth/v1/settings#signup"}), target,
                    conf=Confidence.TENTATIVE))

    # 2) conferma email (MEDIUM sempre quando autoconfirm attivo — decisione del piano)
    if bool(s.get("mailer_autoconfirm")):
        findings.append(_finding(
            "SIGNUP_NO_EMAIL_CONFIRM", "Conferma email non richiesta alla registrazione",
            Severity.MEDIUM,
            "`mailer_autoconfirm=true`: gli account sono attivi senza verifica email → "
            "abuso/spoofing dell'identità. Attiva la conferma email in Auth settings.",
            loc, target))

    # 3) sign-in anonimo (oracle-first R7)
    anon_on = _anon_signin_flag(s)
    if anon_on is not None:
        if anon_on:
            want = exp.anonymous_signin if exp else None
            if want is True:
                pass
            elif want is False:
                as_declared = False
                findings.append(_finding(
                    "ANON_SIGNIN_ENABLED", "Sign-in anonimo abilitato", Severity.MEDIUM,
                    "Il sign-in anonimo è attivo ma la matrice dichiara "
                    "anonymous_signin=false: violazione (§15).", loc, target))
            else:
                findings.append(_finding(
                    "AUTH_EXPECTATION_UNDECLARED", "Sign-in anonimo — attesa non dichiarata",
                    Severity.INFO,
                    "Il sign-in anonimo è attivo ma il TOML non dichiara se è voluto. "
                    "Dichiara `[expectations.auth] anonymous_signin=true|false` (R7).",
                    loc.model_copy(update={"endpoint": "/auth/v1/settings#anonymous_signin"}),
                    target, conf=Confidence.TENTATIVE))

    posture.append(PostureCheck(
        check_id="POSTURE_AUTH_AS_DECLARED",
        title="Configurazione auth conforme alle attese dichiarate",
        passed=as_declared, severity_if_failed=Severity.MEDIUM, target=target,
        detail=("Signup/sign-in anonimo coerenti con [expectations.auth] (§15)."
                if as_declared else
                "La configurazione auth viola un'attesa dichiarata (vedi i finding)."),
        remediation_ref="SIGNUP_OPEN"))
    return findings, posture
