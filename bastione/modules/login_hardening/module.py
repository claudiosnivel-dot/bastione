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
        # L'oracolo richiede un'email esistente nota per essere significativo;
        # TestAccount.email è opzionale (str | None), quindi un account login_post
        # può arrivare qui senza email. Salto difensivo: niente crash (§4.7/§28).
        if not acc.email or "@" not in acc.email:
            return
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
