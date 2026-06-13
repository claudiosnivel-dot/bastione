"""Modulo di verifica degli HTTP security headers (§12).

Produce esclusivamente PostureCheck (nessun Finding): ogni header di sicurezza
standard viene verificato e marcato passed/failed. Il livello di intrusione è
READ_ONLY perché si analizzano solo gli header già presenti nel Fingerprint,
raccolti durante la fase RECON (§8) — nessuna nuova richiesta di rete.

Header verificati (P8 / §12):
  - Strict-Transport-Security     → POSTURE_HSTS       (HIGH)
  - Content-Security-Policy       → POSTURE_CSP        (HIGH)
  - X-Content-Type-Options=nosniff→ POSTURE_XCTO       (MEDIUM)
  - X-Frame-Options ∨ CSP frame-ancestors → POSTURE_XFO (MEDIUM)
  - Referrer-Policy               → POSTURE_REFERRER   (LOW)
  - Permissions-Policy            → POSTURE_PERMISSIONS (LOW)

TLS minimum check: best-effort/opzionale; se non determinabile offline, saltato
senza crash (guardrail resilienza §4.7 / P8).
"""

from __future__ import annotations

import logging

from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, ModuleResult, PostureCheck, RunContext, TargetConfig
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.headers")


def _headers_ci(raw: dict[str, str]) -> dict[str, str]:
    """Restituisce una copia degli header con chiavi in minuscolo (case-insensitive).

    Gli header HTTP sono case-insensitive per specifica (RFC 7230 §3.2);
    normalizzare a minuscolo consente lookup uniformi.
    """
    return {k.lower(): v for k, v in raw.items()}


@register
class HeadersModule(Module):
    """Verifica la presenza degli HTTP security header standard (§12).

    Analisi puramente offline: legge ctx.fingerprint.response_headers —
    già raccolti dal RECON — senza emettere nuove richieste di rete.
    """

    name = "headers"
    max_intrusion = IntrusionLevel.READ_ONLY

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Gira solo se il RECON ha raggiunto almeno un URL (§12).

        Senza resolved_urls non ci sono header da analizzare: il modulo
        sarebbe un no-op silenzioso.
        """
        return bool(fp.resolved_urls)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Verifica gli HTTP security header e produce un PostureCheck per ognuno.

        Per ogni regola: se l'header (o la condizione equivalente) è presente
        nel Fingerprint, il check è passed=True; altrimenti passed=False con la
        severity_if_failed configurata (§12). Non produce mai Finding.
        """
        target = ctx.target_cfg.name
        hdrs = _headers_ci(ctx.fingerprint.response_headers)
        checks: list[PostureCheck] = []

        # ── POSTURE_HSTS: Strict-Transport-Security obbligatorio (HIGH) ──────
        hsts_present = "strict-transport-security" in hdrs
        checks.append(PostureCheck(
            check_id="POSTURE_HSTS",
            title="Strict-Transport-Security header presente",
            passed=hsts_present,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"Strict-Transport-Security: {hdrs['strict-transport-security']!r}"
                if hsts_present
                else "Header Strict-Transport-Security assente"
            ),
        ))

        # ── POSTURE_CSP: Content-Security-Policy (HIGH) ───────────────────────
        csp_value = hdrs.get("content-security-policy", "")
        csp_present = bool(csp_value)
        checks.append(PostureCheck(
            check_id="POSTURE_CSP",
            title="Content-Security-Policy header presente",
            passed=csp_present,
            severity_if_failed=Severity.HIGH,
            target=target,
            detail=(
                f"Content-Security-Policy: {csp_value!r}"
                if csp_present
                else "Header Content-Security-Policy assente"
            ),
        ))

        # ── POSTURE_XCTO: X-Content-Type-Options=nosniff (MEDIUM) ────────────
        xcto_value = hdrs.get("x-content-type-options", "")
        xcto_ok = xcto_value.strip().lower() == "nosniff"
        checks.append(PostureCheck(
            check_id="POSTURE_XCTO",
            title="X-Content-Type-Options: nosniff presente",
            passed=xcto_ok,
            severity_if_failed=Severity.MEDIUM,
            target=target,
            detail=(
                f"X-Content-Type-Options: {xcto_value!r}"
                if xcto_ok
                else (
                    f"X-Content-Type-Options presente ma valore non 'nosniff': {xcto_value!r}"
                    if xcto_value
                    else "Header X-Content-Type-Options assente"
                )
            ),
        ))

        # ── POSTURE_XFO: X-Frame-Options OPPURE CSP frame-ancestors (MEDIUM) ─
        # RFC 7034 e CSP3 §8.4: frame-ancestors in CSP sostituisce X-Frame-Options;
        # è sufficiente che uno dei due sia presente (§12).
        xfo_present = "x-frame-options" in hdrs
        csp_frame_ancestors = "frame-ancestors" in csp_value.lower()
        xfo_ok = xfo_present or csp_frame_ancestors
        if xfo_present:
            xfo_detail = f"X-Frame-Options: {hdrs['x-frame-options']!r}"
        elif csp_frame_ancestors:
            xfo_detail = "CSP frame-ancestors presente (equivalente a X-Frame-Options)"
        else:
            xfo_detail = "Né X-Frame-Options né CSP frame-ancestors presenti"
        checks.append(PostureCheck(
            check_id="POSTURE_XFO",
            title="X-Frame-Options o CSP frame-ancestors presente",
            passed=xfo_ok,
            severity_if_failed=Severity.MEDIUM,
            target=target,
            detail=xfo_detail,
        ))

        # ── POSTURE_REFERRER: Referrer-Policy (LOW) ───────────────────────────
        referrer_present = "referrer-policy" in hdrs
        checks.append(PostureCheck(
            check_id="POSTURE_REFERRER",
            title="Referrer-Policy header presente",
            passed=referrer_present,
            severity_if_failed=Severity.LOW,
            target=target,
            detail=(
                f"Referrer-Policy: {hdrs['referrer-policy']!r}"
                if referrer_present
                else "Header Referrer-Policy assente"
            ),
        ))

        # ── POSTURE_PERMISSIONS: Permissions-Policy (LOW) ─────────────────────
        perms_present = "permissions-policy" in hdrs
        checks.append(PostureCheck(
            check_id="POSTURE_PERMISSIONS",
            title="Permissions-Policy header presente",
            passed=perms_present,
            severity_if_failed=Severity.LOW,
            target=target,
            detail=(
                f"Permissions-Policy: {hdrs['permissions-policy']!r}"
                if perms_present
                else "Header Permissions-Policy assente"
            ),
        ))

        log.debug(
            "Headers [%s]: %d checks, %d passed, %d failed",
            target,
            len(checks),
            sum(1 for c in checks if c.passed),
            sum(1 for c in checks if not c.passed),
        )

        # TLS minimum check: best-effort/opzionale. In M0 gli header TLS non sono
        # determinabili offline dall'analisi degli header HTTP; si salta senza crash
        # (guardrail resilienza §4.7). Sarà implementato in PROBE con connessione
        # TLS diretta (M1+).

        return ModuleResult(findings=[], posture_checks=checks)
