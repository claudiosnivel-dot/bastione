"""Modulo di verifica Cloudflare fronting (§12).

Produce esclusivamente PostureCheck (nessun Finding). Gira solo se il RECON
ha rilevato che il target è protetto da Cloudflare (fp.cloudflare_fronted=True).

Check implementati in M0:
  - POSTURE_CLOUDFLARE_FRONTED  (INFO): il target è frontato da Cloudflare.
    Se il RECON lo ha rilevato, il check è trivialmente passed=True — conferma
    che la protezione CDN/WAF è attiva. severity_if_failed=INFO (peso 1, §17)
    perché il modulo gira solo quando cloudflare_fronted=True (should_run):
    il check non può mai fallire, quindi non deve gonfiare il posture score
    (§26 "lo score non gonfia"). Il lato fallibile arriva con
    POSTURE_ORIGIN_BYPASSABLE (M1).

Check rimandati a M1:
  - POSTURE_ORIGIN_BYPASSABLE: verifica se l'IP di origine è raggiungibile
    direttamente (bypass Cloudflare). Richiede euristiche DNS attive; non si
    implementano in M0 READ_ONLY (§12). TODO M1.
"""

from __future__ import annotations

import logging

from bastione.enums import IntrusionLevel, Severity
from bastione.models import Fingerprint, ModuleResult, PostureCheck, RunContext, TargetConfig
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.cloudflare")


@register
class CloudflareModule(Module):
    """Verifica il fronting Cloudflare e le sue implicazioni di sicurezza (§12).

    In M0 READ_ONLY: solo il check di presenza (POSTURE_CLOUDFLARE_FRONTED).
    Nessuna sonda DNS attiva, nessuna connessione diretta verso l'origin.
    """

    name = "cloudflare"
    max_intrusion = IntrusionLevel.READ_ONLY

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Gira solo se il target è frontato da Cloudflare (§12).

        Se cloudflare_fronted=False non c'è nulla da verificare: il modulo
        è un no-op e non deve emettere check (potrebbe generare falsi negativi
        su target non CF).
        """
        return fp.cloudflare_fronted

    def run(self, ctx: RunContext) -> ModuleResult:
        """Verifica il fronting Cloudflare e produce i PostureCheck (§12).

        In M0 emette solo POSTURE_CLOUDFLARE_FRONTED (passed=True, perché il
        modulo gira solo quando cloudflare_fronted=True).

        TODO M1 — POSTURE_ORIGIN_BYPASSABLE: euristiche DNS per verificare se
        l'IP di origine è raggiungibile direttamente (bypass del WAF/CDN).
        Non implementato in M0: richiede risoluzione DNS attiva (IntrusionLevel
        PROBE) e va oltre il perimetro READ_ONLY.
        """
        target = ctx.target_cfg.name
        checks: list[PostureCheck] = []

        # ── POSTURE_CLOUDFLARE_FRONTED: il target è protetto da Cloudflare ───
        # Questo check è trivialmente passed=True: il modulo esegue solo se
        # cloudflare_fronted=True (see should_run). Lo emettiamo come check
        # esplicito perché il posture score (§17) deve poter contare la
        # protezione CDN/WAF come punto positivo.
        # severity_if_failed=INFO (peso 1, §17): essendo un check che non può
        # mai fallire in M0, un peso alto (MEDIUM=3) gonfierebbe il posture
        # score (§26 "lo score non gonfia"). Lo teniamo a INFO finché
        # POSTURE_ORIGIN_BYPASSABLE (M1) non introdurrà il lato fallibile.
        checks.append(PostureCheck(
            check_id="POSTURE_CLOUDFLARE_FRONTED",
            title="Target frontato da Cloudflare (CDN/WAF attivo)",
            passed=True,
            severity_if_failed=Severity.INFO,
            target=target,
            detail=(
                "Cloudflare rilevato dal RECON (header CF-RAY o Server: cloudflare). "
                "Il traffico passa attraverso il WAF/CDN Cloudflare."
            ),
        ))

        # TODO M1 — POSTURE_ORIGIN_BYPASSABLE:
        # Verificare se l'IP di origine è esposto direttamente (bypass CDN).
        # Richiede risoluzione DNS attiva → IntrusionLevel.PROBE, non M0.
        # Non si emette il check adesso: assenza ≠ passed, lasciamo il gap
        # esplicito come TODO documentato piuttosto che uno stub fuorviante.

        log.debug(
            "Cloudflare [%s]: %d checks emessi (ORIGIN_BYPASSABLE rimandato a M1)",
            target,
            len(checks),
        )

        return ModuleResult(findings=[], posture_checks=checks)
