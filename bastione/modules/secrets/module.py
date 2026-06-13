"""SecretsModule — scansione secret-leak sulle pagine e bundle JS (§10 del blueprint).

Scopo M0 (P5): READ_ONLY. Il modulo:
  1. Scarica (GET) le pagine in ctx.fingerprint.resolved_urls.
  2. Per ogni pagina, estrae i bundle JS same-host referenziati da <script src>
     usando bastione.recon.fingerprint.extract_script_srcs (funzione pubblica).
  3. Scarica ogni bundle JS same-host (owned-only §7/§4.2).
  4. Per ogni TextAsset (pagina + bundle) esegue tutti i Detector in DETECTORS.
  5. Converte ogni RawSecret in Finding con evidence REDATTA (mai il segreto
     in chiaro, §P8): primi 6 + "..." + ultimi 4 caratteri del token.

Il confine di I/O (_fetch a livello modulo) è monkeypatchabile nei test (pattern
identico a bastione/recon/fingerprint.py, dove _fetch è la funzione a sé).

Resilienza (§4.7): ogni asset non scaricabile viene saltato e loggato — non
crasha la scansione degli altri asset. Un modulo/asset che fallisce non
impatta gli altri finding.

TODO M1: probing di .env, .git/config, source map su path indovinati
         (§10 — non implementare in M0, solo il commento qui come marker).
"""

from __future__ import annotations

import hashlib
import logging
from urllib.parse import urlparse

from bastione.enums import Confidence, IntrusionLevel
from bastione.models import (
    Finding,
    Fingerprint,
    Location,
    ModuleResult,
    RawSecret,
    RunContext,
    TargetConfig,
    TextAsset,
)
from bastione.modules.base import Module, register
from bastione.recon.fingerprint import extract_script_srcs

log = logging.getLogger("bastione.modules.secrets")


# ─── confine I/O (monkeypatchabile nei test) ────────────────────────────────

def _fetch(url: str):
    """GET read-only via httpx-lib. Ritorna la response (con .url/.text) o None
    se httpx manca o la richiesta fallisce — degrada con grazia (§4.7/L06)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: secrets HTTP non disponibile (§10)")
        return None
    try:
        return httpx.get(url, timeout=15.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        log.warning("GET %s fallita: %s", url, exc)
        return None


# ─── helper: redazione evidence (P8) ────────────────────────────────────────

def _redact(value: str) -> str:
    """Redige un segreto per l'evidence del Finding: primi 6 char + '...' + ultimi 4.

    Garantisce che il token in chiaro non appaia mai nell'output (§P8). Per token
    molto corti (≤ 10 char) usa solo i primi 4 + '...'.
    """
    if len(value) <= 10:
        return value[:4] + "..."
    return value[:6] + "..." + value[-4:]


# ─── helper: finding_id stabile (§16) ────────────────────────────────────────

def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, formula LOCKED):

        sha256(f"{module}:{rule_id}:{location.canonical()}").hexdigest()[:16]

    NON include `target` (allineato a bastione/baseline/diff.py:finding_id e
    bastione/modules/supabase/module.py:_finding_id) né il valore del segreto
    (che è redatto) né timestamp — solo coordinate stabili del finding. Si appoggia
    a `Location.canonical()`, che normalizza i content-hash dei bundle (§5.2)."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── modulo principale ────────────────────────────────────────────────────────

@register
class SecretsModule(Module):
    """Modulo secret-leak: scansiona pagine e bundle JS same-host (§10).

    Scopo M0 (P5): READ_ONLY — solo GET delle pagine dichiarate e dei bundle
    JS same-host. Nessun probing attivo di path indovinati (TODO M1).
    should_run = True sempre (§9): qualunque target può avere segreti esposti.
    """

    name = "secrets"
    max_intrusion = IntrusionLevel.READ_ONLY

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Ritorna sempre True (§9/§10): i segreti possono essere in qualunque target."""
        return True

    def run(self, ctx: RunContext) -> ModuleResult:
        """Scansiona pagine e bundle JS same-host per segreti esposti (§10).

        Pipeline:
          1. Scarica le pagine in ctx.fingerprint.resolved_urls.
          2. Per ogni pagina, estrae bundle JS same-host (<script src>).
          3. Scarica i bundle same-host.
          4. Esegue ogni Detector in DETECTORS su ogni TextAsset.
          5. Converte RawSecret → Finding con evidence REDATTA.

        Resiliente: asset non scaricabile → saltato (§4.7).
        """
        # Import lazy dei detector (si assicura che DETECTORS sia popolato)
        from bastione.modules.secrets.detectors.base import DETECTORS

        findings: list[Finding] = []
        asset_urls: list[str] = list(ctx.fingerprint.resolved_urls)

        # Cache {url: TextAsset} per evitare il doppio fetch (§4.7): la pagina
        # viene scaricata UNA sola volta — la response serve sia per estrarre i
        # <script src> sia per la scansione successiva, senza un secondo GET.
        assets: dict[str, TextAsset] = {}

        # Raccolta bundle JS same-host da ogni pagina (singolo fetch per pagina)
        for page_url in list(asset_urls):
            resp = _fetch(page_url)
            if resp is None:
                log.warning("secrets: pagina non raggiungibile, saltata: %s", page_url)
                continue

            # Riuso della response: costruiamo subito il TextAsset della pagina,
            # così la scansione non rifarà un secondo GET sullo stesso URL.
            assets[page_url] = TextAsset(source=page_url, content=resp.text)

            page_host = urlparse(str(resp.url)).netloc
            srcs = extract_script_srcs(resp.text, str(resp.url))
            for src in srcs:
                src_host = urlparse(src).netloc
                if src_host != page_host:
                    # Owned-only (§7/§4.2): bundle su host esterno → saltato
                    log.info(
                        "secrets: bundle su host esterno ignorato (owned-only §7): %s", src)
                    continue
                if src not in asset_urls:
                    asset_urls.append(src)

        # Scansione di ogni asset
        for url in asset_urls:
            asset = assets.get(url)
            if asset is None:
                # Solo i bundle non ancora scaricati richiedono un fetch: le pagine
                # sono già nella cache (un solo GET per pagina, vedi sopra).
                resp = _fetch(url)
                if resp is None:
                    log.warning("secrets: asset non scaricabile, saltato: %s", url)
                    continue
                asset = TextAsset(source=url, content=resp.text)

            for detector in DETECTORS:
                try:
                    raw_secrets = detector.scan(asset)
                except Exception as exc:  # noqa: BLE001
                    # Resilienza: un detector che esplode non ferma gli altri
                    log.warning(
                        "secrets: detector %r ha sollevato un'eccezione su %s: %s",
                        detector.detector_id, url, exc)
                    continue

                for raw in raw_secrets:
                    loc = Location(file=url)
                    evidence = _redact(raw.value)
                    fid = _finding_id("secrets", detector.detector_id, loc)
                    findings.append(Finding(
                        finding_id=fid,
                        module="secrets",
                        rule_id=detector.detector_id,
                        title=detector.title,
                        severity=detector.severity,
                        confidence=Confidence.FIRM,
                        target=ctx.target_cfg.name,
                        location=loc,
                        evidence=evidence,
                        description=(
                            f"Rilevato segreto {detector.detector_id} esposto "
                            f"in {url}. Evidence: {evidence}. "
                            "Rimuovere immediatamente dal codice sorgente e "
                            "ruotare il segreto (§10)."
                        ),
                        remediation_ref=detector.detector_id,
                        owasp=["A05:2021"],
                        gdpr_relevant=detector.gdpr_relevant,
                        intrusion_used=IntrusionLevel.READ_ONLY,
                    ))

        return ModuleResult(findings=findings, posture_checks=[])
