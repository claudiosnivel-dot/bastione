"""SecretsModule — scansione secret-leak sulle pagine e bundle JS (§10 del blueprint).

Scopo M0 (P5): READ_ONLY. Il modulo:
  1. Scarica (GET) le pagine in ctx.fingerprint.resolved_urls.
  2. Per ogni pagina, estrae i bundle JS same-host referenziati da <script src>
     usando bastione.recon.fingerprint.extract_script_srcs (funzione pubblica).
  3. Scarica ogni bundle JS same-host (owned-only §7/§4.2).
  4. Per ogni TextAsset (pagina + bundle) esegue tutti i Detector in DETECTORS.
  5. Converte ogni RawSecret in Finding con evidence REDATTA (mai il segreto
     in chiaro, §P8): primi 6 + "..." + ultimi 4 caratteri del token.

Stadio 2 — Liveness (PROBE 🟡, §10.2): opt-in, eseguito SOLO se il tetto della
run è ≥ PROBE E l'ownership è verificata. Per i RawSecret il cui detector
supporta `validate_liveness`, una GET read-only verifica se la chiave è ancora
viva e arricchisce il Finding corrispondente (intrusion_used=PROBE). Gated dal
backstop gate.authorize(PROBE, ctx); un fallimento qui non crasha la scansione.

Il confine di I/O (_fetch a livello modulo) è monkeypatchabile nei test (pattern
identico a bastione/recon/fingerprint.py, dove _fetch è la funzione a sé). La
liveness usa il proprio confine I/O (_probe in detectors/service_role.py).

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
from bastione.gate import IntrusionDenied, authorize
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
    # PROBE: il tetto reale di capability del modulo (§10.2). La detection Stadio 1
    # è READ_ONLY, ma lo Stadio 2 (liveness, _run_liveness) esegue azioni PROBE
    # (authorize(PROBE) + GET privilegiata read-only). `max_intrusion` è "la più alta
    # intrusione che il modulo può richiedere" (base.py) ed è esposto user-facing da
    # `list-modules` (cli.py): deve riflettere PROBE. NON è un bypass del gate —
    # l'autorizzazione runtime usa sempre il tetto run-wide ctx.max_intrusion.
    max_intrusion = IntrusionLevel.PROBE

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Ritorna sempre True (§9/§10): i segreti possono essere in qualunque target."""
        return True

    def run(self, ctx: RunContext) -> ModuleResult:
        """Scansiona pagine e bundle JS same-host per segreti esposti (§10).

        Pipeline:
          1. Scarica le pagine in ctx.fingerprint.resolved_urls.
          2. Per ogni pagina, estrae bundle JS same-host (<script src>).
          3. Scarica i bundle same-host.
          4. Esegue ogni Detector in DETECTORS su ogni TextAsset (Stadio 1,
             READ_ONLY). Converte RawSecret → Finding con evidence REDATTA.
          5. Stadio 2 — Liveness (PROBE 🟡, §10.2): SOLO se tetto ≥ PROBE E
             ownership verificata, arricchisce i Finding con la liveness.

        Resiliente: asset non scaricabile → saltato (§4.7).
        """
        # Import lazy dei detector (si assicura che DETECTORS sia popolato)
        from bastione.modules.secrets.detectors.base import DETECTORS

        findings: list[Finding] = []
        # Traccia (finding, raw_secret, detector) per lo Stadio 2: serve a
        # ricollegare il RawSecret (col token in chiaro, mai esposto) e il detector
        # al Finding già redatto, così la liveness può arricchirlo senza riscansionare.
        detected: list[tuple[Finding, RawSecret, object]] = []
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
                    finding = Finding(
                        finding_id=fid,
                        module="secrets",
                        rule_id=detector.detector_id,
                        title=detector.title,
                        severity=(raw.severity_override
                                  if raw.severity_override is not None
                                  else detector.severity),
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
                    )
                    findings.append(finding)
                    detected.append((finding, raw, detector))

        # ── Stadio 2 — Liveness (PROBE 🟡, §10.2) ────────────────────────────
        # Opt-in e gated: gira SOLO con tetto ≥ PROBE E ownership verificata.
        # Quando NON gira, il comportamento M0 resta IDENTICO (nessun probe,
        # nessun authorize): solo la detection READ_ONLY sopra.
        self._run_liveness(ctx, detected)

        return ModuleResult(findings=findings, posture_checks=[])

    # ─── Stadio 2 — Liveness (PROBE) ────────────────────────────────────────

    def _run_liveness(
        self,
        ctx: RunContext,
        detected: list[tuple[Finding, RawSecret, object]],
    ) -> None:
        """Verifica read-only se i segreti rilevati sono ancora vivi (§10.2).

        Gate (§7/§10.2): gira SOLO se tetto run ≥ PROBE E ownership verificata.
        Prima di qualsiasi probe chiama `authorize(PROBE, ctx)` come backstop
        (difesa in profondità): se solleva `IntrusionDenied`, logga e salta —
        niente crash. Ogni finding arricchito passa a intrusion_used=PROBE
        mantenendo confidence=FIRM (verificato; NON esiste Confidence.CONFIRMED).
        L'evidence resta redatta e il token in chiaro non appare mai (§P8).

        NON emette PostureCheck: POSTURE_SERVICE_ROLE_HIDDEN è già coperto dalla
        fase NORMALIZE dell'orchestratore (la detection di una service_role lo fa
        già fallire) — qui si arricchisce solo il Finding, senza duplicazioni."""
        # Precondizione: niente liveness in read-only o senza ownership (M0 identico).
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return
        if not detected:
            return

        # Backstop del gate (§7): se nega, salta tutta la liveness, non crasha.
        try:
            authorize(IntrusionLevel.PROBE, ctx)
        except IntrusionDenied as exc:
            log.info("secrets: liveness PROBE negata dal gate, salto (§7): %s", exc)
            return

        for finding, raw, detector in detected:
            try:
                result = detector.validate_liveness(raw)
            except Exception as exc:  # noqa: BLE001
                # Resilienza (§4.7): un probe che esplode non ferma gli altri.
                log.warning(
                    "secrets: liveness %r ha sollevato un'eccezione: %s",
                    detector.detector_id, exc)
                continue

            if result is None:
                # Esito sconosciuto: il finding di detection resta invariato.
                continue

            # Arricchimento del Finding (mutazione in place: è lo stesso oggetto
            # già presente in `findings`). Evidence già redatta, immutata (§P8).
            finding.intrusion_used = IntrusionLevel.PROBE
            finding.confidence = Confidence.FIRM
            if result.alive:
                finding.description = (
                    f"{detector.detector_id}: chiave CONFERMATA VIVA tramite "
                    f"liveness read-only (PROBE). {result.detail} {finding.description}"
                )
            else:
                finding.description = (
                    f"{detector.detector_id}: chiave esposta ma apparentemente "
                    f"REVOCATA/ruotata (liveness PROBE). {result.detail} "
                    f"{finding.description}"
                )
