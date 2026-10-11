"""ServerExposureModule — segreti/config esposti lato server (M4.4, PROBE 🟡).

Oracoli: source-map .js.map esposte (riusa i detector §10), endpoint sensibili
(allowlist; dal M5 il body passa ai detector §10), dev server esposto, specifica API
pubblicata, CORS permissivo. Confine I/O `_fetch` monkeypatchato.
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
# allowlist conservativa di path sensibili (§14). GET read-only. M5 (§4.5): varianti
# `.env` e metadati git.
_SENSITIVE_PATHS = ["/.env", "/.env.local", "/.env.production", "/.env.development",
                    "/.git/config", "/.git/HEAD", "/api/debug", "/server-status",
                    "/actuator", "/.aws/credentials", "/config.json"]
# M5 (§4.5): specifica API pubblicata (LOW) e marker di un dev server (HIGH).
_API_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs"]
_DEV_SERVER_PATHS = ["/@vite/client", "/__vite_ping"]
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


def _content_type(resp) -> str:
    try:
        return (resp.headers.get("content-type", "") or "").lower()
    except Exception:  # noqa: BLE001
        return ""


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
        self._dev_server(base, target, findings)
        self._api_spec(base, target, findings)
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
            ctype = _content_type(resp)
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
                             "(OWASP A05). Blocca l'accesso pubblico. Il contenuto passa ai "
                             "detector segreti (P8: valori redatti, nessun contenuto incluso)."),
                remediation_ref="SENSITIVE_ENDPOINT_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            # §4.5: il BODY passa ai detector L2 — una chiave trapelata va identificata
            # (e messa in rotazione), come già fa `_source_maps`.
            self._scan_body(path, getattr(resp, "text", "") or "", target, findings)

    def _scan_body(self, path, body, target, findings) -> None:
        asset = TextAsset(source=path, content=body)
        loc = Location(endpoint=path, file=path)
        seen: set[str] = set()
        for det in DETECTORS:
            try:
                raws = det.scan(asset)
            except Exception:  # noqa: BLE001
                continue
            for raw in raws:
                # stesso detector + stesso file → stesso finding_id: un solo finding
                if raw.detector_id in seen:
                    continue
                seen.add(raw.detector_id)
                sev = (raw.severity_override if raw.severity_override is not None
                       else det.severity)
                findings.append(Finding(
                    finding_id=_finding_id("server_exposure", raw.detector_id, loc),
                    module="server_exposure", rule_id=raw.detector_id,
                    title=f"{det.title} (in file di config esposto {path})", severity=sev,
                    confidence=Confidence.FIRM, target=target, location=loc,
                    evidence=f"{_redact(raw.value)} (in {path})",
                    description=(f"Un file di config esposto ({path}) contiene un segreto "
                                 f"{raw.detector_id}. Rimuovere il file dall'accesso pubblico e "
                                 "RUOTARE il segreto. (P8: valore redatto.)"),
                    remediation_ref=raw.detector_id, owasp=["A05:2021"],
                    gdpr_relevant=det.gdpr_relevant, intrusion_used=IntrusionLevel.PROBE))

    def _dev_server(self, base, target, findings) -> None:
        for path in _DEV_SERVER_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            # SPA fallback (ogni path → index.html) non è un dev server
            if "text/html" in _content_type(resp):
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "DEV_SERVER_EXPOSED", loc),
                module="server_exposure", rule_id="DEV_SERVER_EXPOSED",
                title="Dev server raggiungibile pubblicamente", severity=Severity.HIGH,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (endpoint da dev server)",
                description=(f"Il path {path} risponde 200: un dev server (es. Vite) è esposto "
                             "— source non minificato, HMR, superficie estesa. Servi solo la "
                             "build di produzione."),
                remediation_ref="DEV_SERVER_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            return   # un marker basta

    def _api_spec(self, base, target, findings) -> None:
        for path in _API_SPEC_PATHS:
            resp = _fetch("GET", base + path, headers=None)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                continue
            ctype = _content_type(resp)
            if "text/html" in ctype:
                continue
            loc = Location(endpoint=path)
            findings.append(Finding(
                finding_id=_finding_id("server_exposure", "API_SPEC_EXPOSED", loc),
                module="server_exposure", rule_id="API_SPEC_EXPOSED",
                title=f"Specifica API pubblicata: {path}", severity=Severity.LOW,
                confidence=Confidence.FIRM, target=target, location=loc,
                evidence=f"GET {path} → 200 (content-type {ctype or 'n/d'})",
                description=(f"La specifica API {path} è pubblica: utile a un attaccante per "
                             "mappare la superficie. Pubblicala solo se intenzionale."),
                remediation_ref="API_SPEC_EXPOSED", owasp=["A05:2021"],
                intrusion_used=IntrusionLevel.PROBE))
            return

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
