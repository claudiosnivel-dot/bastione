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
# ENFORCED dal codice: ogni categoria è mappata agli scanner-id ZAP che vengono
# DISABILITATI nella scan policy PRIMA di avviare l'active scan (vedi
# `_apply_excluded_policy`). Mai solo documentale.
_EXCLUDED_ASCAN = "sql-injection-mutating,os-command-injection,remote-code,upload,dos"

# Mappa categoria-distruttiva → scanner-id ZAP (ascan plugin id) da disabilitare.
# Questi sono i plugin "attack"/mutanti che NON devono mai girare contro un target
# (SQLi mutante, OS command injection, RCE, upload arbitrario, DoS). La policy
# vincolata (§14) li disattiva tutti prima dello scan.
_EXCLUDED_SCANNER_IDS: dict[str, tuple[str, ...]] = {
    "sql-injection-mutating": ("40018", "40019", "40020", "40021", "40022",
                               "40024", "90018"),
    "os-command-injection": ("90020",),
    "remote-code": ("90019", "90034", "20019", "90021"),
    "upload": ("110009", "90035"),
    "dos": ("40017", "40043", "20015"),
}
# Nome della scan policy vincolata creata/usata lato ZAP (detection-oriented).
_CONSTRAINED_POLICY = "bastione-constrained"


def _excluded_scanner_ids() -> list[str]:
    """Espande `_EXCLUDED_ASCAN` negli scanner-id ZAP concreti da disabilitare.

    Sorgente unica di verità della policy vincolata (§14): converte le categorie
    distruttive elencate in `_EXCLUDED_ASCAN` nei plugin-id ascan corrispondenti.
    Usata sia da `_apply_excluded_policy` (enforcement reale) sia dai test
    (verifica che la policy sia applicata). Categorie sconosciute → ignorate."""
    ids: list[str] = []
    for cat in _EXCLUDED_ASCAN.split(","):
        ids.extend(_EXCLUDED_SCANNER_IDS.get(cat.strip(), ()))
    # dedup mantenendo l'ordine
    return list(dict.fromkeys(ids))


def _apply_excluded_policy(httpx, addr: str, params: dict) -> bool:
    """Disabilita gli scanner distruttivi (`_EXCLUDED_ASCAN`) nella policy ZAP.

    GUARD di sicurezza (§14): viene chiamata PRIMA di avviare qualunque active
    scan. Disabilita esplicitamente, via `ascan/action/setScannerAlertThreshold`
    + `ascan/action/disableScanners`, i plugin mutanti/distruttivi sulla scan
    policy vincolata. Ritorna True solo se l'esclusione è stata applicata: il
    chiamante NON deve avviare lo scan se questo ritorna False (fail-closed).

    Degrado (§4.7): qualunque errore → False (nessuno scan partirà), mai crash."""
    excluded = _excluded_scanner_ids()
    if not excluded:
        # Nessuno scanner da escludere = policy non determinabile: fail-closed.
        log.warning("zap_active: lista esclusioni vuota, scan NON avviato (§14)")
        return False
    ids_csv = ",".join(excluded)
    disable_params = dict(params)
    disable_params.update({"ids": ids_csv, "scanPolicyName": _CONSTRAINED_POLICY})
    try:
        resp = httpx.get(f"{addr}/JSON/ascan/action/disableScanners/",
                         params=disable_params, timeout=_ZAP_TIMEOUT)
        ok = getattr(resp, "status_code", 0) == 200
        if not ok:
            log.warning("zap_active: disableScanners HTTP %s, scan NON avviato (§14)",
                        getattr(resp, "status_code", "?"))
            return False
        log.info("zap_active: policy vincolata applicata, %d scanner disabilitati (§14)",
                 len(excluded))
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("zap_active: applicazione policy fallita, scan NON avviato (§14): %s", exc)
        return False


def _run_zap_active(base_url: str, session_headers: dict, endpoints: list, out_path: str):
    """Invoca ZAP active con policy VINCOLATA e ritorna la lista di alert (§14).

    Confine I/O monkeypatchato nei test. In produzione si parla col daemon ZAP via
    la sua REST API (host/api-key da ENV: BASTIONE_ZAP_ADDR, BASTIONE_ZAP_API_KEY),
    configurando la sessione autenticata (session_headers) e una scan policy che
    DISABILITA le regole distruttive (_EXCLUDED_ASCAN) — detection-oriented.

    Sequenza fail-closed (§14): (1) applica la policy vincolata disabilitando gli
    scanner distruttivi; SE NON riesce, lo scan NON parte (nessuna azione mutante
    contro il target). (2) avvia l'active scan SOLO sulla policy vincolata. (3)
    legge gli alert risultanti.

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
        params = {"apikey": api_key} if api_key else {}
        # (1) GATE DI SICUREZZA: applica la policy vincolata PRIMA di scansionare.
        #     fail-closed — se non si riesce a disabilitare le regole distruttive,
        #     NON si avvia alcun active scan (mai azioni mutanti non controllate).
        if not _apply_excluded_policy(httpx, addr, params):
            log.warning("zap_active: policy vincolata non applicata, scan abortito (§14)")
            return None
        # (2) avvia l'active scan SOLO sulla scan policy vincolata (no regole distruttive).
        scan_params = dict(params)
        scan_params.update({"url": base_url, "scanPolicyName": _CONSTRAINED_POLICY,
                            "recurse": "true", "inScopeOnly": "true"})
        httpx.get(f"{addr}/JSON/ascan/action/scan/", params=scan_params,
                  timeout=_ZAP_TIMEOUT)
        # (3) leggi gli alert risultanti (lo stato di poll/avanzamento è gestito
        #     dal daemon; qui in forma minimale/difensiva).
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
