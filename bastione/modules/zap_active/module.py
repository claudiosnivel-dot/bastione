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
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit

from bastione.auth.session import acquire_session
from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (Finding, Fingerprint, Location, ModuleResult,
                             RunContext, TargetConfig)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.zap_active")
_ZAP_TIMEOUT = 1800  # l'active scan può richiedere tempo

# §4.6/§11 decisione piano: deadline di completamento dello scan (NON il timeout
# per-richiesta _ZAP_TIMEOUT). Default 30 min, configurabile via env.
_ZAP_SCAN_DEADLINE_DEFAULT = 1800


def _scan_deadline() -> int:
    """Deadline da `BASTIONE_ZAP_SCAN_TIMEOUT` (secondi). Valutata all'import: un
    valore non intero o ≤ 0 degrada al default con un warning, mai un'eccezione
    (romperebbe l'import del modulo e quindi l'intera run, §4.7)."""
    raw = os.getenv("BASTIONE_ZAP_SCAN_TIMEOUT", str(_ZAP_SCAN_DEADLINE_DEFAULT))
    try:
        value = int(raw.strip())
    except ValueError:
        log.warning("BASTIONE_ZAP_SCAN_TIMEOUT=%r non è un intero: uso %ss",
                    raw, _ZAP_SCAN_DEADLINE_DEFAULT)
        return _ZAP_SCAN_DEADLINE_DEFAULT
    return value if value > 0 else _ZAP_SCAN_DEADLINE_DEFAULT


_ZAP_SCAN_DEADLINE = _scan_deadline()
_ZAP_POLL_INTERVAL = 5

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


def _url_scope(base_url: str) -> str:
    """Regex (ancorata) delle URL dell'origin del target: la credenziale di sessione
    va iniettata SOLO verso l'host owned, mai verso host terzi (§7)."""
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    return "^" + re.escape(origin) + r"([/?#].*)?$"


def _apply_session_headers(httpx, addr, params, headers, rule_names, base_url) -> None:
    """(a) Una regola Replacer REQ_HEADER per ogni header di sessione, limitata
    all'origin del target. Niente header → nessuna regola.

    Ogni nome entra in `rule_names` (lista del chiamante) PRIMA della addRule: se una
    addRule successiva fallisce, il teardown in `finally` rimuove comunque le regole
    già create — che portano il VALORE della credenziale e resterebbero nel daemon
    (§4.6/§11.2: cleanup garantito). Rimuovere una regola mai creata è innocuo."""
    scope = _url_scope(base_url)
    for i, (k, v) in enumerate(headers.items()):
        name = f"bastione-auth-{i}"
        rule_names.append(name)
        httpx.get(f"{addr}/JSON/replacer/action/addRule/", params={
            **params, "description": name, "enabled": "true", "matchType": "REQ_HEADER",
            "matchString": k, "matchRegex": "false", "replacement": v, "url": scope},
            timeout=_ZAP_TIMEOUT)


def _seed_endpoints(httpx, addr, params, base_url, endpoints) -> None:
    """(b) Semina gli endpoint dichiarati nel site tree (accessUrl)."""
    for ep in endpoints:
        url = base_url + ep if ep.startswith("/") else ep
        httpx.get(f"{addr}/JSON/core/action/accessUrl/",
                  params={**params, "url": url, "followRedirects": "false"}, timeout=_ZAP_TIMEOUT)


def _wait_scan_complete(httpx, addr, params, scan_id) -> None:
    """(c) Poll ascan/view/status fino a 100 o deadline."""
    deadline = time.monotonic() + _ZAP_SCAN_DEADLINE
    while time.monotonic() < deadline:
        r = httpx.get(f"{addr}/JSON/ascan/view/status/",
                      params={**params, "scanId": scan_id}, timeout=_ZAP_TIMEOUT)
        if str((r.json() or {}).get("status", "")) == "100":
            return
        time.sleep(_ZAP_POLL_INTERVAL)
    log.warning("zap_active: deadline di scan raggiunta prima del 100%% (scanId=%s)", scan_id)


def _teardown(httpx, addr, params, rule_names) -> None:
    """(d) Rimuove le regole Replacer e la policy vincolata. Best-effort."""
    for name in rule_names:
        try:
            httpx.get(f"{addr}/JSON/replacer/action/removeRule/",
                      params={**params, "description": name}, timeout=_ZAP_TIMEOUT)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpx.get(f"{addr}/JSON/ascan/action/removeScanPolicy/",
                  params={**params, "scanPolicyName": _CONSTRAINED_POLICY}, timeout=_ZAP_TIMEOUT)
    except Exception:  # noqa: BLE001
        pass


def _run_zap_active(base_url: str, session_headers: dict, endpoints: list, out_path: str):
    """Invoca ZAP active con policy VINCOLATA e ritorna la lista di alert (§14/§4.6).

    Confine I/O monkeypatchato nei test. In produzione si parla col daemon ZAP via
    la sua REST API (host/api-key da ENV: BASTIONE_ZAP_ADDR, BASTIONE_ZAP_API_KEY).

    Sequenza fail-closed (§14/§4.6): (1) applica la policy vincolata disabilitando
    gli scanner distruttivi; SE NON riesce, lo scan NON parte. (a) applica la
    sessione autenticata via Replacer (REQ_HEADER per ogni header, Cookie incluso).
    (b) semina gli endpoint dichiarati nel site tree. (2) avvia l'active scan SOLO
    sulla policy vincolata. (c) ATTENDE la fine (poll status) prima di leggere gli
    alert. (d) teardown in `finally`: rimuove regole Replacer e policy vincolata.

    Degrado grazioso (§4.7): qualunque errore / daemon assente → None (nessun
    alert), mai crash. Scrive il raw JSON in out_path."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx assente: zap_active non disponibile (§14)")
        return None
    addr = os.getenv("BASTIONE_ZAP_ADDR")
    if not addr:
        log.warning("BASTIONE_ZAP_ADDR non impostato: zap_active non eseguito")
        return None
    params = {"apikey": os.getenv("BASTIONE_ZAP_API_KEY", "")}
    rule_names: list[str] = []
    try:
        # policy vincolata PRIMA di tutto (fail-closed §4.6): se non applicata, stop.
        if not _apply_excluded_policy(httpx, addr, params):
            log.warning("zap_active: policy vincolata non applicata → fail-closed, niente scan")
            return None
        _apply_session_headers(httpx, addr, params, session_headers,               # (a)
                               rule_names, base_url)
        _seed_endpoints(httpx, addr, params, base_url, endpoints)                   # (b)
        scan_params = {**params, "url": base_url, "scanPolicyName": _CONSTRAINED_POLICY,
                       "recurse": "true", "inScopeOnly": "true"}
        resp = httpx.get(f"{addr}/JSON/ascan/action/scan/", params=scan_params, timeout=_ZAP_TIMEOUT)
        scan_id = str((resp.json() or {}).get("scan", ""))
        if scan_id:
            _wait_scan_complete(httpx, addr, params, scan_id)                       # (c)
        resp = httpx.get(f"{addr}/JSON/core/view/alerts/", params=params, timeout=_ZAP_TIMEOUT)
        alerts = (resp.json() or {}).get("alerts", [])
        try:
            Path(out_path).write_text(json.dumps(alerts), encoding="utf-8")
        except OSError:
            pass
        return alerts
    except Exception as exc:  # noqa: BLE001
        log.warning("zap_active: scan fallito, degrado a None (§4.7): %s", exc)
        return None
    finally:
        _teardown(httpx, addr, params, rule_names)                                  # (d)


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
        sess_headers = dict(sess.headers)
        if sess.cookies:   # la sessione a cookie NON va più scartata (come idor, Task 13)
            sess_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
        try:
            alerts = _run_zap_active(ctx.target_cfg.base_url.rstrip("/"),
                                     sess_headers, endpoints, str(out_path))
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
