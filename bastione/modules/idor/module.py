"""IdorModule — probe cross-tenant / IDOR autenticato (M4.1).

Attaccante autorizzato: con due account di TEST owned (A, B) prova a violare
l'isolamento tra tenant. READ a PROBE (B/anon legge i dati di A), WRITE a MUTATING
su risorsa-canary usa-e-getta creata da A (mai dati reali), con cleanup garantito
(§11.2). Oracolo riusa §15 (endpoint dichiarati pubblici → soppressi). P8: mai i
valori-dato di A né i token in un campo Finding. Tutto offline-testabile: il confine
I/O `_http_request` è monkeypatchato nei test.

Guardrail §7/§28: niente bypass auth, niente brute-force; login SOLO con le
credenziali di test fornite via ENV. WRITE gate-first `authorize(MUTATING, ctx)`."""
from __future__ import annotations

import hashlib
import logging

from bastione.auth.session import acquire_session
from bastione.enums import Confidence, IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, authorize
from bastione.models import (
    AuthSession, Finding, Fingerprint, Location, ModuleResult, PostureCheck,
    RunContext, TargetConfig,
)
from bastione.modules.base import Module, register

log = logging.getLogger("bastione.modules.idor")
_HTTP_TIMEOUT = 15.0


def _http_request(method: str, url: str, *, json=None, headers=None):
    """Confine I/O (monkeypatchato nei test). Ritorna response o None (§4.7)."""
    try:
        import httpx
    except ImportError:
        log.warning("httpx non installato: idor non disponibile (M4.1)")
        return None
    try:
        return httpx.request(method, url, json=json, headers=headers,
                             timeout=_HTTP_TIMEOUT, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        log.warning("idor %s %s fallita: %s", method, url, exc)
        return None


def _finding_id(module: str, rule_id: str, location: Location) -> str:
    """finding_id stabile (§16, LOCKED)."""
    raw = f"{module}:{rule_id}:{location.canonical()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@register
class IdorModule(Module):
    """Probe cross-tenant / IDOR autenticato (M4.1). MUTATING 🔴 (il WRITE)."""

    name = "idor"
    max_intrusion = IntrusionLevel.MUTATING

    _CANARY_MARKER = "bastione-idor-canary"

    def should_run(self, fp: Fingerprint, cfg: TargetConfig) -> bool:
        """Vero se ≥2 account di test E ≥1 endpoint API dichiarato (valutazione
        leggera, nessun I/O)."""
        auth = cfg.auth
        return bool(auth and len(auth.test_accounts) >= 2 and auth.api_endpoints)

    def run(self, ctx: RunContext) -> ModuleResult:
        """Self-gate → READ probe (PROBE) → WRITE canary (MUTATING). Sotto PROBE o
        senza ownership: `IDOR_SKIPPED` INFO, nessuna richiesta (M0 invariato)."""
        target = ctx.target_cfg.name
        if ctx.max_intrusion < IntrusionLevel.PROBE or not ctx.ownership_verified:
            return self._skipped(
                target,
                "idor richiede --max-intrusion >= probe e ownership verificata "
                "(§7): probe cross-tenant saltato, run read-only invariata.")
        from bastione.recon.api_surface import build_api_surface
        surface = build_api_surface(ctx.fingerprint, ctx.target_cfg)
        sessions = self._acquire_sessions(ctx)
        if sessions.get("A") is None or sessions.get("B") is None:
            return self._skipped(
                target,
                "sessioni di test A/B non acquisite (credenziali env assenti?): "
                "probe saltato.")
        findings: list[Finding] = []
        posture: list[PostureCheck] = []
        self._read_probe(ctx, surface, sessions, findings, posture)
        self._write_probe(ctx, surface, sessions, findings, posture)
        return ModuleResult(findings=findings, posture_checks=posture)

    # ── acquisizione sessioni ────────────────────────────────────────────────

    def _acquire_sessions(self, ctx: RunContext) -> dict[str, "AuthSession | None"]:
        out: dict[str, AuthSession | None] = {"anon": None}
        for acc in ctx.target_cfg.auth.test_accounts:
            sess = acquire_session(acc)
            out[acc.label] = sess if sess.acquired_ok else None
        return out

    def _request(self, method: str, url: str, sess: "AuthSession | None"):
        headers = dict(sess.headers) if sess else {}
        return _http_request(method, url, headers=headers)

    def _request_json(self, method, url, sess, body):
        headers = dict(sess.headers) if sess else {}
        return _http_request(method, url, json=body, headers=headers)

    # ── READ cross-tenant probe + oracolo isolamento (§15) ───────────────────

    def _read_probe(self, ctx, surface, sessions, findings, posture) -> None:
        base = ctx.target_cfg.base_url.rstrip("/")
        a = sessions["A"]
        public = set((ctx.target_cfg.auth.public_endpoints or []))
        # 1) come A: raccogli gli URL risorsa leggibili (list/read)
        a_urls: list[str] = []
        for ep in surface.endpoints:
            if ep.kind not in ("list", "read"):
                continue
            url = base + ep.path_template
            if "{id}" in ep.path_template:
                continue  # gli ID concreti vengono dalla list (sotto)
            resp = self._request("GET", url, a)
            if resp is not None and getattr(resp, "status_code", 0) == 200:
                a_urls.append(url)
                for rid in self._ids_from(resp):
                    for read_ep in surface.endpoints:
                        if read_ep.kind == "read" and "{id}" in read_ep.path_template:
                            a_urls.append(base + read_ep.path_template.replace("{id}", str(rid)))
        # 2) rigioca come B e anon
        for url in dict.fromkeys(a_urls):  # dedup, ordine stabile
            path = url[len(base):]
            if self._is_public(path, public):
                posture.append(self._isolation_posture(path, ctx.target_cfg.name, suppressed=True))
                continue
            leaked_by = None
            for role in ("B", "anon"):
                resp = self._request("GET", url, sessions.get(role))
                if resp is not None and getattr(resp, "status_code", 0) == 200 \
                        and self._nonempty(resp):
                    leaked_by = role
                    break
            if leaked_by:
                findings.append(self._read_finding(path, leaked_by, ctx.target_cfg.name))
            else:
                posture.append(self._isolation_posture(path, ctx.target_cfg.name, suppressed=False))

    @staticmethod
    def _ids_from(resp) -> list:
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return []
        if isinstance(body, list):
            return [r.get("id") for r in body if isinstance(r, dict) and r.get("id") is not None]
        return []

    @staticmethod
    def _nonempty(resp) -> bool:
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return False
        return bool(body)

    @staticmethod
    def _is_public(path: str, public: set[str]) -> bool:
        for p in public:
            if p.endswith("*") and path.startswith(p[:-1]):
                return True
            if path == p:
                return True
        return False

    def _read_finding(self, path: str, role: str, target: str) -> Finding:
        location = Location(endpoint=path)
        attacker = "anonimo (non autenticato)" if role == "anon" else "un altro utente (B)"
        # P8: SOLO path + ruolo, mai i dati di A.
        evidence = f"GET {path} accessibile a {attacker} (risorsa di un altro tenant)"
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CROSS_TENANT_READ", location),
            module="idor", rule_id="IDOR_CROSS_TENANT_READ",
            title=f"Lettura cross-tenant su {path}",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location, evidence=evidence,
            description=(f"Una richiesta GET a {path} eseguita come {attacker} restituisce "
                         "i dati appartenenti a un altro tenant: l'autorizzazione lato server "
                         "non isola i tenant (Broken Access Control, OWASP A01). Il valore dei "
                         "dati NON è incluso qui (P8). Verifica la authz dell'endpoint."),
            remediation_ref="IDOR_CROSS_TENANT_READ", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.PROBE)

    @staticmethod
    def _isolation_posture(path: str, target: str, *, suppressed: bool) -> PostureCheck:
        detail = ("endpoint dichiarato pubblico (§15): isolamento non richiesto"
                  if suppressed else "B/anon non accedono alle risorse di A")
        return PostureCheck(
            check_id=f"POSTURE_TENANT_ISOLATION_{path}",
            title=f"Isolamento tenant su {path}", passed=True,
            severity_if_failed=Severity.CRITICAL, target=target, detail=detail,
            remediation_ref="IDOR_CROSS_TENANT_READ")

    # ── WRITE cross-tenant — canary usa-e-getta + cleanup garantito (§11.2) ──

    def _write_probe(self, ctx, surface, sessions, findings, posture) -> None:
        # SELF-GATE: niente WRITE se il tetto non è MUTATING (read-only invariato).
        if ctx.max_intrusion < IntrusionLevel.MUTATING:
            return
        # GATE-FIRST: authorize PRIMA di qualsiasi scrittura. Propaga IntrusionDenied
        # (la run aborta, non si declassa — §7/§22).
        authorize(IntrusionLevel.MUTATING, ctx)

        base = ctx.target_cfg.base_url.rstrip("/")
        target = ctx.target_cfg.name
        create_ep = next((e for e in surface.endpoints if e.kind == "create"), None)
        delete_ep = next((e for e in surface.endpoints if e.kind == "delete"), None)
        if create_ep is None or delete_ep is None:
            findings.append(self._write_skipped_no_canary(target))
            return

        a, b = sessions["A"], sessions["B"]
        # 1) come A: crea la canary usa-e-getta (marker, mai dati reali)
        resp = self._request_json("POST", base + create_ep.path_template, a,
                                  {"title": self._CANARY_MARKER})
        canary_id = self._id_from(resp)
        if canary_id is None:
            findings.append(self._write_skipped_no_canary(target))
            return
        canary_url = base + delete_ep.path_template.replace("{id}", str(canary_id))
        read_url = canary_url  # GET come A per verificare persistenza/cleanup
        cleaned = False
        try:
            # 2) come B: prova a CANCELLARE la canary di A
            del_b = self._request("DELETE", canary_url, b)
            if del_b is not None and getattr(del_b, "status_code", 0) in (200, 204):
                # verifica che sia DAVVERO sparita (riletta come A)
                check = self._request("GET", read_url, a)
                gone = check is not None and getattr(check, "status_code", 0) == 404
                if gone:
                    cleaned = True  # B l'ha cancellata → niente da ripulire
                    findings.append(self._write_finding(delete_ep.path_template, target))
        finally:
            # 3) cleanup GARANTITO come A (se non già cancellata da B)
            if not cleaned:
                dc = self._request("DELETE", canary_url, a)
                ok = dc is not None and getattr(dc, "status_code", 0) in (200, 204)
                if not ok:
                    findings.append(self._cleanup_failed(delete_ep.path_template,
                                                         canary_id, target))

    @staticmethod
    def _id_from(resp):
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return None
        return body.get("id") if isinstance(body, dict) else None

    def _write_finding(self, path_template: str, target: str) -> Finding:
        location = Location(endpoint=path_template)
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CROSS_TENANT_WRITE", location),
            module="idor", rule_id="IDOR_CROSS_TENANT_WRITE",
            title=f"Scrittura cross-tenant su {path_template}",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence=(f"DELETE {path_template} su una risorsa-canary di A è stato accettato "
                      "come utente B (modifica cross-tenant)"),
            description=("Un altro utente (B) ha potuto cancellare/modificare una risorsa "
                         "creata da A: l'authz di scrittura non isola i tenant (Broken Access "
                         "Control, OWASP A01). Testato su risorsa-canary usa-e-getta (mai dati "
                         "reali). Il caso peggiore di IDOR: distruzione/manomissione dati. (P8)"),
            remediation_ref="IDOR_CROSS_TENANT_WRITE", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING)

    def _cleanup_failed(self, path_template: str, canary_id, target: str) -> Finding:
        location = Location(endpoint=path_template)
        return Finding(
            finding_id=_finding_id("idor", "IDOR_CLEANUP_FAILED", location),
            module="idor", rule_id="IDOR_CLEANUP_FAILED",
            title="Cleanup della canary IDOR non confermato (rimozione manuale)",
            severity=Severity.CRITICAL, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence=(f"canary id={canary_id} su {path_template}: DELETE di cleanup non "
                      f"confermato. Rimozione manuale: DELETE {path_template} (id={canary_id})."),
            description=("Il probe WRITE ha creato una risorsa-canary ma il cleanup automatico "
                         f"NON è confermato. Resta una canary da rimuovere a mano (id={canary_id}, "
                         f"marker '{self._CANARY_MARKER}'). (§11.2)"),
            remediation_ref="IDOR_CROSS_TENANT_WRITE", owasp=["A01:2021"],
            intrusion_used=IntrusionLevel.MUTATING)

    def _write_skipped_no_canary(self, target: str) -> Finding:
        location = Location(endpoint="idor-write")
        return Finding(
            finding_id=_finding_id("idor", "IDOR_WRITE_SKIPPED_NO_CANARY", location),
            module="idor", rule_id="IDOR_WRITE_SKIPPED_NO_CANARY",
            title="Probe WRITE IDOR saltato: nessun endpoint create dichiarato",
            severity=Severity.INFO, confidence=Confidence.FIRM,
            target=target, location=location,
            evidence="nessun endpoint kind='create' (+ 'delete') dichiarato in [auth]",
            description=("Il probe WRITE cross-tenant è stato SALTATO: senza un endpoint "
                         "'create' (per la canary) e 'delete', non si testa la scrittura alla "
                         "cieca (cleanup-safe §11.2). Verifica INCOMPLETA, dichiarata (§4.7)."),
            intrusion_used=IntrusionLevel.READ_ONLY)

    # ── SKIPPED (§4.7/§26) ───────────────────────────────────────────────────

    def _skipped(self, target: str, motivo: str) -> ModuleResult:
        """Finding INFO `IDOR_SKIPPED` (§4.7/§26): skip DICHIARATO, non nascosto."""
        location = Location(endpoint="idor")
        finding = Finding(
            finding_id=_finding_id("idor", "IDOR_SKIPPED", location),
            module="idor", rule_id="IDOR_SKIPPED",
            title="Probe IDOR saltato",
            severity=Severity.INFO, confidence=Confidence.FIRM,
            target=target, location=location, evidence=motivo,
            description=(f"Il probe IDOR (M4.1) è stato saltato: {motivo} "
                         "Skip dichiarato esplicitamente (§4.7/§26): verifica NON eseguita."),
            intrusion_used=IntrusionLevel.READ_ONLY)
        return ModuleResult(findings=[finding], posture_checks=[])
