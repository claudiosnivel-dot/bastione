"""Smoke test END-TO-END OFFLINE — il più vicino possibile alla DoD M0 (§3).

Obiettivo (BUILD CD): provare che
`bastione scan --target <t> --max-intrusion read-only` gira **end-to-end senza
crash** e produce i tre artefatti su disco (SARIF 2.1.0 + report.md + state.json),
esercitando il **PIPELINE VERO** (NON si monkeypatcha `Orchestrator.run`).

Approccio (il meno invasivo, documentato qui):
  - invochiamo il comando `scan` reale via `typer.testing.CliRunner`, così passiamo
    per TUTTO il cablaggio CLI→orchestratore→fasi→report (§25/§6/§23);
  - la CLI fa `Orchestrator()` con i path di default (runs/ baselines/ targets/);
    per non scrivere fuori da tmp, monkeypatchiamo `bastione.cli.Orchestrator` con
    una **factory** che costruisce il VERO `Orchestrator` con
    `targets_dir=tmp, runs_root=tmp, baselines_root=tmp`. È la sostituzione meno
    invasiva: la classe orchestratrice e tutte le sue fasi restano quelle reali —
    cambiano solo le directory di I/O, iniettate via costruttore;
  - nel tmp creiamo `targets/<nome>.toml` staging+owned con base_url fittizio
    (il gate in LOAD lo accetta: niente produzione, ownership dichiarata, §7).

Monkeypatchiamo SOLO i confini di rete (come fanno i test unitari di ogni modulo):
  - `bastione.orchestrator.fingerprint` → Fingerprint sintetico (is_supabase=True,
    anon_key valorizzata, resolved_urls + response_headers SENZA alcuni security
    header → il modulo headers emette dei fail) e scrive comunque `fingerprint.json`
    nel run_dir (come l'originale, per il --resume);
  - `bastione.modules.supabase.module._get` → schema OpenAPI con UNA tabella
    (colonna 'email') e RLS aperta (200 + righe) → Finding RLS_DISABLED;
  - `bastione.modules.secrets.module._fetch` → un bundle con un JWT service_role
    → Finding SECRET_SERVICE_ROLE (evidence redatta a monte, P8).

Asserzioni (DoD M0): exit 0; nel run_dir esistono bastione.sarif (SARIF 2.1.0
valido), report.md, state.json; state.json ha phases_completed con RECON..PERSIST
e posture_score valorizzato; il report.md contiene il finding RLS e lo score;
nessun segreto/valore di riga in chiaro negli artefatti (redazione P8).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

import bastione.cli as cli_mod
import bastione.modules.secrets.module as secrets_mod
import bastione.modules.supabase.module as supabase_mod
import bastione.orchestrator as orch_mod
from bastione.cli import app
from bastione.models import Fingerprint
from bastione.orchestrator import Orchestrator

runner = CliRunner()

TARGET = "gestionale"

# Config target staging+owned con base_url fittizio: il gate in LOAD la accetta
# (niente produzione, ownership dichiarata). base_url mai contattato — il recon è
# monkeypatchato (fingerprint sintetico), quindi l'URL resta puramente fittizio.
TARGET_TOML = (
    f'name = "{TARGET}"\n'
    'base_url = "https://staging.gestionale.example"\n'
    'environment = "staging"\n'
    'ownership = "owned"\n'
)

# URL Supabase fittizio (mai contattato: _get è monkeypatchato).
SUPABASE_URL = "https://abcdefghijklmnop.supabase.co"
BUNDLE_URL = "https://staging.gestionale.example/assets/app-deadbeef.js"

# Valori segreti che NON devono mai comparire in chiaro negli artefatti (P8).
# - ANON_KEY: pubblica per design, ma ne verifichiamo comunque l'assenza nei file;
# - SERVICE_ROLE_KEY: fuga CRITICA → redatta;
# - ROW_EMAIL: valore di riga letto via RLS aperta → MAI in evidence (solo conteggio
#   righe + nomi colonna, §11.1).
ROW_EMAIL = "mario.rossi@cliente-segreto.example"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(role: str) -> str:
    """JWT sintetico (header.payload.signature) con il claim `role` richiesto.
    Stesso schema usato dai test unitari del detector (§10)."""
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(json.dumps(
        {"iss": "supabase", "ref": "abcdefghijklmnop", "role": role,
         "iat": 1, "exp": 2}).encode())
    return f"{header}.{payload}.{_b64url(b'fakesig')}"


ANON_KEY = _make_jwt("anon")
SERVICE_ROLE_KEY = _make_jwt("service_role")


# ─── confini di rete sintetici (gli UNICI monkeypatch) ──────────────────────

def _fake_fingerprint(target: str, run_dir: Path | None = None) -> Fingerprint:
    """Sostituto OFFLINE di `recon.fingerprint` (§8): Fingerprint sintetico che
    riproduce uno staging Supabase reale.

    - is_supabase=True + anon_key valorizzata → il modulo supabase gira (should_run);
    - resolved_urls valorizzati → il modulo headers gira;
    - response_headers SENZA alcuni security header (manca CSP/HSTS/...) → headers
      emette dei PostureCheck failed;
    - come l'originale, scrive `fingerprint.json` nel run_dir (utile al --resume).
    """
    fp = Fingerprint(
        target=target,
        resolved_urls=[BUNDLE_URL.rsplit("/", 2)[0] + "/"],  # la pagina app
        response_headers={
            # volutamente incompleto: c'è solo XCTO, mancano HSTS/CSP/XFO/...
            "server": "nginx",
            "x-content-type-options": "nosniff",
        },
        is_supabase=True,
        supabase_url=SUPABASE_URL,
        anon_key=ANON_KEY,
        cloudflare_fronted=False,
    )
    if run_dir is not None:
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "fingerprint.json").write_text(
            fp.model_dump_json(indent=2), encoding="utf-8")
    return fp


def _fake_supabase_get(url: str, headers: dict[str, str]):
    """Sostituto OFFLINE del confine HTTP del modulo supabase (`_get`, §11.1).

    - GET <base>/rest/v1/  → schema OpenAPI PostgREST con UNA tabella `clienti`
      (colonna 'email' → euristica dati personali → CRITICAL + gdpr);
    - GET <base>/rest/v1/clienti?... → 200 con una riga NON vuota (RLS aperta).
    """
    if url.endswith("/rest/v1/"):
        schema = {
            "swagger": "2.0",
            "definitions": {
                "clienti": {
                    "properties": {
                        "id": {"type": "integer"},
                        "email": {"type": "string"},
                        "nome": {"type": "string"},
                    }
                }
            },
            "paths": {"/": {}, "/clienti": {}},
        }
        return SimpleNamespace(status_code=200, json=lambda: schema)
    if "/rest/v1/clienti" in url:
        # RLS aperta: l'anon legge una riga reale con un dato personale dentro.
        rows = [{"id": 1, "email": ROW_EMAIL, "nome": "Mario"}]
        return SimpleNamespace(status_code=200, json=lambda: rows)
    return SimpleNamespace(status_code=404, json=lambda: {})


def _fake_secrets_fetch(url: str):
    """Sostituto OFFLINE del confine HTTP del modulo secrets (`_fetch`, §10).

    - la PAGINA app → HTML che referenzia un bundle JS same-host (<script src>);
    - il BUNDLE JS → contiene una service_role key esposta (fuga CRITICA).
    """
    page_prefix = BUNDLE_URL.rsplit("/", 2)[0] + "/"
    if url == page_prefix:
        html = f'<html><body><script src="{BUNDLE_URL}"></script></body></html>'
        return SimpleNamespace(url=url, text=html)
    if url == BUNDLE_URL:
        js = (
            "const SUPABASE_URL=" + json.dumps(SUPABASE_URL) + ";"
            "const ANON=" + json.dumps(ANON_KEY) + ";"
            # service_role key esposta nel bundle: la fuga che il detector trova.
            "const SERVICE=" + json.dumps(SERVICE_ROLE_KEY) + ";"
        )
        return SimpleNamespace(url=url, text=js)
    return None


def _install_offline_boundaries(monkeypatch, tmp_path: Path) -> None:
    """Monkeypatcha SOLO i confini di rete + la factory Orchestrator della CLI.

    Tutto il resto (fasi, moduli, baseline, posture, SARIF, report) resta REALE.
    """
    # 1) RECON: fingerprint sintetico (con scrittura fingerprint.json).
    monkeypatch.setattr(orch_mod, "fingerprint", _fake_fingerprint, raising=True)
    # 2) SUPABASE: confine HTTP _get.
    monkeypatch.setattr(supabase_mod, "_get", _fake_supabase_get, raising=True)
    # 3) SECRETS: confine HTTP _fetch.
    monkeypatch.setattr(secrets_mod, "_fetch", _fake_secrets_fetch, raising=True)

    # 4) la CLI fa Orchestrator() coi path di default: lo rimpiazziamo con una
    #    factory che costruisce il VERO Orchestrator con i path dentro tmp_path.
    #    (Scelta meno invasiva: cambiano solo le directory di I/O, non la logica.)
    def _factory(*args, **kwargs):
        return Orchestrator(
            targets_dir=tmp_path,
            runs_root=tmp_path,
            baselines_root=tmp_path,
        )

    monkeypatch.setattr(cli_mod, "Orchestrator", _factory, raising=True)


# ─── lo smoke test END-TO-END ───────────────────────────────────────────────

def test_scan_end_to_end_produces_sarif_report_and_state(tmp_path: Path, monkeypatch):
    """DoD M0: `scan --max-intrusion read-only` gira end-to-end (pipeline reale) e
    produce bastione.sarif + report.md + state.json, senza crash e senza segreti
    in chiaro."""
    # config target nel tmp (la factory usa tmp_path come targets_dir)
    (tmp_path / f"{TARGET}.toml").write_text(TARGET_TOML, encoding="utf-8")
    _install_offline_boundaries(monkeypatch, tmp_path)

    result = runner.invoke(
        app, ["scan", "--target", TARGET, "--max-intrusion", "read-only"])

    # 1) exit 0: nessun crash, nessun gate scattato (read-only, niente --ci)
    assert result.exit_code == 0, result.output

    # 2) i tre artefatti esistono nel run_dir
    run_dirs = list((tmp_path / TARGET).glob("*/"))
    assert len(run_dirs) == 1, f"atteso un solo run_dir, trovati: {run_dirs}"
    run_dir = run_dirs[0]
    sarif_path = run_dir / "bastione.sarif"
    report_path = run_dir / "report.md"
    state_path = run_dir / "state.json"
    assert sarif_path.exists(), "bastione.sarif non prodotto"
    assert report_path.exists(), "report.md non prodotto"
    assert state_path.exists(), "state.json non prodotto"

    # 3) SARIF 2.1.0 valido + contiene le rule dei finding emessi
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"], "SARIF senza runs"
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "RLS_DISABLED" in rule_ids, "finding RLS assente dal SARIF"
    assert "SECRET_SERVICE_ROLE" in rule_ids, "finding service_role assente dal SARIF"

    # 4) state.json: phases_completed con RECON..PERSIST + posture_score valorizzato
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["schema"] == "bastione-state/1"
    for phase in ("RECON", "PLAN", "SCAN", "NORMALIZE",
                  "BASELINE", "POSTURE", "REPORT", "PERSIST"):
        assert phase in state["phases_completed"], f"{phase} non completata"
    assert state["posture_score"] is not None, "posture_score non valorizzato"
    # ≥2 finding NEW (RLS + service_role); il CRITICAL della tabella personale c'è
    assert state["counts"]["new"] >= 2
    assert state["counts"]["by_severity"]["critical"] >= 1

    # 5) il report cita il finding RLS e mostra lo score
    report = report_path.read_text(encoding="utf-8")
    assert "RLS_DISABLED" in report, "il report non cita il finding RLS"
    assert "SECRET_SERVICE_ROLE" in report, "il report non cita il finding service_role"
    assert "Posture Score" in report
    assert str(state["posture_score"]) in report, "lo score non compare nel report"

    # 6) REDAZIONE (P8): nessun segreto né valore di riga in chiaro negli artefatti.
    artifacts = "\n".join(
        p.read_text(encoding="utf-8")
        for p in (sarif_path, report_path, state_path)
    )
    assert SERVICE_ROLE_KEY not in artifacts, "service_role key in chiaro negli artefatti!"
    assert ROW_EMAIL not in artifacts, "valore di riga (email) in chiaro negli artefatti!"
    # anche la anon key (pubblica per design) non deve finire negli artefatti
    assert ANON_KEY not in artifacts, "anon key in chiaro negli artefatti!"


def test_scan_end_to_end_does_not_write_outside_tmp(tmp_path: Path, monkeypatch):
    """Difesa: la run NON deve scrivere fuori da tmp (niente runs/ baselines/ reali
    nel repo). Verifica che il run_dir reale sia sotto tmp e che lì ci siano i file."""
    (tmp_path / f"{TARGET}.toml").write_text(TARGET_TOML, encoding="utf-8")
    _install_offline_boundaries(monkeypatch, tmp_path)

    result = runner.invoke(app, ["scan", "--target", TARGET])
    assert result.exit_code == 0, result.output

    # il run_dir reale (orch._run_dir) è dentro tmp: lo verifichiamo via il path
    # stampato nel sommario (la CLI stampa run_dir + i file).
    run_dirs = list((tmp_path / TARGET).glob("*/"))
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    assert str(tmp_path) in str(run_dir.resolve())
    assert (run_dir / "fingerprint.json").exists(), "fingerprint.json non scritto dal RECON"
