"""CLI di Bastione (§25) — il guscio `typer` sopra l'orchestratore (step 15).

La CLI **non** orchestra né bypassa nulla: cabla soltanto i comandi dell'utente
sull'`Orchestrator` (§6) e ne presenta i risultati con `rich`. Le regole di
sicurezza restano dove devono stare: il gate (§7, fase LOAD) è l'autorità — la CLI
non declassa e non aggira (GUARDRAIL LOCKED). In M0 il default è **READ_ONLY**.

Comandi M0 (§25):
  - `scan`          : esegue una run sull'orchestratore e stampa il sommario;
  - `doctor`        : verifica quali tool esterni / lib opzionali sono presenti;
  - `list-modules`  : elenca i moduli registrati (§9);
  - `list-detectors`: elenca i detector di segreti registrati (§10).

Vincoli M0 (LOCKED):
  - `--unsafe-show-secrets` è INCOMPATIBILE con `--ci` (un CI non deve mai stampare
    segreti in chiaro): combinazione → errore, exit ≠ 0 (P8/§25);
  - i flag M1/M2 (`--no-fix` remediation, `--i-own-this-its-staging`) sono
    ACCETTATI ma in M0 read-only sono **no-op** con una nota (nessuna scrittura);
  - `--fail-on` / `--ci`: dopo la run, se ≥1 finding emesso ha severity ≥ soglia →
    exit 1 (gate CI minimale §22); altrimenti 0.

Gestione errori (§25): un `IntrusionDenied` dal gate produce un messaggio chiaro e
un exit code ≠ 0 — MAI uno stacktrace in faccia all'utente.
"""

from __future__ import annotations

import logging
import os
import shutil
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bastione.baseline.diff import (
    accept_finding,
    load_baseline,
    save_baseline,
)
from bastione.enums import IntrusionLevel, Severity
from bastione.gate import IntrusionDenied, PreconditionDenied
from bastione.orchestrator import (
    DEFAULT_BASELINES_ROOT,
    REPORT_FILENAME,
    SARIF_FILENAME,
    Orchestrator,
    _ensure_modules_loaded,
)
from bastione.state import RunState

log = logging.getLogger("bastione.cli")

app = typer.Typer(
    add_completion=False,
    help="Bastione (BAS) — orchestratore di security testing difensivo (§25).",
)

console = Console()
err_console = Console(stderr=True)

# Tool esterni opzionali sondati da `doctor` (§24): l'assenza degrada il recon
# (§8), non è un errore — è proprio lo scopo del comando rilevarla.
_EXTERNAL_TOOLS = ["whatweb", "katana", "testssl.sh", "nuclei", "zap"]


class IntrusionChoice(str, Enum):
    """Valori ammessi da `--max-intrusion` (§25). Stringhe stabili in CLI,
    mappate a `IntrusionLevel` (enum di dominio, §5.1) prima della run."""

    READ_ONLY = "read-only"
    PROBE = "probe"
    MUTATING = "mutating"


class FailOnChoice(str, Enum):
    """Soglia di `--fail-on` (§22/§25): nome di severità (case CLI)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Mapping stringa CLI → enum di dominio (§5.1). Tenuto esplicito: la CLI parla
# stringhe, il dominio parla enum ordinabili.
_CLI_TO_INTRUSION = {
    IntrusionChoice.READ_ONLY: IntrusionLevel.READ_ONLY,
    IntrusionChoice.PROBE: IntrusionLevel.PROBE,
    IntrusionChoice.MUTATING: IntrusionLevel.MUTATING,
}

_CLI_TO_SEVERITY = {
    FailOnChoice.INFO: Severity.INFO,
    FailOnChoice.LOW: Severity.LOW,
    FailOnChoice.MEDIUM: Severity.MEDIUM,
    FailOnChoice.HIGH: Severity.HIGH,
    FailOnChoice.CRITICAL: Severity.CRITICAL,
}

# Soglia di default per `--ci` quando `--fail-on` non è specificato (§22): un CI
# senza soglia esplicita fallisce su HIGH/CRITICAL.
_CI_DEFAULT_THRESHOLD = Severity.HIGH


# ─── scan (§25) ──────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Nome del target (config in targets/)."),
    max_intrusion: IntrusionChoice = typer.Option(
        IntrusionChoice.READ_ONLY, "--max-intrusion",
        help="Tetto di intrusione della run (§7). M0 default: read-only."),
    resume: bool = typer.Option(
        False, "--resume", help="Riprende l'ultima run del target (§24)."),
    accept_baseline: bool = typer.Option(
        False, "--accept-baseline", help="Promuove i finding NEW a KNOWN (§16)."),
    fail_on: FailOnChoice | None = typer.Option(
        None, "--fail-on",
        help="Exit 1 se ≥1 finding ha severity ≥ soglia (gate CI §22)."),
    ci: bool = typer.Option(
        False, "--ci",
        help="Modalità CI: attiva il gate exit-code (§22). Incompatibile con --unsafe-show-secrets."),
    unsafe_show_secrets: bool = typer.Option(
        False, "--unsafe-show-secrets",
        help="Mostra i segreti in chiaro (P8). INCOMPATIBILE con --ci."),
    no_fix: bool = typer.Option(
        False, "--no-fix", help="[M1] Disabilita la remediation. In M0 è no-op."),
    i_own_this_its_staging: bool = typer.Option(
        False, "--i-own-this-its-staging",
        help="[M2] Conferma ownership per scritture su staging. In M0 è no-op."),
) -> None:
    """Esegue una scansione difensiva del target e ne stampa il sommario (§6/§25).

    In M0 la run è interamente READ_ONLY: nessuna scrittura sul target. Il gate
    (§7) resta l'autorità: una config di produzione/non-posseduta fa abortire la
    run con un messaggio chiaro (gestito sotto come `IntrusionDenied`)."""
    # Vincolo LOCKED (P8/§25): un CI non deve MAI stampare segreti in chiaro.
    if unsafe_show_secrets and ci:
        err_console.print(
            "[bold red]Errore:[/] --unsafe-show-secrets è incompatibile con --ci: "
            "un'esecuzione CI non deve mai stampare segreti in chiaro (P8/§25).")
        raise typer.Exit(code=2)

    # Flag M1/M2: accettati ma no-op in M0 (read-only). Nota esplicita, non azione.
    if no_fix:
        console.print("[dim]nota:[/] --no-fix è un no-op in M0 (remediation arriva a M1).")
    if i_own_this_its_staging:
        console.print(
            "[dim]nota:[/] --i-own-this-its-staging è un no-op in M0 "
            "(le scritture canary arrivano a M2).")
    if unsafe_show_secrets:
        console.print(
            "[dim]nota:[/] --unsafe-show-secrets: la de-redazione dell'evidence è "
            "M1; in M0 i segreti restano redatti nei file (P8).")

    level = _CLI_TO_INTRUSION[max_intrusion]

    orch = Orchestrator()
    try:
        state = orch.run(
            target,
            max_intrusion=level,
            resume=resume,
            accept_baseline=accept_baseline,
        )
    except PreconditionDenied as exc:
        # Precondizione di LOAD non soddisfatta (produzione bloccata o ownership
        # non dichiarata): per §22 (LOCKED) è exit 2 (errore config/precondizione),
        # NON il 3 dell'ownership challenge. In M0 read-only è l'unico ramo del gate
        # raggiungibile. Catturato PRIMA di IntrusionDenied (ne è sottoclasse).
        err_console.print(f"[bold red]Precondizione negata dal gate (§7):[/] {exc}")
        raise typer.Exit(code=2)
    except IntrusionDenied as exc:
        # Ownership challenge fallito (§7.1) o altra negazione del gate runtime:
        # per §22 (LOCKED) è exit 3. Messaggio chiaro, niente stacktrace (§25).
        err_console.print(f"[bold red]Run negata dal gate (§7):[/] {exc}")
        raise typer.Exit(code=3)
    except FileNotFoundError as exc:
        # Config target assente (§6 LOAD): errore chiaro, non uno stacktrace.
        err_console.print(f"[bold red]Config target non trovata:[/] {exc}")
        raise typer.Exit(code=4)

    _print_summary(state, orch._run_dir)

    # Gate CI (§22, LOCKED): se --fail-on o --ci, exit 1 quando ≥1 finding NEW ≥
    # soglia OPPURE ≥1 DRIFT. KNOWN/ACCEPTED ≥ soglia NON fanno fallire il gate
    # (in CI la baseline è committata: i noti sono lo scenario normale, §24).
    threshold = _resolve_threshold(fail_on, ci)
    if threshold is not None and _ci_gate_failed(state, threshold):
        console.print(
            f"[bold red]CI gate:[/] rilevato ≥1 finding NEW con severity ≥ "
            f"{threshold.name} oppure ≥1 DRIFT → exit 1 (§22).")
        raise typer.Exit(code=1)


def _resolve_threshold(fail_on: FailOnChoice | None, ci: bool) -> Severity | None:
    """Determina la soglia effettiva del gate CI (§22). `--fail-on` ha la
    precedenza; `--ci` senza `--fail-on` usa il default HIGH. Senza nessuno dei
    due il gate è disattivo (None → exit 0 a prescindere dai finding)."""
    if fail_on is not None:
        return _CLI_TO_SEVERITY[fail_on]
    if ci:
        return _CI_DEFAULT_THRESHOLD
    return None


def _ci_gate_failed(state: RunState, threshold: Severity) -> bool:
    """True se il gate CI (§22, LOCKED) deve fallire: ≥1 finding NEW ≥ soglia
    OPPURE ≥1 DRIFT.

    Due deviazioni rispetto al "qualsiasi finding emesso ≥ soglia":
    - la soglia guarda i SOLI NEW (`counts.new_by_severity`), non tutti gli emessi:
      KNOWN/ACCEPTED ≥ soglia sono lo scenario normale in CI (baseline committata,
      §24) e non devono bloccare il deploy;
    - il DRIFT (regressione di posture, `counts.drift`) fa fallire il gate da solo,
      anche senza alcun NEW ≥ soglia (§22 riga 884)."""
    counts = state.counts
    if counts.get("drift", 0) > 0:
        return True
    new_by_sev = counts.get("new_by_severity", {})
    for sev in Severity:
        if sev >= threshold and new_by_sev.get(sev.name.lower(), 0) > 0:
            return True
    return False


def _print_summary(state: RunState, run_dir: Path) -> None:
    """Stampa il sommario di una run (§23/§25): posture score, counts per stato e
    per severità, e i path degli artefatti (run_dir + SARIF + report)."""
    score = state.posture_score if state.posture_score is not None else 0.0
    console.print()
    console.print(f"[bold]Bastione[/] — sommario run su [cyan]{state.target}[/]")
    console.print(f"Posture score: [bold]{score:.1f}[/] / 100  "
                  f"(intrusione: {state.max_intrusion})")

    counts = state.counts
    status_table = Table(title="Finding per stato", show_header=True, header_style="bold")
    status_table.add_column("stato")
    status_table.add_column("conteggio", justify="right")
    for key in ("new", "known", "fixed", "drift"):
        status_table.add_row(key, str(counts.get(key, 0)))
    console.print(status_table)

    by_sev = counts.get("by_severity", {})
    sev_table = Table(title="Finding per severità", show_header=True, header_style="bold")
    sev_table.add_column("severità")
    sev_table.add_column("conteggio", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_table.add_row(sev, str(by_sev.get(sev, 0)))
    console.print(sev_table)

    console.print(f"Artefatti in: [cyan]{run_dir}[/]")
    console.print(f"  • SARIF : {run_dir / SARIF_FILENAME}")
    console.print(f"  • Report: {run_dir / REPORT_FILENAME}")


# ─── baseline (§25 riga 946 / §16 gradino 2) ─────────────────────────────────

def _validate_target_name(target: str) -> None:
    """Rifiuta nomi di target che evaderebbero la baselines root (path traversal).

    A differenza di `scan` — protetto a monte da `load_target`/`resolve_target_path`
    (§7 fase LOAD), che fallisce su un target inesistente PRIMA di toccare la
    baseline — il comando `baseline` opera direttamente sul path. Senza questa
    guardia un `--target ../../x` farebbe uscire `--reset` (unlink) e `--accept`
    (write) dalla root: una cancellazione/scrittura distruttiva fuori dalla
    directory prevista (GUARDRAIL LOCKED: tocca SOLO il file baseline locale).

    Rifiuta separatori di percorso, componenti `..`/`.` e NUL → messaggio chiaro
    + exit 2 (niente stacktrace, §25). Nessun I/O qui: la guardia precede ogni
    accesso al filesystem."""
    invalid = (
        not target
        or os.sep in target
        or (os.altsep is not None and os.altsep in target)
        or "\x00" in target
        or target in {".", ".."}
        or ".." in Path(target).parts
    )
    if invalid:
        err_console.print(
            f"[bold red]Errore:[/] target non valido: [bold]{target!r}[/]. "
            "Il nome del target non può contenere separatori di percorso né "
            "componenti '..' (la baseline vive in baselines/<target>.baseline.json).")
        raise typer.Exit(code=2)


def _baseline_path(baselines_dir: Path | None, target: str) -> Path:
    """Path della baseline del target (§16). Usa lo STESSO formato/root di
    `scan --accept-baseline` (`DEFAULT_BASELINES_ROOT`, orchestrator.py) così i due
    gradini operano sullo stesso file. `--baselines-dir` (nascosto) lo redirige a
    una dir temporanea nei test."""
    root = baselines_dir if baselines_dir is not None else DEFAULT_BASELINES_ROOT
    return root / f"{target}.baseline.json"


@app.command()
def baseline(
    target: str = typer.Option(..., "--target", help="Nome del target (baselines/<target>.baseline.json)."),
    show: bool = typer.Option(
        False, "--show", help="Stampa il contenuto della baseline (default se nessuna opzione)."),
    reset: bool = typer.Option(
        False, "--reset", help="Cancella il file baseline del target (azione deliberata, non interattiva)."),
    accept: str | None = typer.Option(
        None, "--accept", metavar="FINDING_ID",
        help="Promuove un singolo finding KNOWN→ACCEPTED (gradino 2, §16)."),
    baselines_dir: Path | None = typer.Option(
        None, "--baselines-dir", hidden=True,
        help="Override della root delle baseline (uso interno/test)."),
) -> None:
    """Gestisce la baseline locale del target (§25/§16): mostra, resetta o accetta.

    Comando LOCALE e READ-ONLY rispetto al target: tocca SOLO il file baseline JSON
    (mai rete, mai il target). Le tre azioni sono mutuamente esclusive. Il file
    contiene SOLO finding_id/status/date/rule_id/module + esito booleano dei posture
    check — mai evidenze (L05)."""
    # Mutua esclusione (§25): al più UNA delle tre opzioni.
    chosen = [name for name, on in
              (("--show", show), ("--reset", reset), ("--accept", accept is not None)) if on]
    if len(chosen) > 1:
        err_console.print(
            f"[bold red]Errore:[/] {', '.join(chosen)} sono mutuamente esclusive: "
            "scegline una sola (§25).")
        raise typer.Exit(code=2)

    # Guardia path-traversal (GUARDRAIL LOCKED): rifiuta target che evaderebbero la
    # baselines root PRIMA di qualsiasi I/O (reset/unlink, accept/write, show/read).
    _validate_target_name(target)

    path = _baseline_path(baselines_dir, target)

    if reset:
        _baseline_reset(target, path)
    elif accept is not None:
        _baseline_accept(target, path, accept)
    else:
        # --show esplicito oppure default (nessuna opzione data).
        _baseline_show(target, path)


def _baseline_show(target: str, path: Path) -> None:
    """`--show` (§25): stampa header + tabella finding + tabella posture. Se il file
    non esiste → messaggio amichevole, exit 0 (non è un errore: la baseline si crea
    con `scan --accept-baseline`)."""
    if not path.exists():
        console.print(f"[yellow]Nessuna baseline per[/] [cyan]{target}[/] "
                      f"(atteso in {path}). Creala con [bold]scan --accept-baseline[/].")
        return

    bl = load_baseline(path)
    console.print()
    console.print(f"[bold]Baseline[/] di [cyan]{bl.get('target') or target}[/]  "
                  f"updated_at: {bl.get('updated_at') or '—'}")

    findings = bl.get("findings", {})
    f_table = Table(title="Finding", show_header=True, header_style="bold")
    for col in ("finding_id", "status", "first_seen", "last_seen", "rule_id", "module"):
        f_table.add_column(col)
    for fid, entry in findings.items():
        entry = entry if isinstance(entry, dict) else {}
        f_table.add_row(
            fid,
            str(entry.get("status", "")),
            str(entry.get("first_seen") or "—"),
            str(entry.get("last_seen") or "—"),
            str(entry.get("rule_id") or "—"),
            str(entry.get("module") or "—"),
        )
    console.print(f_table)

    posture = bl.get("posture", {})
    p_table = Table(title="Posture", show_header=True, header_style="bold")
    p_table.add_column("check_id")
    p_table.add_column("passed")
    for check_id, entry in posture.items():
        entry = entry if isinstance(entry, dict) else {}
        p_table.add_row(check_id, str(bool(entry.get("passed"))))
    console.print(p_table)


def _baseline_reset(target: str, path: Path) -> None:
    """`--reset` (§25): cancella il file baseline del target. Azione deliberata e
    NON interattiva (la CLI gira non-interattiva): nessun prompt, ma stampa
    chiaramente cosa è stato rimosso. Se il file non esiste → nota, exit 0."""
    if not path.exists():
        console.print(f"[dim]nota:[/] niente da resettare per [cyan]{target}[/] "
                      f"(nessuna baseline in {path}).")
        return
    bl = load_baseline(path)
    n_findings = len(bl.get("findings", {}))
    n_posture = len(bl.get("posture", {}))
    path.unlink()
    console.print(
        f"Baseline di [cyan]{target}[/] rimossa ({path}): conteneva "
        f"[bold]{n_findings}[/] finding e [bold]{n_posture}[/] posture check.")


def _baseline_accept(target: str, path: Path, finding_id: str) -> None:
    """`--accept <id>` (§25 / §16 gradino 2): promozione selettiva e deliberata di
    UN finding KNOWN→ACCEPTED. Carica, promuove via `accept_finding` (puro), salva.

    Errori chiari (niente stacktrace, §25):
    - baseline assente o id non presente → messaggio + exit ≠ 0;
    - id presente ma entry corrotta (non-dict) → messaggio dedicato + exit ≠ 0;
    - già accepted → vero no-op su disco, nota idempotente, exit 0.
    Non promuove nessun altro finding."""
    if not path.exists():
        err_console.print(
            f"[bold red]Errore:[/] nessuna baseline per [cyan]{target}[/] "
            f"(atteso in {path}): niente da accettare. Creala con "
            f"[bold]scan --accept-baseline[/].")
        raise typer.Exit(code=2)

    bl = load_baseline(path)
    findings = bl.get("findings", {})
    entry = findings.get(finding_id) if isinstance(findings, dict) else None
    id_present = isinstance(findings, dict) and finding_id in findings

    # Già accepted → vero no-op su disco: non riscriviamo il file (mtime invariato,
    # nessun rischio di azzerare un updated_at non-ISO). Idempotente per davvero.
    if isinstance(entry, dict) and entry.get("status") == "accepted":
        console.print(f"[dim]nota:[/] finding [bold]{finding_id}[/] era già "
                      f"[bold]accepted[/] (idempotente, nessuna modifica su disco).")
        return

    if not accept_finding(bl, finding_id):
        # accept_finding ritorna False sia per id assente sia per entry corrotta
        # (non-dict): distinguiamo i due casi per un messaggio preciso (§25).
        if id_present:
            err_console.print(
                f"[bold red]Errore:[/] finding [bold]{finding_id}[/] presente nella "
                f"baseline di [cyan]{target}[/] ma con entry corrotta (non è un "
                f"oggetto): impossibile accettarlo. Ispeziona/rigenera la baseline.")
        else:
            err_console.print(
                f"[bold red]Errore:[/] finding [bold]{finding_id}[/] non presente nella "
                f"baseline di [cyan]{target}[/]. Usa [bold]baseline --show[/] per gli id noti.")
        raise typer.Exit(code=2)

    # Promozione REALE: la baseline è cambiata → updated_at = adesso. Così non
    # azzeriamo mai silenziosamente un updated_at preesistente (anche non-ISO):
    # lo aggiorniamo deliberatamente perché il file è stato davvero modificato.
    save_baseline(
        path,
        target=bl.get("target") or target,
        findings=bl.get("findings", {}),
        posture=bl.get("posture", {}),
        updated_at=datetime.now(timezone.utc),
    )
    console.print(f"Finding [bold]{finding_id}[/] promosso a "
                  f"[bold]accepted[/] nella baseline di [cyan]{target}[/].")


# ─── doctor (§24) ────────────────────────────────────────────────────────────

@app.command()
def doctor() -> None:
    """Verifica quali tool esterni e librerie opzionali sono presenti (§24).

    Best-effort: nessun crash se qualcosa manca — è esattamente ciò che il comando
    deve rilevare. L'assenza di un tool degrada il recon (§8), non lo interrompe."""
    table = Table(title="Bastione doctor — dipendenze opzionali (§24)",
                  show_header=True, header_style="bold")
    table.add_column("componente")
    table.add_column("tipo")
    table.add_column("stato")

    for tool in _EXTERNAL_TOOLS:
        presente = shutil.which(tool) is not None
        table.add_row(tool, "tool esterno", _ok(presente))

    table.add_row("httpx", "libreria python", _ok(_lib_present("httpx")))

    console.print(table)


def _lib_present(module_name: str) -> bool:
    """True se la libreria `module_name` è importabile. Nessun crash se assente."""
    import importlib.util
    return importlib.util.find_spec(module_name) is not None


def _ok(presente: bool) -> str:
    return "[green]installato[/]" if presente else "[yellow]assente[/]"


# ─── list-modules (§9) ───────────────────────────────────────────────────────

@app.command("list-modules")
def list_modules() -> None:
    """Elenca i moduli di scansione registrati (§9): name e tetto di intrusione."""
    from bastione.modules.base import REGISTRY

    _ensure_modules_loaded()
    table = Table(title="Moduli registrati (§9)", show_header=True, header_style="bold")
    table.add_column("name")
    table.add_column("max_intrusion")
    for name in sorted(REGISTRY):
        module = REGISTRY[name]
        table.add_row(name, module.max_intrusion.name.lower())
    console.print(table)


# ─── list-detectors (§10) ────────────────────────────────────────────────────

@app.command("list-detectors")
def list_detectors() -> None:
    """Elenca i detector di segreti registrati (§10): detector_id e severità."""
    # L'import del package popola DETECTORS via @register_detector (§10).
    import bastione.modules.secrets.detectors  # noqa: F401
    from bastione.modules.secrets.detectors.base import DETECTORS

    table = Table(title="Detector di segreti (§10)", show_header=True, header_style="bold")
    table.add_column("detector_id")
    table.add_column("severity")
    for detector in DETECTORS:
        table.add_row(detector.detector_id, detector.severity.name.lower())
    console.print(table)


# ─── comandi §25 non ancora in M0 (stub espliciti) ───────────────────────────

@app.command()
def verify() -> None:
    """[M1] Verifica un finding specifico — non disponibile in M0."""
    err_console.print("[yellow]verify[/]: disponibile a M1 (non implementato in M0).")
    raise typer.Exit(code=1)


@app.command()
def fix() -> None:
    """[M1] Applica una remediation — non disponibile in M0."""
    err_console.print("[yellow]fix[/]: disponibile a M1 (non implementato in M0).")
    raise typer.Exit(code=1)


if __name__ == "__main__":   # pragma: no cover
    app()
