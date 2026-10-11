"""CLI di Bastione (§25) — il guscio `typer` sopra l'orchestratore (step 15).

La CLI **non** orchestra né bypassa nulla: cabla soltanto i comandi dell'utente
sull'`Orchestrator` (§6) e ne presenta i risultati con `rich`. Le regole di
sicurezza restano dove devono stare: il gate (§7, fase LOAD) è l'autorità — la CLI
non declassa e non aggira (GUARDRAIL LOCKED). In M0 il default è **READ_ONLY**.

Comandi (§25):
  - `scan`          : esegue una run sull'orchestratore e stampa il sommario;
  - `verify`        : ri-scansiona (READ_ONLY) e mostra lo stato dei finding (§18-bis.8);
  - `baseline`      : gestisce la baseline locale del target (§16);
  - `doctor`        : verifica tool esterni / lib opzionali: presenza, versione e
                      stato della policy di versione (R4, via `toolcheck`);
  - `list-modules`  : elenca i moduli registrati (§9);
  - `list-detectors`: elenca i detector di segreti registrati (§10).

Vincoli (LOCKED):
  - `--unsafe-show-secrets` è INCOMPATIBILE con `--ci` (un CI non deve mai stampare
    segreti in chiaro): combinazione → errore, exit ≠ 0 (P8/§25);
  - `--no-fix` (M1) salta la generazione del bundle di remediation `fix/` (§18-bis);
    `--i-own-this-its-staging` (M2) è **RICHIESTO** per `--max-intrusion mutating`
    (scritture canary §11.2, non interattivo): senza → exit 2 (precondizione). NON
    declassa né aggira il gate (§7), che resta l'autorità su staging+ownership;
  - `--fail-on` / `--ci`: dopo la run, se ≥1 finding emesso ha severity ≥ soglia →
    exit 1 (gate CI minimale §22); altrimenti 0.

Gestione errori (§25): un `IntrusionDenied` dal gate produce un messaggio chiaro e
un exit code ≠ 0 — MAI uno stacktrace in faccia all'utente.
"""

from __future__ import annotations

import json
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
from bastione.enums import IntrusionLevel, Severity, Status
from bastione.gate import IntrusionDenied, PreconditionDenied
from bastione.models import Fingerprint
from bastione.normalize.defectdojo import (
    push_to_defectdojo,
    to_defectdojo,
    write_defectdojo_export,
)
from bastione.orchestrator import (
    DEFAULT_BASELINES_ROOT,
    DEFAULT_RUNS_ROOT,
    FINGERPRINT_FILENAME,
    REPORT_FILENAME,
    SARIF_FILENAME,
    Orchestrator,
    _ensure_modules_loaded,
)
from bastione.portfolio import (
    DEFAULT_PORTFOLIO_FILE,
    PortfolioRow,
    load_portfolio,
    run_portfolio,
)
from bastione.state import RunState
from bastione.surface.inventory import (
    build_snapshot,
    diff_snapshots,
    load_surface_baseline,
    save_surface_baseline,
)

log = logging.getLogger("bastione.cli")

app = typer.Typer(
    add_completion=False,
    help="Bastione (BAS) — orchestratore di security testing difensivo (§25).",
)

console = Console()
err_console = Console(stderr=True)

# Tool esterni opzionali sondati da `doctor` (§24): l'assenza degrada il recon
# (§8), non è un errore — è proprio lo scopo del comando rilevarla.
# `zap-baseline.py` è il binario REALE usato dal modulo zap (`_ZAP_BINARY`): doctor
# e modulo controllano lo stesso nome (niente mismatch).
_EXTERNAL_TOOLS = ["whatweb", "katana", "testssl.sh", "nuclei", "zap-baseline.py",
                   "semgrep", "trivy"]


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
        False, "--no-fix",
        help="Disabilita la remediation: salta la generazione del bundle fix/ (§18-bis)."),
    i_own_this_its_staging: bool = typer.Option(
        False, "--i-own-this-its-staging",
        help="[M2] RICHIESTO per --max-intrusion mutating (scritture canary, §11.2): "
             "conferma esplicita ownership+staging per esecuzioni non interattive "
             "(CI/cron). Autodescrittivo, finisce nei log. Il gate runtime (§7) "
             "resta comunque l'autorità che impone staging+ownership."),
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

    level = _CLI_TO_INTRUSION[max_intrusion]

    # §7/§25 (LOCKED): per --max-intrusion mutating (scritture canary 🔴) in modo
    # NON interattivo serve la conferma esplicita --i-own-this-its-staging. Senza,
    # è una PRECONDIZIONE non soddisfatta → errore chiaro + exit 2 (come le altre
    # precondizioni di LOAD, §22). Questo NON declassa e NON aggira il gate: il
    # gate runtime (authorize/ownership, §7) resta l'autorità che impone
    # staging+ownership sul target — questa è solo la conferma d'intento dell'utente
    # (autodescrittiva, finisce nei log). Il flag su read-only/probe è un no-op
    # innocuo (non richiesto, non rifiutato).
    if level >= IntrusionLevel.MUTATING and not i_own_this_its_staging:
        err_console.print(
            "[bold red]Errore:[/] --max-intrusion mutating richiede la conferma "
            "esplicita [bold]--i-own-this-its-staging[/] (scritture canary §11.2, "
            "🔴). Aggiungi il flag SOLO se il target è uno staging che possiedi: il "
            "gate (§7) verificherà comunque staging+ownership e aborterà se non lo "
            "sono.")
        raise typer.Exit(code=2)

    if i_own_this_its_staging:
        console.print(
            "[dim]nota:[/] --i-own-this-its-staging confermato: per --max-intrusion "
            "mutating il canary write (§11.2) può procedere; il gate (§7) impone "
            "comunque staging+ownership."
            if level >= IntrusionLevel.MUTATING else
            "[dim]nota:[/] --i-own-this-its-staging è ininfluente sotto "
            "--max-intrusion mutating (nessuna scrittura sotto MUTATING).")
    if unsafe_show_secrets:
        console.print(
            "[dim]nota:[/] --unsafe-show-secrets: la de-redazione dell'evidence è "
            "M1; in M0 i segreti restano redatti nei file (P8).")

    # Soglia del trigger NOTIFY (§19 LOCKED): il flag --fail-on vince sul TOML
    # (notify_min_severity). Passiamo all'orchestratore SOLO la severità di
    # --fail-on quando è esplicito (None altrimenti): è il default --ci a NON
    # dover sovrascrivere il min_severity del notify (il default HIGH di --ci
    # serve al gate CI §22, non al notify). Così la soglia di NOTIFY resta "il
    # flag se c'è, altrimenti il TOML".
    notify_threshold = _CLI_TO_SEVERITY[fail_on] if fail_on is not None else None

    orch = Orchestrator()
    try:
        state = orch.run(
            target,
            max_intrusion=level,
            resume=resume,
            accept_baseline=accept_baseline,
            no_fix=no_fix,
            fail_on=notify_threshold,
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
    except Exception as exc:  # noqa: BLE001 — catch-all §22/§25 (LOCKED)
        # Catch-all FINALE (dopo Precondition/Intrusion/FileNotFound): ogni altra
        # eccezione inattesa (bug interno, tool esterno esploso) è per §22 un
        # "errore esecuzione tool/interno" → exit 4. Messaggio chiaro, MAI uno
        # stacktrace in faccia all'utente (§25). DEVE restare l'ultimo ramo: i
        # mapping specifici 2/3/4-config lo precedono e non vanno scavalcati.
        err_console.print(
            f"[bold red]Errore interno durante la run:[/] {exc}\n"
            "La run è stata interrotta da un errore inatteso (tool esterno o bug "
            "interno). Riprova con --resume; se persiste, apri un'issue (§22/§25).")
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
    """Verifica tool esterni e librerie opzionali: presenza, versione e policy (§24/R4).

    Best-effort: nessun crash se qualcosa manca — è esattamente ciò che il comando
    deve rilevare. L'assenza di un tool degrada il recon (§8), non lo interrompe.
    Per i tool con policy di versione (`toolcheck.TOOL_POLICY`: trivy, nuclei) mostra
    la versione reale e lo stato: ammesso, oppure il motivo del blocco (R4)."""
    from bastione.toolcheck import check_tool, TOOL_POLICY

    table = Table(title="Bastione doctor — dipendenze opzionali (§24)",
                  show_header=True, header_style="bold")
    table.add_column("componente")
    table.add_column("tipo")
    table.add_column("versione")
    table.add_column("stato")

    for tool in _EXTERNAL_TOOLS:
        presente = shutil.which(tool) is not None
        version, stato = "—", _ok(presente)
        if presente and tool in TOOL_POLICY:
            st = check_tool(tool)
            version = st.version or "?"
            stato = "[green]ammesso[/]" if st.ok else f"[red]{st.reason}[/]"
        table.add_row(tool, "tool esterno", version, stato)

    table.add_row("httpx", "libreria python", "—", _ok(_lib_present("httpx")))

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


# ─── verify (§18-bis.8) ──────────────────────────────────────────────────────

# Mappa lo status di un finding (post-baseline) sull'etichetta del loop di
# verifica (§18-bis.8): un fix è chiuso SOLO quando il finding passa a FIXED.
_VERIFY_LABEL = {
    Status.FIXED: "FIXED",       # non più riscontrato → il fix ha chiuso il finding
    Status.NEW: "new",           # comparso ora (non era in baseline): regressione/nuovo
    Status.KNOWN: "still_open",   # già noto e ANCORA aperto: il fix non ha (ancora) chiuso
    Status.ACCEPTED: "still_open",  # rumore noto silenziato, ma sempre presente sul target
}


def _rescan_read_only(target: str) -> Orchestrator:
    """Ri-scansione READ_ONLY del target, riusabile da `verify` ed `export-defectdojo`.

    Esegue l'orchestratore con il tetto READ_ONLY, `--no-fix` (nessun bundle) e
    `notify=False`: è SOLO una ri-scansione di sola lettura del target — nessuna
    scrittura sul target, nessuna azione outward-facing. Ritorna l'`Orchestrator`
    (da cui i chiamanti leggono `_result` e `_run_dir`).

    `notify=False` è il punto CHIAVE del contratto outward-facing (§7/§19): `run()`
    esegue l'INTERA pipeline, NOTIFY inclusa, e la precondizione NOTIFY non dipende
    da `max_intrusion` né da `no_fix`. Senza sopprimerla, un target con
    `[notify].channel='telegram'` e finding NEW ≥ soglia farebbe partire un POST
    Telegram REALE anche da `verify`/`export-defectdojo` — in diretta contraddizione
    col docstring "nessuna azione outward-facing". Con `notify=False`
    l'orchestratore salta la fase NOTIFY del tutto (vedi `_should_run`).

    Gli errori sono mappati ai medesimi exit code di `scan` (§22/§25): precondizione
    del gate → exit 2, ownership challenge → exit 3, config target assente → exit 4,
    ogni altra eccezione inattesa → exit 4 (catch-all finale, niente stacktrace)."""
    orch = Orchestrator()
    try:
        orch.run(
            target,
            max_intrusion=IntrusionLevel.READ_ONLY,
            no_fix=True,   # ri-scansione di sola lettura: non rigenera il bundle fix/
            notify=False,  # contratto outward-facing (§7/§19): nessun POST Telegram
        )
    except PreconditionDenied as exc:
        err_console.print(f"[bold red]Precondizione negata dal gate (§7):[/] {exc}")
        raise typer.Exit(code=2)
    except IntrusionDenied as exc:
        err_console.print(f"[bold red]Run negata dal gate (§7):[/] {exc}")
        raise typer.Exit(code=3)
    except FileNotFoundError as exc:
        err_console.print(f"[bold red]Config target non trovata:[/] {exc}")
        raise typer.Exit(code=4)
    except Exception as exc:  # noqa: BLE001 — catch-all §22/§25 (LOCKED)
        err_console.print(
            f"[bold red]Errore interno durante la ri-scansione:[/] {exc}\n"
            "La ri-scansione è stata interrotta da un errore inatteso (tool esterno "
            "o bug interno). Se persiste, apri un'issue (§22/§25).")
        raise typer.Exit(code=4)
    return orch


@app.command()
def verify(
    target: str = typer.Option(..., "--target", help="Nome del target (config in targets/)."),
) -> None:
    """Ri-scansiona il target (READ_ONLY) e mostra lo stato di ogni finding (§18-bis.8).

    Il loop di verifica: un fix è chiuso SOLO quando il finding passa a **FIXED**.
    La tabella mappa ogni `finding_id` su `{FIXED | still_open | new}` confrontando la
    ri-scansione con la baseline/ultima run:
      - presente in baseline ma non più riscontrato → **FIXED** (il fix ha funzionato);
      - già noto e ancora presente (KNOWN/ACCEPTED) → **still_open** (non ancora chiuso);
      - comparso ora (non in baseline) → **new** (nuovo/regressione).

    PRECONDIZIONE (importante): lo stato **FIXED** si calcola per differenza contro la
    BASELINE SALVATA. È quindi raggiungibile SOLO se la baseline è stata accettata
    PRIMA della remediation, con `bastione scan --target <t> --accept-baseline`: così i
    finding ancora aperti sono salvati come KNOWN e, una volta corretti, la ri-scansione
    li riconosce come FIXED. SENZA una baseline accettata, un finding corretto sparisce
    semplicemente dalla ri-scansione (non era in baseline → non può risultare FIXED) e
    uno ancora presente compare come `new`, non `still_open`. Il flusso completo del
    loop è dunque: `scan --accept-baseline` → applica i fix del bundle → `verify`.

    READ_ONLY rispetto al target e senza generare bundle (`--no-fix`): è solo una
    verifica. Errori gestiti come `scan` (niente stacktrace, §25): precondizione del
    gate → exit 2, ownership challenge → exit 3, config target assente → exit 4."""
    orch = _rescan_read_only(target)
    _print_verify_table(target, orch._result)


def _print_verify_table(target: str, result) -> None:
    """Rende la tabella finding_id → stato della verifica (§18-bis.8).

    Legge la `BaselineResult` dell'ultima run: i finding *emessi* (NEW/KNOWN/ACCEPTED)
    e i `fixed` (in baseline ma non più riscontrati). Ordina i FIXED in fondo: ciò che
    resta aperto (still_open/new) è ciò su cui agire."""
    emitted = list(result.findings) if result is not None else []
    fixed = list(result.fixed) if result is not None else []

    console.print()
    console.print(f"[bold]Bastione verify[/] — target [cyan]{target}[/] (§18-bis.8)")

    table = Table(title="Stato dei finding", show_header=True, header_style="bold")
    table.add_column("finding_id")
    table.add_column("rule_id")
    table.add_column("severità")
    table.add_column("stato")

    rows = 0
    for f in emitted + fixed:
        label = _VERIFY_LABEL.get(f.status, str(f.status.value))
        table.add_row(
            f.finding_id, f.rule_id, f.severity.name.lower(), label)
        rows += 1

    if rows == 0:
        console.print("[green]Nessun finding[/]: il target risulta pulito in questa "
                      "ri-scansione (§18-bis.8).")
        return

    console.print(table)

    open_count = sum(1 for f in emitted if f.status in (Status.NEW, Status.KNOWN))
    new_count = sum(1 for f in emitted if f.status is Status.NEW)
    fixed_count = len(fixed)
    console.print(
        f"Riepilogo: [bold]{fixed_count}[/] FIXED, [bold]{open_count}[/] ancora aperti. "
        f"Un fix è chiuso solo quando il finding risulta [bold]FIXED[/].")

    # Precondizione del loop (§18-bis.8): FIXED si calcola per differenza contro la
    # BASELINE SALVATA. Se NON c'è alcun FIXED ma ci sono finding `new`, è il sintomo
    # tipico di una baseline mai accettata: un finding corretto sparirebbe dalla
    # ri-scansione invece di risultare FIXED, e uno ancora presente compare come `new`.
    # Lo segnaliamo per non far credere all'utente che "0 FIXED" significhi "fix
    # falliti" quando in realtà la baseline non è stata accettata prima della
    # remediation.
    if fixed_count == 0 and new_count > 0:
        console.print(
            "[yellow]Nota:[/] nessun finding risulta FIXED e alcuni sono [bold]new[/]. "
            "Lo stato FIXED si misura contro la baseline SALVATA: se non hai accettato "
            "la baseline PRIMA della remediation "
            "([italic]scan --accept-baseline[/]), un finding corretto sparisce dalla "
            "ri-scansione invece di risultare FIXED. Flusso del loop: "
            "[italic]scan --accept-baseline[/] → applica i fix → [italic]verify[/].")


# ─── surface (attack-surface inventory & diff, M3) ────────────────────────────

# Nome del file di baseline della superficie (M3): vive accanto alla baseline dei
# finding, in baselines/<target>.surface.json. Stesso stile/root della baseline §16.
SURFACE_BASELINE_SUFFIX = ".surface.json"


def _surface_baseline_path(baselines_dir: Path | None, target: str) -> Path:
    """Path della surface baseline del target (M3): baselines/<target>.surface.json.
    `--baselines-dir` (nascosto) la redirige a una dir temporanea nei test, come per
    la baseline dei finding (§16)."""
    root = baselines_dir if baselines_dir is not None else DEFAULT_BASELINES_ROOT
    return root / f"{target}{SURFACE_BASELINE_SUFFIX}"


def _latest_fingerprint(target: str) -> Fingerprint:
    """Carica l'ultimo `fingerprint.json` prodotto da una run di RECON (§8) per il
    target: cerca runs/<target>/<ts>/fingerprint.json e prende la run più recente
    (i timestamp ordinano lessicograficamente). READ-ONLY rispetto al target:
    legge SOLO un artefatto locale, nessuna rete.

    Errore ONESTO (niente stacktrace, §25): se non c'è alcuna run con fingerprint
    → messaggio chiaro + exit 4 (suggerisce di lanciare `scan` prima)."""
    target_root = DEFAULT_RUNS_ROOT / target
    candidates: list[Path] = []
    if target_root.exists():
        for run_dir in sorted(p for p in target_root.iterdir() if p.is_dir()):
            fp_path = run_dir / FINGERPRINT_FILENAME
            if fp_path.exists():
                candidates.append(fp_path)
    if not candidates:
        err_console.print(
            f"[bold red]Nessun fingerprint per[/] [cyan]{target}[/]: atteso in "
            f"runs/{target}/<ts>/{FINGERPRINT_FILENAME}. Lancia prima "
            f"[bold]bastione scan --target {target}[/] per generare il recon (§8).")
        raise typer.Exit(code=4)

    latest = candidates[-1]   # la run più recente (i timestamp ordinano)
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
        return Fingerprint.model_validate(data)
    except Exception as exc:  # noqa: BLE001 — errore onesto, niente stacktrace (§25)
        err_console.print(
            f"[bold red]Fingerprint illeggibile[/] ({latest}): {exc}. "
            f"Rigenera il recon con [bold]bastione scan --target {target}[/].")
        raise typer.Exit(code=4)


def _print_surface_diff(diff) -> None:
    """Stampa il delta della superficie d'attacco (M3) come tabella deterministica:
    una riga per ogni elemento aggiunto/rimosso, per categoria. Le liste sono già
    ordinate a monte (`diff_snapshots`), quindi l'output è deterministico."""
    if diff.unchanged:
        console.print("[green]Superficie invariata[/]: nessun add/remove rispetto allo "
                      "snapshot precedente (M3).")
        return

    table = Table(title="Delta superficie d'attacco (M3)", show_header=True,
                  header_style="bold")
    table.add_column("categoria")
    table.add_column("delta")
    table.add_column("elemento")
    # Ordine FISSO delle categorie e di added-prima-di-removed → tabella deterministica.
    rows = (
        ("table", "added", diff.added_tables),
        ("table", "removed", diff.removed_tables),
        ("endpoint", "added", diff.added_endpoints),
        ("endpoint", "removed", diff.removed_endpoints),
        ("url", "added", diff.added_urls),
        ("url", "removed", diff.removed_urls),
    )
    for category, delta, items in rows:
        marker = "[green]+[/]" if delta == "added" else "[red]-[/]"
        for item in items:
            table.add_row(category, f"{marker} {delta}", item)
    console.print(table)


def _print_surface_snapshot(snapshot, target: str) -> None:
    """Stampa lo snapshot della superficie d'attacco (M3): id deterministico e le
    tre categorie (tabelle/endpoint/url), ordinate."""
    console.print()
    console.print(f"[bold]Superficie d'attacco[/] di [cyan]{target}[/] "
                  f"(snapshot_id: {snapshot.snapshot_id})  taken_at: "
                  f"{snapshot.taken_at or '—'}")
    table = Table(title="Superficie d'attacco (M3)", show_header=True, header_style="bold")
    table.add_column("categoria")
    table.add_column("elemento")
    for item in snapshot.tables:
        table.add_row("table", item)
    for item in snapshot.endpoints:
        table.add_row("endpoint", item)
    for item in snapshot.urls:
        table.add_row("url", item)
    console.print(table)


@app.command()
def surface(
    target: str = typer.Option(..., "--target", help="Nome del target (config in targets/)."),
    snap: bool = typer.Option(
        False, "--snap",
        help="Salva il nuovo snapshot della superficie come baseline (mostra il diff col precedente)."),
    diff: bool = typer.Option(
        False, "--diff",
        help="Mostra il diff superficie vs baseline SENZA salvare."),
    show: bool = typer.Option(
        False, "--show",
        help="Stampa lo snapshot baseline corrente (default se nessuna opzione)."),
    baselines_dir: Path | None = typer.Option(
        None, "--baselines-dir", hidden=True,
        help="Override della root delle baseline (uso interno/test)."),
) -> None:
    """Inventario e diff della superficie d'attacco del target (M3).

    Il gemello della baseline, ma per la SUPERFICIE esposta (tabelle, endpoint, URL)
    invece che per i finding. Costruisce lo snapshot dall'ULTIMO fingerprint del
    recon (runs/<target>/<ts>/fingerprint.json) e lo confronta con la baseline
    salvata (baselines/<target>.surface.json).

    Le tre azioni sono mutuamente esclusive (default `--show`):
      - `--snap` : salva il nuovo snapshot come baseline (e mostra il diff col precedente, se c'è);
      - `--diff` : mostra il diff vs baseline SENZA salvare;
      - `--show` : stampa lo snapshot baseline corrente.

    READ-ONLY rispetto al target: legge SOLO artefatti locali (il fingerprint già
    prodotto da una run), MAI rete, MAI il target. La tabella added/removed è
    deterministica. Errore onesto (niente stacktrace, §25) se manca il fingerprint."""
    # Mutua esclusione (come `baseline`, §25): al più UNA delle tre opzioni.
    chosen = [name for name, on in
              (("--snap", snap), ("--diff", diff), ("--show", show)) if on]
    if len(chosen) > 1:
        err_console.print(
            f"[bold red]Errore:[/] {', '.join(chosen)} sono mutuamente esclusive: "
            "scegline una sola (M3).")
        raise typer.Exit(code=2)

    # Guardia path-traversal (GUARDRAIL LOCKED): la surface baseline è scritta/letta
    # per path, come la baseline dei finding — rifiuta target che evaderebbero la root.
    _validate_target_name(target)

    path = _surface_baseline_path(baselines_dir, target)

    # --show: stampa la baseline salvata, senza toccare il fingerprint. Se assente →
    # nota amichevole + exit 0 (la baseline si crea con `surface --snap`).
    if show or not chosen:
        baseline_snapshot = load_surface_baseline(path)
        if baseline_snapshot is None:
            console.print(
                f"[yellow]Nessuna surface baseline per[/] [cyan]{target}[/] "
                f"(atteso in {path}). Creala con [bold]surface --snap[/].")
            return
        _print_surface_snapshot(baseline_snapshot, target)
        return

    # --snap / --diff: costruisci lo snapshot corrente dall'ultimo fingerprint e
    # confrontalo con la baseline (READ-ONLY: nessuna rete, solo artefatti locali).
    fp = _latest_fingerprint(target)
    new_snapshot = build_snapshot(fp, taken_at=datetime.now(timezone.utc))
    old_snapshot = load_surface_baseline(path)
    delta = diff_snapshots(old_snapshot, new_snapshot)

    if diff:
        # --diff: mostra il delta SENZA salvare.
        console.print()
        console.print(f"[bold]Bastione surface[/] — diff [cyan]{target}[/] "
                      f"(snapshot_id: {new_snapshot.snapshot_id})")
        if old_snapshot is None:
            console.print("[dim]nota:[/] nessuna surface baseline precedente: l'intera "
                          "superficie risulta [green]added[/] (prima rilevazione).")
        _print_surface_diff(delta)
        return

    # --snap: salva il nuovo snapshot come baseline, mostrando il diff col precedente.
    console.print()
    console.print(f"[bold]Bastione surface[/] — snapshot [cyan]{target}[/] salvato "
                  f"(snapshot_id: {new_snapshot.snapshot_id})")
    if old_snapshot is None:
        console.print("[dim]nota:[/] nessuna surface baseline precedente: l'intera "
                      "superficie risulta [green]added[/] (prima rilevazione).")
    _print_surface_diff(delta)
    saved = save_surface_baseline(path, new_snapshot)
    console.print(f"Surface baseline scritta in [cyan]{saved}[/].")


# ─── export-defectdojo (§T4) ──────────────────────────────────────────────────

# Nome del file di export DefectDojo nella run dir (§T4).
DEFECTDOJO_FILENAME = "defectdojo.json"


@app.command("export-defectdojo")
def export_defectdojo(
    target: str = typer.Option(..., "--target", help="Nome del target (config in targets/)."),
) -> None:
    """Esporta i finding correnti nel formato DefectDojo e (gated) li pusha (§T4).

    Ottiene i finding correnti con lo STESSO meccanismo di `verify`: una
    ri-scansione READ_ONLY del target (`--no-fix`, nessun bundle, nessuna scrittura
    sul target). Converte i finding emessi in "Generic Findings Import" (`to_defectdojo`),
    scrive il payload in runs/<target>/<ts>/defectdojo.json (`write_defectdojo_export`)
    e tenta il push (`push_to_defectdojo`).

    Il push è GATED sull'ambiente (BASTIONE_DEFECTDOJO_URL/TOKEN): se non configurato
    riporta onestamente [bold]skipped[/] SENZA toccare la rete. Guardrail P8:
    l'evidence non finisce mai nel payload (omessa a monte).

    Errori gestiti come `scan`/`verify` (niente stacktrace, §25): precondizione del
    gate → exit 2, ownership challenge → exit 3, config target assente → exit 4."""
    orch = _rescan_read_only(target)

    result = orch._result
    findings = list(result.findings) if result is not None else []

    payload = to_defectdojo(findings, target=target)
    out_path = orch._run_dir / DEFECTDOJO_FILENAME
    write_defectdojo_export(out_path, payload)

    # Push GATED + RESILIENTE (§T4): "skipped" se l'env non è configurato; "pushed"
    # se la POST è andata (qualunque status HTTP); "error:<msg>" se ha sollevato.
    outcome = push_to_defectdojo(payload)

    console.print()
    console.print(f"[bold]Bastione export-defectdojo[/] — target [cyan]{target}[/] (§T4)")
    console.print(f"Finding esportati: [bold]{len(findings)}[/]")
    console.print(f"Export DefectDojo scritto in: [cyan]{out_path}[/]")
    if outcome == "skipped":
        console.print(
            "Push: [yellow]skipped[/] — env "
            "[bold]BASTIONE_DEFECTDOJO_URL[/]/[bold]BASTIONE_DEFECTDOJO_TOKEN[/] non "
            "configurato. Il file di export è comunque pronto da importare a mano.")
    elif outcome == "pushed":
        console.print("Push: [green]pushed[/] — payload inviato all'istanza DefectDojo.")
    else:
        # "error:<msg>": il push è best-effort (§19), non fa fallire il comando.
        msg = outcome.split(":", 1)[1] if ":" in outcome else outcome
        console.print(
            f"Push: [red]error[/] — {msg}. Il file di export è comunque pronto da "
            "importare a mano (il push è best-effort §19).")


# ─── scan-all (portfolio mode §21) ───────────────────────────────────────────

@app.command("scan-all")
def scan_all(
    portfolio: Path = typer.Option(
        DEFAULT_PORTFOLIO_FILE, "--portfolio",
        help="File del portfolio (default portfolio.toml): lista target + [defaults] (§21)."),
) -> None:
    """Esegue OGNI target del portfolio e stampa la tabella di postura (§21).

    Portfolio mode: `portfolio.toml` elenca le tue app; `scan-all` le scansiona
    tutte (READ_ONLY di default, riusando la pipeline di `scan`), raccoglie per ogni
    app score / #CRITICAL aperti / #DRIFT e scrive un REPORT CONSOLIDATO. Stampa qui
    la **tabella di postura del portfolio**: una sola occhiata per sapere quale app
    ha bisogno di attenzione.

    READ_ONLY e rispettoso dei guardrail: ogni target passa comunque dal gate (§7)
    in fase LOAD, esattamente come una `scan` singola — il portfolio non declassa e
    non aggira nulla. RESILIENTE: un target che fallisce (config assente, gate
    denial, errore) diventa una riga d'errore nella tabella e NON interrompe gli
    altri (§21). Niente stacktrace in faccia all'utente (§25)."""
    try:
        config = load_portfolio(portfolio)
    except FileNotFoundError as exc:
        # Portfolio assente: errore chiaro (niente stacktrace, §25), exit ≠ 0.
        err_console.print(f"[bold red]Portfolio non trovato:[/] {exc}")
        raise typer.Exit(code=4)

    # Factory dell'orchestratore (§21): un closure che costruisce un `Orchestrator`
    # con i path standard. run_portfolio lo invoca per OGNI target — la costruzione
    # è qui (la CLI) così la pipeline reale resta cablata, ma run_portfolio è
    # testabile con un fake offline iniettato al suo posto.
    def _orch_factory() -> Orchestrator:
        return Orchestrator()

    report, rows = run_portfolio(
        config,
        orch_factory=_orch_factory,
        runs_root=DEFAULT_RUNS_ROOT,
        baselines_root=DEFAULT_BASELINES_ROOT,
        write=True,   # scrive il report consolidato sotto runs/<ts>/portfolio-report.md
    )

    _print_portfolio_table(rows)


def _print_portfolio_table(rows: list[PortfolioRow]) -> None:
    """Stampa la tabella di postura del portfolio (§21): per ogni app score,
    #CRITICAL aperti e #DRIFT. Le righe d'errore (target falliti) sono rese in
    modo visibile, così non passano inosservate (resilienza §21)."""
    console.print()
    console.print("[bold]Bastione[/] — tabella di postura del portfolio (§21)")

    if not rows:
        console.print("[yellow]Portfolio vuoto:[/] nessun target in portfolio.toml.")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("app")
    table.add_column("score", justify="right")
    table.add_column("#CRITICAL aperti", justify="right")
    table.add_column("#DRIFT", justify="right")
    table.add_column("NEW", justify="right")
    table.add_column("KNOWN", justify="right")
    table.add_column("FIXED", justify="right")
    table.add_column("stato")

    for r in rows:
        if r.error is not None:
            # Riga d'errore: numeri non disponibili, messaggio nello stato.
            table.add_row(
                r.target, "—", "—", "—", "—", "—", "—",
                f"[red]error:[/] {r.error}")
        else:
            score = f"{r.score:.1f}" if r.score is not None else "—"
            # Evidenzia in rosso le righe con CRITICAL aperti o DRIFT: sono le app
            # su cui agire per prime (§21).
            warn = (r.critical_open or 0) > 0 or (r.drift or 0) > 0
            stato = "[red]attenzione[/]" if warn else "[green]ok[/]"
            table.add_row(
                r.target, score, str(r.critical_open), str(r.drift),
                str(r.new), str(r.known), str(r.fixed), stato)

    console.print(table)

    n_error = sum(1 for r in rows if r.error is not None)
    n_crit = sum(1 for r in rows if r.error is None and (r.critical_open or 0) > 0)
    n_drift = sum(1 for r in rows if r.error is None and (r.drift or 0) > 0)
    console.print(
        f"Riepilogo: [bold]{len(rows)}[/] app "
        f"({len(rows) - n_error} scansionate, {n_error} in errore), "
        f"[bold]{n_crit}[/] con CRITICAL aperti, [bold]{n_drift}[/] con DRIFT.")


@app.command()
def fix() -> None:
    """[M1] Applica una remediation — il bundle fix/ è generato da `scan` (§18-bis)."""
    err_console.print(
        "[yellow]fix[/]: l'applicazione automatica non è ancora disponibile. Il "
        "bundle di remediation è generato da [bold]scan[/] in runs/<target>/<ts>/fix/ "
        "ed è destinato a un agente di coding (§18-bis).")
    raise typer.Exit(code=1)


if __name__ == "__main__":   # pragma: no cover
    app()
