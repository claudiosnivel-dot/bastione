"""Test del subcomando `bastione baseline` (§25 riga 946) — interamente OFFLINE.

Il comando è il gradino-2 del workflow baseline (§16): locale e READ-ONLY rispetto
al target (tocca SOLO il file `baselines/<target>.baseline.json`, nessuna rete).

Copre (§25 / §16):
  - --show con baseline esistente (mostra finding + posture) e senza file
    (messaggio amichevole, exit 0);
  - --reset con file presente (rimosso + conteggio) e assente (niente da
    resettare, exit 0);
  - --accept <id>: KNOWN→ACCEPTED nel file salvato; id inesistente → exit != 0 +
    messaggio; id già ACCEPTED → idempotente exit 0; non promuove altri finding;
  - mutua esclusione delle tre opzioni (--show + --reset → errore, exit != 0);
  - catena realistica: baseline scritta da `scan --accept-baseline` (NEW→KNOWN),
    poi `baseline --accept <id>` → quel finding ACCEPTED, gli altri KNOWN.

Per puntare a una baselines dir temporanea i test passano l'Option nascosto
`--baselines-dir` (stesso pattern del cablaggio CLI di scan, ma esplicito).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from bastione.baseline.diff import save_baseline
from bastione.cli import app

runner = CliRunner()

# Terminale ampio per i test: rich elide le colonne delle tabelle alla larghezza
# del terminale (80 col di default sotto CliRunner), troncando rule_id/module/id.
# Forziamo COLUMNS così --show mostra le voci per intero (è un dettaglio di
# rendering, non di logica). `Console` di rich legge COLUMNS dall'ambiente.
WIDE_ENV = {"COLUMNS": "200"}

NOW = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
EARLIER = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _write_baseline(root: Path, target: str, findings: dict, posture: dict) -> Path:
    """Scrive una baseline di test nel formato §16 sotto `root`."""
    return save_baseline(
        root / f"{target}.baseline.json",
        target=target,
        findings=findings,
        posture=posture,
        updated_at=NOW,
    )


def _known_finding(rule_id="RLS_DISABLED", module="supabase", status="known") -> dict:
    return {
        "status": status,
        "first_seen": EARLIER.isoformat(),
        "last_seen": NOW.isoformat(),
        "rule_id": rule_id,
        "module": module,
    }


# ─── --show ──────────────────────────────────────────────────────────────────

def test_show_existing_baseline_lists_entries(tmp_path: Path):
    _write_baseline(
        tmp_path, "g",
        findings={
            "aaaa1111": _known_finding(rule_id="RLS_DISABLED"),
            "bbbb2222": _known_finding(rule_id="MISSING_HSTS", module="headers",
                                       status="accepted"),
        },
        posture={"POSTURE_HSTS": {"passed": True}},
    )
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--show", "--baselines-dir", str(tmp_path)],
        env=WIDE_ENV)
    assert result.exit_code == 0, result.output
    out = result.output
    assert "g" in out
    assert "aaaa1111" in out
    assert "bbbb2222" in out
    assert "RLS_DISABLED" in out
    assert "MISSING_HSTS" in out
    assert "POSTURE_HSTS" in out


def test_show_is_default_when_no_option(tmp_path: Path):
    # Nessuna delle tre opzioni → default --show.
    _write_baseline(tmp_path, "g", findings={"aaaa1111": _known_finding()},
                    posture={})
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--baselines-dir", str(tmp_path)],
        env=WIDE_ENV)
    assert result.exit_code == 0, result.output
    assert "aaaa1111" in result.output


def test_show_missing_baseline_is_friendly(tmp_path: Path):
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--show", "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "g" in result.output
    # messaggio amichevole, nessuno stacktrace
    assert "nessuna baseline" in result.output.lower()
    assert "Traceback" not in result.output


# ─── --reset ─────────────────────────────────────────────────────────────────

def test_reset_removes_file_and_reports_count(tmp_path: Path):
    path = _write_baseline(
        tmp_path, "g",
        findings={"aaaa1111": _known_finding(), "bbbb2222": _known_finding()},
        posture={"POSTURE_HSTS": {"passed": True}},
    )
    assert path.exists()
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--reset", "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert not path.exists()       # file rimosso (azione deliberata, non interattiva)
    assert "2" in result.output    # conteggio voci rimosse


def test_reset_missing_file_is_noop(tmp_path: Path):
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--reset", "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "niente da resettare" in result.output.lower()


# ─── --accept <finding_id> ───────────────────────────────────────────────────

def test_accept_promotes_known_to_accepted(tmp_path: Path):
    path = _write_baseline(
        tmp_path, "g",
        findings={
            "aaaa1111": _known_finding(status="known"),
            "bbbb2222": _known_finding(status="known"),
        },
        posture={},
    )
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "aaaa1111",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    # solo aaaa1111 promosso; bbbb2222 resta KNOWN
    assert data["findings"]["aaaa1111"]["status"] == "accepted"
    assert data["findings"]["bbbb2222"]["status"] == "known"


def test_accept_unknown_id_errors(tmp_path: Path):
    _write_baseline(tmp_path, "g", findings={"aaaa1111": _known_finding()},
                    posture={})
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "deadbeef",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "deadbeef" in result.output
    assert "Traceback" not in result.output


def test_accept_already_accepted_is_idempotent(tmp_path: Path):
    path = _write_baseline(
        tmp_path, "g",
        findings={"aaaa1111": _known_finding(status="accepted")},
        posture={},
    )
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "aaaa1111",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"]["aaaa1111"]["status"] == "accepted"


def test_accept_on_missing_baseline_errors(tmp_path: Path):
    # nessun file → nessun finding da accettare → errore chiaro, exit != 0.
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "aaaa1111",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


# ─── mutua esclusione ────────────────────────────────────────────────────────

def test_show_and_reset_are_mutually_exclusive(tmp_path: Path):
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--show", "--reset",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_reset_and_accept_are_mutually_exclusive(tmp_path: Path):
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--reset", "--accept", "aaaa1111",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code != 0
    assert "Traceback" not in result.output


# ─── catena realistica: scan --accept-baseline poi baseline --accept ─────────

def test_chain_scan_accept_baseline_then_baseline_accept(tmp_path: Path):
    """Una baseline come la scrive `scan --accept-baseline` (NEW→KNOWN), poi
    `baseline --accept <id>`: quel finding diventa ACCEPTED, gli altri restano
    KNOWN. Stesso path/formato → i due gradini operano sullo stesso file (§16)."""
    baselines = tmp_path / "baselines"
    # simula l'output di _save_accepted_baseline dell'orchestratore (NEW→KNOWN)
    path = save_baseline(
        baselines / "g.baseline.json",
        target="g",
        findings={
            "id_a": {"status": "known", "first_seen": NOW.isoformat(),
                     "last_seen": NOW.isoformat(), "rule_id": "RLS_DISABLED",
                     "module": "supabase"},
            "id_b": {"status": "known", "first_seen": NOW.isoformat(),
                     "last_seen": NOW.isoformat(), "rule_id": "MISSING_HSTS",
                     "module": "headers"},
        },
        posture={"POSTURE_HSTS": {"passed": True}},
        updated_at=NOW,
    )
    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "id_a",
              "--baselines-dir", str(baselines)])
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"]["id_a"]["status"] == "accepted"
    assert data["findings"]["id_b"]["status"] == "known"
    # posture e metadati preservati
    assert data["posture"]["POSTURE_HSTS"]["passed"] is True
    assert data["target"] == "g"


# ─── path traversal sul nome target (GUARDRAIL LOCKED) ───────────────────────

def _victim_outside(tmp_path: Path) -> tuple[Path, Path]:
    """Crea baselines/ + un file vittima FUORI dalla baselines dir.

    Ritorna (baselines_dir, victim_path). `--target ../outside` da dentro
    `baselines/` punterebbe a `victim_path` se il traversal non fosse bloccato."""
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    victim = tmp_path / "outside.baseline.json"
    save_baseline(victim, target="outside",
                  findings={"id_a": _known_finding(status="known")},
                  posture={}, updated_at=NOW)
    assert victim.exists()
    return baselines, victim


def test_reset_traversal_target_is_rejected_and_victim_untouched(tmp_path: Path):
    # --reset con un target di traversal NON deve cancellare un file fuori root.
    baselines, victim = _victim_outside(tmp_path)
    result = runner.invoke(
        app, ["baseline", "--target", "../outside", "--reset",
              "--baselines-dir", str(baselines)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    assert "non valido" in result.output.lower()
    assert victim.exists()          # file esterno NON toccato (no unlink fuori root)


def test_accept_traversal_target_is_rejected_and_victim_untouched(tmp_path: Path):
    # --accept con un target di traversal NON deve scrivere fuori dalla root.
    baselines, victim = _victim_outside(tmp_path)
    result = runner.invoke(
        app, ["baseline", "--target", "../outside", "--accept", "id_a",
              "--baselines-dir", str(baselines)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    # status del file esterno invariato (resta 'known', non promosso ad 'accepted')
    data = json.loads(victim.read_text(encoding="utf-8"))
    assert data["findings"]["id_a"]["status"] == "known"


def test_show_traversal_target_is_rejected(tmp_path: Path):
    baselines, _ = _victim_outside(tmp_path)
    result = runner.invoke(
        app, ["baseline", "--target", "../outside", "--show",
              "--baselines-dir", str(baselines)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


def test_traversal_with_separator_in_subdir_is_rejected(tmp_path: Path):
    # Anche un separatore "in mezzo" (sottodir) deve essere rifiutato.
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    result = runner.invoke(
        app, ["baseline", "--target", "../../etc/passwd", "--reset",
              "--baselines-dir", str(baselines)])
    assert result.exit_code == 2, result.output
    assert "non valido" in result.output.lower()


# ─── --accept: fedeltà di updated_at e vero no-op idempotente ────────────────

def test_accept_does_not_null_a_non_iso_updated_at(tmp_path: Path):
    """REGRESSIONE: un --accept reale su una baseline con updated_at non-ISO non
    deve azzerarlo a null. La promozione è una mutazione vera → updated_at viene
    aggiornato a un ISO valido (mai None)."""
    path = tmp_path / "g.baseline.json"
    # save_baseline scrive sempre ISO; sovrascriviamo updated_at con un valore
    # non-ISO a mano per simulare una baseline editata/esterna.
    _write_baseline(tmp_path, "g",
                    findings={"id_a": _known_finding(status="known")}, posture={})
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["updated_at"] = "NOT-A-DATE"
    path.write_text(json.dumps(raw), encoding="utf-8")

    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "id_a",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"]["id_a"]["status"] == "accepted"
    # updated_at NON azzerato: ora è un ISO valido (la baseline è cambiata davvero)
    assert data["updated_at"] is not None
    datetime.fromisoformat(data["updated_at"])   # parsabile → non più 'NOT-A-DATE'/null


def test_accept_already_accepted_is_true_noop_on_disk(tmp_path: Path):
    """REGRESSIONE: --accept idempotente (già accepted) è un VERO no-op su disco:
    il file non viene riscritto, quindi un updated_at non-ISO resta intatto."""
    path = tmp_path / "g.baseline.json"
    _write_baseline(tmp_path, "g",
                    findings={"id_a": _known_finding(status="accepted")}, posture={})
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["updated_at"] = "not-a-date"
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_text(encoding="utf-8")

    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "id_a",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "idempotente" in result.output.lower()
    # byte-per-byte invariato: nessuna riscrittura, updated_at non azzerato
    assert path.read_text(encoding="utf-8") == before


# ─── --accept: messaggio dedicato per entry corrotta (non-dict) ──────────────

def test_accept_corrupt_nondict_entry_has_dedicated_message(tmp_path: Path):
    """REGRESSIONE: un id PRESENTE ma con entry corrotta (non-dict) non deve dire
    'non presente'; messaggio dedicato + exit != 0, nessuno stacktrace."""
    path = tmp_path / "g.baseline.json"
    _write_baseline(tmp_path, "g", findings={}, posture={})
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["findings"] = {"id_a": "corrupt"}     # entry non-dict, id presente
    path.write_text(json.dumps(raw), encoding="utf-8")

    result = runner.invoke(
        app, ["baseline", "--target", "g", "--accept", "id_a",
              "--baselines-dir", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    out = result.output.lower()
    assert "corrotta" in out          # messaggio dedicato all'entry malformata
    assert "non presente" not in out  # NON il messaggio fuorviante 'id assente'
