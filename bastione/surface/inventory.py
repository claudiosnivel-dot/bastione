"""Attack-surface inventory & diff (M3) — il gemello della baseline per la
*superficie esposta* (non per i finding).

Tre pezzi, tutti PURI (zero rete, zero subprocess — i confini I/O sono solo
`load`/`save` che toccano il filesystem locale, stile `baseline/diff.py`):

- `build_snapshot`: da una `Fingerprint` (output di RECON, §8) estrae le tre
  categorie della superficie — tabelle scoperte, endpoint, URL risolti — le
  ordina+deduplica e calcola lo `snapshot_id` deterministico **per categoria
  distinta** (delega al costruttore `SurfaceSnapshot.build`, T0): stesso
  contenuto → stesso id, contenuto diverso → id diverso, a prescindere
  dall'ordine di input (P7, diff stabile).
- `diff_snapshots`: differenze di insiemi per categoria (added/removed), liste
  ORDINATE; `old=None` (prima run) → tutto added; `unchanged=True` quando non
  c'è nessun add/remove. Deterministico.
- `load_surface_baseline` / `save_surface_baseline`: JSON tollerante
  (`baselines/<target>.surface.json`), stesso stile di `load_baseline`/
  `save_baseline` (§16): file assente o corrotto → `None`, non si crasha la
  pipeline per uno snapshot malformato (resilienza). Il file è committabile —
  contiene solo nomi di superficie/date, mai evidenze.

Nessun git qui: il versionamento è dell'orchestratore.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from bastione.models import Fingerprint, SurfaceDiff, SurfaceSnapshot

log = logging.getLogger("bastione.surface")


# ─── build (Fingerprint → SurfaceSnapshot) ──────────────────────────────────

def build_snapshot(fp: Fingerprint, *, taken_at: datetime | None = None) -> SurfaceSnapshot:
    """Costruisce lo snapshot della superficie d'attacco da una `Fingerprint`.

    Le tre categorie sono prese dal recon (§8): `discovered_tables`, `endpoints`,
    `resolved_urls`. L'ordinamento, la deduplica e il calcolo dello `snapshot_id`
    deterministico **per categoria distinta** sono delegati al costruttore
    `SurfaceSnapshot.build` (T0): lo stesso contenuto produce lo stesso id, e
    contenuto diverso produce id diverso (P7, diff stabile), a prescindere
    dall'ordine di input. La distribuzione delle stringhe FRA categorie influenza
    l'id (le tre liste non vengono appiattite senza delimitatore), così superfici
    semanticamente diverse non collidono — vedi i test di regressione in
    `tests/test_surface.py`.
    """
    return SurfaceSnapshot.build(
        target=fp.target,
        tables=fp.discovered_tables,
        endpoints=fp.endpoints,
        urls=fp.resolved_urls,
        taken_at=taken_at,
    )


# ─── diff (delta tra due snapshot) ──────────────────────────────────────────

def diff_snapshots(old: SurfaceSnapshot | None, new: SurfaceSnapshot) -> SurfaceDiff:
    """Delta tra due snapshot della superficie: per ciascuna categoria, gli
    elementi *aggiunti* (in `new` ma non in `old`) e *rimossi* (in `old` ma non
    in `new`), come differenze di insiemi e con liste ORDINATE (deterministico).

    Prima run (`old=None`) → tutto in `new` è `added`, niente `removed`.
    `unchanged=True` quando non c'è nessun add/remove in nessuna categoria.
    """
    old_tables = set(old.tables) if old else set()
    old_endpoints = set(old.endpoints) if old else set()
    old_urls = set(old.urls) if old else set()

    added_tables = sorted(set(new.tables) - old_tables)
    removed_tables = sorted(old_tables - set(new.tables))
    added_endpoints = sorted(set(new.endpoints) - old_endpoints)
    removed_endpoints = sorted(old_endpoints - set(new.endpoints))
    added_urls = sorted(set(new.urls) - old_urls)
    removed_urls = sorted(old_urls - set(new.urls))

    unchanged = not (
        added_tables or removed_tables
        or added_endpoints or removed_endpoints
        or added_urls or removed_urls
    )

    return SurfaceDiff(
        target=new.target,
        added_tables=added_tables,
        removed_tables=removed_tables,
        added_endpoints=added_endpoints,
        removed_endpoints=removed_endpoints,
        added_urls=added_urls,
        removed_urls=removed_urls,
        unchanged=unchanged,
    )


# ─── load / save (JSON tollerante, stile baseline §16) ──────────────────────

def load_surface_baseline(path: str | Path) -> SurfaceSnapshot | None:
    """Carica `baselines/<target>.surface.json` come `SurfaceSnapshot`. Se il
    file non esiste ritorna `None` (prima run: ogni elemento sarà `added`).
    Degrada a `None` anche se il file è illeggibile/corrotto o non valida sul
    contratto — non si crasha la pipeline per uno snapshot malformato
    (resilienza, stesso stile di `load_baseline`, §16)."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return SurfaceSnapshot.model_validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        log.warning("surface baseline %s illeggibile (%s): la tratto come assente", path, exc)
        return None


def save_surface_baseline(path: str | Path, snapshot: SurfaceSnapshot) -> Path:
    """Scrive lo snapshot della superficie (M3) come JSON committabile. Il file
    contiene solo nomi di superficie/date e l'id deterministico: **mai evidenze**,
    come la baseline dei finding (§16). Serializza con l'alias `schema` per
    coerenza col contratto persistito (T0)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        snapshot.model_dump_json(by_alias=True, indent=2),
        encoding="utf-8",
    )
    return path
