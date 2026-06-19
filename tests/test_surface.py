"""Test dell'attack-surface inventory (M3) — il gemello della baseline per la
*superficie esposta*.

Copriamo:
- `build_snapshot`: estrae tabelle/endpoint/URL dalla `Fingerprint`, ordina e
  deduplica; lo `snapshot_id` è DETERMINISTICO — stesso contenuto in ordine
  diverso (e con duplicati) → stesso id;
- `diff_snapshots`: added/removed per categoria, liste ORDINATE; `old=None` →
  tutto added; `unchanged=True` quando i due snapshot sono identici;
- round-trip `save`/`load`; `load` di un file assente → `None`; file corrotto →
  `None` (resilienza, stile §16).

Test OFFLINE puri: nessuna rete, nessun subprocess; solo `tmp_path` per il
round-trip su filesystem locale.
"""

from datetime import datetime, timezone
from pathlib import Path

from bastione.models import Fingerprint, SurfaceSnapshot
from bastione.surface.inventory import (
    build_snapshot,
    diff_snapshots,
    load_surface_baseline,
    save_surface_baseline,
)

NOW = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)


def make_fp(
    *,
    target="g",
    tables=None,
    endpoints=None,
    urls=None,
):
    return Fingerprint(
        target=target,
        resolved_urls=urls if urls is not None else ["https://g.example/"],
        discovered_tables=tables if tables is not None else ["clienti", "ordini"],
        endpoints=endpoints if endpoints is not None else ["/rest/v1/clienti"],
    )


# ─── build_snapshot: estrazione + ordine/dedup + id deterministico ──────────

def test_build_snapshot_pulls_three_categories_from_fingerprint():
    fp = make_fp(
        tables=["ordini", "clienti"],
        endpoints=["/rest/v1/clienti", "/rest/v1/ordini"],
        urls=["https://g.example/b", "https://g.example/a"],
    )
    snap = build_snapshot(fp, taken_at=NOW)
    assert snap.target == "g"
    assert snap.taken_at == NOW
    # ordinati e deduplicati dal costruttore SurfaceSnapshot.build (T0).
    assert snap.tables == ["clienti", "ordini"]
    assert snap.endpoints == ["/rest/v1/clienti", "/rest/v1/ordini"]
    assert snap.urls == ["https://g.example/a", "https://g.example/b"]


def test_build_snapshot_sorts_and_dedups():
    fp = make_fp(
        tables=["b", "a", "a", "c"],
        endpoints=["/z", "/y", "/z"],
        urls=["https://g/2", "https://g/1", "https://g/1"],
    )
    snap = build_snapshot(fp, taken_at=NOW)
    assert snap.tables == ["a", "b", "c"]
    assert snap.endpoints == ["/y", "/z"]
    assert snap.urls == ["https://g/1", "https://g/2"]


def test_snapshot_id_is_16_hex_chars():
    snap = build_snapshot(make_fp(), taken_at=NOW)
    assert len(snap.snapshot_id) == 16
    assert all(c in "0123456789abcdef" for c in snap.snapshot_id)


def test_snapshot_id_deterministic_regardless_of_input_order():
    # Stesso contenuto, ordine di input diverso (e duplicati) → STESSO id:
    # il determinismo abilita il diff stabile (P7, "solo delta").
    a = build_snapshot(make_fp(
        tables=["clienti", "ordini"],
        endpoints=["/a", "/b"],
        urls=["https://g/1", "https://g/2"],
    ))
    b = build_snapshot(make_fp(
        tables=["ordini", "clienti", "clienti"],
        endpoints=["/b", "/a"],
        urls=["https://g/2", "https://g/1", "https://g/2"],
    ))
    assert a.snapshot_id == b.snapshot_id


def test_snapshot_id_differs_on_different_content():
    a = build_snapshot(make_fp(tables=["clienti"]))
    b = build_snapshot(make_fp(tables=["fatture"]))
    assert a.snapshot_id != b.snapshot_id


def test_snapshot_id_differs_when_token_moves_across_categories():
    # REGRESSIONE: lo stesso token che si sposta da una categoria all'altra
    # deve produrre snapshot_id DIVERSI. Il payload naive `"\n".join(t+e+u)`
    # appiattiva le tre liste senza delimitatore di categoria, così
    # tables=['x','y'] e tables=['x'],endpoints=['y'] collidevano (stesso id):
    # due superfici semanticamente diverse → stesso diff, violando P7.
    a = build_snapshot(make_fp(tables=["x", "y"], endpoints=[], urls=[]))
    b = build_snapshot(make_fp(tables=["x"], endpoints=["y"], urls=[]))
    # sanity: le superfici sono davvero diverse (il token ha cambiato categoria).
    assert a.tables == ["x", "y"] and a.endpoints == []
    assert b.tables == ["x"] and b.endpoints == ["y"]
    assert a.snapshot_id != b.snapshot_id


def test_snapshot_id_differs_for_token_in_each_of_the_three_categories():
    # Lo stesso token in ciascuna delle tre categorie → tre id distinti.
    in_tables = build_snapshot(make_fp(tables=["x"], endpoints=[], urls=[]))
    in_endpoints = build_snapshot(make_fp(tables=[], endpoints=["x"], urls=[]))
    in_urls = build_snapshot(make_fp(tables=[], endpoints=[], urls=["x"]))
    ids = {in_tables.snapshot_id, in_endpoints.snapshot_id, in_urls.snapshot_id}
    assert len(ids) == 3


def test_snapshot_id_distinguishes_newline_in_value():
    # REGRESSIONE: un valore che contiene '\n' non deve collidere con due valori
    # separati. Col join su '\n', tables=['a\nb'] e tables=['a','b'] davano lo
    # stesso payload e quindi lo stesso id; il payload JSON fa l'escape del
    # newline nel valore, eliminando la collisione.
    one_value_with_newline = build_snapshot(make_fp(tables=["a\nb"], endpoints=[], urls=[]))
    two_values = build_snapshot(make_fp(tables=["a", "b"], endpoints=[], urls=[]))
    assert one_value_with_newline.snapshot_id != two_values.snapshot_id


def test_snapshot_id_separates_categories():
    # REGRESSIONE: la distribuzione delle stringhe FRA categorie deve influenzare
    # l'id. Lo stesso insieme totale di stringhe ({'a','b'}) ma distribuito in
    # categorie diverse deve produrre id DIVERSI, non collidere.
    # Prima del fix: payload = "\n".join(t + e + u) → entrambi 'a\nb' → stesso id.
    only_tables = SurfaceSnapshot.build(
        target="g", tables=["a", "b"], endpoints=[], urls=[],
    )
    split = SurfaceSnapshot.build(
        target="g", tables=["a"], endpoints=["b"], urls=[],
    )
    assert only_tables.snapshot_id != split.snapshot_id


def test_snapshot_id_separates_categories_endpoints_vs_urls():
    # Anche per le altre due categorie: stesso insieme totale, ripartizione
    # diversa fra endpoints/urls → id diversi.
    a = SurfaceSnapshot.build(
        target="g", tables=[], endpoints=["x", "y"], urls=[],
    )
    b = SurfaceSnapshot.build(
        target="g", tables=[], endpoints=["x"], urls=["y"],
    )
    assert a.snapshot_id != b.snapshot_id


def test_snapshot_id_independent_of_taken_at():
    # L'id è funzione del solo *contenuto* della superficie, non del momento:
    # due run con lo stesso contenuto a istanti diversi hanno lo stesso id.
    a = build_snapshot(make_fp(), taken_at=NOW)
    b = build_snapshot(make_fp(), taken_at=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert a.snapshot_id == b.snapshot_id


# ─── diff_snapshots: added/removed, ordine, unchanged ───────────────────────

def test_diff_old_none_is_all_added():
    new = build_snapshot(make_fp(
        tables=["b", "a"],
        endpoints=["/y", "/x"],
        urls=["https://g/2", "https://g/1"],
    ), taken_at=NOW)
    diff = diff_snapshots(None, new)
    assert diff.target == "g"
    assert diff.added_tables == ["a", "b"]
    assert diff.added_endpoints == ["/x", "/y"]
    assert diff.added_urls == ["https://g/1", "https://g/2"]
    assert diff.removed_tables == []
    assert diff.removed_endpoints == []
    assert diff.removed_urls == []
    assert diff.unchanged is False


def test_diff_added_and_removed_per_category_sorted():
    old = build_snapshot(make_fp(
        tables=["clienti", "ordini"],
        endpoints=["/rest/v1/clienti", "/rest/v1/ordini"],
        urls=["https://g/a", "https://g/b"],
    ), taken_at=NOW)
    new = build_snapshot(make_fp(
        tables=["clienti", "fatture"],          # +fatture, -ordini
        endpoints=["/rest/v1/clienti", "/rest/v1/audit"],  # +audit, -ordini
        urls=["https://g/a", "https://g/c"],    # +c, -b
    ), taken_at=NOW)
    diff = diff_snapshots(old, new)
    assert diff.added_tables == ["fatture"]
    assert diff.removed_tables == ["ordini"]
    assert diff.added_endpoints == ["/rest/v1/audit"]
    assert diff.removed_endpoints == ["/rest/v1/ordini"]
    assert diff.added_urls == ["https://g/c"]
    assert diff.removed_urls == ["https://g/b"]
    assert diff.unchanged is False


def test_diff_lists_are_sorted_with_multiple_changes():
    old = build_snapshot(make_fp(tables=["a"], endpoints=["/a"], urls=["https://g/a"]), taken_at=NOW)
    new = build_snapshot(make_fp(
        tables=["z", "m", "b"],
        endpoints=["/z", "/m", "/b"],
        urls=["https://g/z", "https://g/m", "https://g/b"],
    ), taken_at=NOW)
    diff = diff_snapshots(old, new)
    assert diff.added_tables == ["b", "m", "z"]
    assert diff.added_endpoints == ["/b", "/m", "/z"]
    assert diff.added_urls == ["https://g/b", "https://g/m", "https://g/z"]


def test_diff_unchanged_when_identical():
    fp = make_fp(
        tables=["clienti", "ordini"],
        endpoints=["/rest/v1/clienti"],
        urls=["https://g/a"],
    )
    old = build_snapshot(fp, taken_at=NOW)
    # Stesso contenuto in ordine diverso → snapshot equivalente, diff vuoto.
    new = build_snapshot(make_fp(
        tables=["ordini", "clienti"],
        endpoints=["/rest/v1/clienti"],
        urls=["https://g/a"],
    ), taken_at=datetime(2030, 1, 1, tzinfo=timezone.utc))
    diff = diff_snapshots(old, new)
    assert diff.added_tables == [] and diff.removed_tables == []
    assert diff.added_endpoints == [] and diff.removed_endpoints == []
    assert diff.added_urls == [] and diff.removed_urls == []
    assert diff.unchanged is True
    # determinismo: lo stesso contenuto produce lo stesso id.
    assert old.snapshot_id == new.snapshot_id


def test_diff_is_deterministic():
    old = build_snapshot(make_fp(tables=["a", "b"]), taken_at=NOW)
    new = build_snapshot(make_fp(tables=["b", "c"]), taken_at=NOW)
    d1 = diff_snapshots(old, new)
    d2 = diff_snapshots(old, new)
    assert d1.model_dump() == d2.model_dump()


# ─── save / load: round-trip e resilienza (stile §16) ───────────────────────

def test_load_surface_baseline_none_when_missing(tmp_path: Path):
    assert load_surface_baseline(tmp_path / "non-esiste.surface.json") is None


def test_save_and_load_roundtrip(tmp_path: Path):
    path = tmp_path / "g.surface.json"
    snap = build_snapshot(make_fp(
        tables=["clienti", "ordini"],
        endpoints=["/rest/v1/clienti"],
        urls=["https://g/a"],
    ), taken_at=NOW)
    save_surface_baseline(path, snap)

    loaded = load_surface_baseline(path)
    assert loaded is not None
    assert loaded.target == "g"
    assert loaded.tables == ["clienti", "ordini"]
    assert loaded.endpoints == ["/rest/v1/clienti"]
    assert loaded.urls == ["https://g/a"]
    assert loaded.snapshot_id == snap.snapshot_id
    assert loaded.taken_at == NOW
    # round-trip stabile: re-diff contro l'originale → unchanged.
    assert diff_snapshots(snap, loaded).unchanged is True


def test_saved_file_uses_schema_alias_and_no_evidence(tmp_path: Path):
    import json as _json

    path = tmp_path / "g.surface.json"
    snap = build_snapshot(make_fp(), taken_at=NOW)
    save_surface_baseline(path, snap)
    raw = path.read_text(encoding="utf-8")
    data = _json.loads(raw)
    # Serializzato con l'alias "schema" (contratto persistito T0).
    assert data["schema"] == "bastione-surface/1"
    # Committabile: mai evidenze/segreti nel file di superficie.
    assert "evidence" not in raw
    assert "anon_key" not in raw


def test_load_surface_baseline_corrupt_returns_none(tmp_path: Path):
    path = tmp_path / "corrotto.surface.json"
    path.write_text("{ questo non e' JSON valido", encoding="utf-8")
    assert load_surface_baseline(path) is None


def test_load_surface_baseline_invalid_shape_returns_none(tmp_path: Path):
    # JSON valido ma non conforme al contratto SurfaceSnapshot (manca target):
    # degrada a None, non si crasha la pipeline (resilienza §16).
    path = tmp_path / "invalido.surface.json"
    path.write_text('{"schema": "bastione-surface/1", "tables": 123}', encoding="utf-8")
    assert load_surface_baseline(path) is None


def test_load_roundtrip_object_validates_as_snapshot(tmp_path: Path):
    # Sanity: ciò che torna da load è proprio un SurfaceSnapshot.
    path = tmp_path / "g.surface.json"
    save_surface_baseline(path, build_snapshot(make_fp(), taken_at=NOW))
    assert isinstance(load_surface_baseline(path), SurfaceSnapshot)
