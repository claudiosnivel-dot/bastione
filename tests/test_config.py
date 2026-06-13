"""Test minimi per config.py (§5.6, §6 LOAD, §29).

Verifica: risoluzione `<n>.local.toml` con precedenza sul `<n>.toml`, flatten
delle tabelle annidate del TOML → `TargetConfig`, errore chiaro se il target non
esiste, e — importante per la separazione delle responsabilità — il fatto che
`config.py` *non* blocca produzione: caricarla è valido, è il gate (§7) ad
abortire in LOAD. Include un test d'integrazione sul vero `targets/_example.toml`.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from bastione.config import load_target, resolve_target_path
from bastione.enums import Severity

TARGETS_DIR = Path(__file__).resolve().parents[1] / "targets"

MINIMAL = """\
name = "g"
base_url = "https://staging.example"
environment = "staging"
ownership = "owned"
"""

FULL = """\
name = "gestionale"
base_url = "https://staging.example"
environment = "staging"
ownership = "owned"
ownership_token = "tok-123"

[supabase]
url = "https://abcdef.supabase.co"

[notify]
channel = "telegram"
min_severity = "high"

[[expectations.table]]
name = "clienti"
anon_select = false
anon_insert = false
[[expectations.table]]
name = "listino_pubblico"
anon_select = true

[modules]
disabled = ["zap"]
"""


def _write(dir_: Path, fname: str, body: str) -> None:
    (dir_ / fname).write_text(body, encoding="utf-8")


def test_resolve_prefers_local_toml(tmp_path: Path):
    _write(tmp_path, "g.toml", MINIMAL)
    _write(tmp_path, "g.local.toml", MINIMAL)
    assert resolve_target_path("g", tmp_path).name == "g.local.toml"


def test_resolve_uses_plain_when_no_local(tmp_path: Path):
    _write(tmp_path, "g.toml", MINIMAL)
    assert resolve_target_path("g", tmp_path).name == "g.toml"


def test_resolve_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        resolve_target_path("nope", tmp_path)


def test_local_content_wins_over_plain(tmp_path: Path):
    _write(tmp_path, "g.toml", MINIMAL)
    _write(tmp_path, "g.local.toml",
           MINIMAL.replace("https://staging.example", "https://real.local"))
    cfg = load_target("g", tmp_path)
    assert cfg.base_url == "https://real.local"


def test_load_flattens_nested_tables(tmp_path: Path):
    _write(tmp_path, "g.toml", FULL)
    cfg = load_target("g", tmp_path)
    assert cfg.supabase_url == "https://abcdef.supabase.co"
    assert cfg.notify_channel == "telegram"
    assert cfg.notify_min_severity is Severity.HIGH      # "high" → enum
    assert cfg.modules_disabled == ["zap"]
    assert [t.name for t in cfg.expectations] == ["clienti", "listino_pubblico"]
    assert cfg.expectations[0].anon_select is False
    assert cfg.expectations[1].anon_select is True


def test_load_defaults_when_optional_blocks_absent(tmp_path: Path):
    _write(tmp_path, "g.toml", MINIMAL)
    cfg = load_target("g", tmp_path)
    assert cfg.supabase_url is None
    assert cfg.notify_channel == "none"
    assert cfg.notify_min_severity is Severity.HIGH
    assert cfg.expectations == [] and cfg.modules_disabled == []


def test_load_invalid_environment_raises(tmp_path: Path):
    _write(tmp_path, "g.toml", MINIMAL.replace("staging", "prod"))
    with pytest.raises(ValidationError):
        load_target("g", tmp_path)


def test_config_does_not_block_production(tmp_path: Path):
    # Separazione (§6/§7): config.py carica anche 'production' senza errori.
    # È il gate (assert_preconditions, step 4) ad abortire — non config.
    _write(tmp_path, "g.toml", MINIMAL.replace("staging", "production"))
    cfg = load_target("g", tmp_path)
    assert cfg.environment == "production"


def test_example_toml_is_valid():
    # Integrazione: il template committato §29 deve parsare e validare.
    cfg = load_target("_example", TARGETS_DIR)
    assert cfg.environment == "staging"
    assert cfg.ownership == "owned"
    assert cfg.supabase_url is not None
    assert cfg.notify_min_severity is Severity.HIGH
    by_name = {t.name: t for t in cfg.expectations}
    assert by_name["clienti"].anon_select is False
    assert by_name["listino_pubblico"].anon_select is True
