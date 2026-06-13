"""Caricamento e validazione della config target (§5.6, §6 LOAD, §29).

`config.py` fa **solo** parse+validate del TOML → `TargetConfig`. Non applica i
guardrail di sicurezza: l'assert delle precondizioni (`assert_preconditions`,
§7) è compito del gate, invocato dall'orchestratore in fase LOAD. Tenere le due
cose separate è voluto — config produce il dato, il gate decide se è ammesso.

Risoluzione (§6 LOAD): `targets/<n>.local.toml` (config reale, gitignored) ha
precedenza su `targets/<n>.toml` (template committabile).
"""

from __future__ import annotations

from pathlib import Path

try:                                   # Python ≥3.11
    import tomllib
except ModuleNotFoundError:            # pragma: no cover — fallback <3.11 (§3)
    import tomli as tomllib            # type: ignore[no-redef]

from bastione.models import TargetConfig

DEFAULT_TARGETS_DIR = Path("targets")


def resolve_target_path(name: str, targets_dir: Path = DEFAULT_TARGETS_DIR) -> Path:
    """Restituisce il path della config per `name`, dando precedenza al
    `.local.toml` sul `.toml` (§6 LOAD). Solleva `FileNotFoundError` se nessuno
    dei due esiste."""
    local = targets_dir / f"{name}.local.toml"
    plain = targets_dir / f"{name}.toml"
    if local.exists():
        return local
    if plain.exists():
        return plain
    raise FileNotFoundError(
        f"Nessuna config per il target '{name}': attesi '{local}' "
        f"(config reale, gitignored) oppure '{plain}'. (§6 LOAD)"
    )


def load_target(name: str, targets_dir: Path = DEFAULT_TARGETS_DIR) -> TargetConfig:
    """Carica, appiattisce e valida il TOML del target → `TargetConfig`."""
    path = resolve_target_path(name, targets_dir)
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    return TargetConfig(**_flatten(data))


def _flatten(data: dict) -> dict:
    """Appiattisce le tabelle annidate del TOML (§29) nei campi piatti di
    `TargetConfig` (§5.6). I campi opzionali assenti vengono omessi così che
    valgano i default del modello; quelli obbligatori mancanti arrivano come
    `None` e fanno scattare un errore di validazione chiaro."""
    kwargs: dict = {
        "name": data.get("name"),
        "base_url": data.get("base_url"),
        "environment": data.get("environment"),
        "ownership": data.get("ownership"),
        "ownership_token": data.get("ownership_token"),
    }

    supabase = data.get("supabase") or {}
    if "url" in supabase:
        kwargs["supabase_url"] = supabase["url"]

    notify = data.get("notify") or {}
    if "channel" in notify:
        kwargs["notify_channel"] = notify["channel"]
    if "min_severity" in notify:
        kwargs["notify_min_severity"] = notify["min_severity"]

    tables = (data.get("expectations") or {}).get("table")
    if tables is not None:
        kwargs["expectations"] = tables

    modules = data.get("modules") or {}
    if "disabled" in modules:
        kwargs["modules_disabled"] = modules["disabled"]

    return kwargs
