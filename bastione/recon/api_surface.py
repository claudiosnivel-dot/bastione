"""Scoperta della superficie API applicativa (M4.0).

`extract_api_paths` è una funzione PURA (nessun I/O): lavora sul testo del bundle
già in memoria (owned-only §7), come `extract_table_names` (§8). La ground truth
del probe sono gli endpoint DICHIARATI in [auth] (con metodo+kind); i path estratti
dal bundle sono un ASSIST per la copertura (analogo a SUPABASE_SCHEMA_VIA_BUNDLE)."""
from __future__ import annotations

import re

from bastione.models import ApiSurface, Fingerprint, TargetConfig

# Letterali stringa che iniziano per /api/ in un bundle JS. Caratteri ammessi in un
# path (lettere, cifre, _-/{}. ); url completi e spazi non matchano (non sono path).
_API_PATH_RE = re.compile(r"""['"](/api/[A-Za-z0-9_\-/{}.]+)['"]""")


def extract_api_paths(text: str) -> list[str]:
    """Path `/api/...` referenziati nel bundle (dedup + sort deterministico)."""
    return sorted({m.group(1) for m in _API_PATH_RE.finditer(text)})


def build_api_surface(fp: Fingerprint, cfg: TargetConfig) -> ApiSurface:
    """Combina endpoint DICHIARATI (ground truth) + path estratti (assist)."""
    declared = list(cfg.auth.api_endpoints) if (cfg.auth and cfg.auth.api_endpoints) else []
    return ApiSurface(endpoints=declared, extracted_paths=list(fp.discovered_api_paths))
