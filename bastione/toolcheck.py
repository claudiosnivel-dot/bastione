"""Gate di versione fail-closed per i tool esterni (R4, §4.2/§4.7).

`check_tool(name)` applica una policy (versione minima + denylist) leggendo la
versione reale del tool. Una versione vietata, sotto il minimo o NON LEGGIBILE
→ `ok=False` (fail-closed): il chiamante NON esegue il tool e emette `*_SKIPPED`
INFO col motivo (§26). Un tool senza policy → `ok=True` (ammesso).

`_read_version` è l'UNICO confine I/O: monkeypatchato nei test (nessun subprocess
reale), come i `_run_*` dei wrapper.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import NamedTuple

log = logging.getLogger("bastione.toolcheck")

# Policy iniziale (§4.2, LOCKED): CVE note nei tool.
TOOL_POLICY: dict[str, dict] = {
    "trivy": {"min": "0.72.0", "deny": ["0.69.4", "0.69.5", "0.69.6"]},
    "nuclei": {"min": "3.10.0", "deny": []},
}

_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_VERSION_TIMEOUT = 10


class ToolStatus(NamedTuple):
    ok: bool
    version: str | None
    reason: str


def _read_version(name: str) -> str | None:
    """Esegue `<name> --version` e ritorna l'output grezzo (stdout+stderr), o None
    se il binario è assente o l'esecuzione fallisce. Confine I/O monkeypatchabile."""
    if shutil.which(name) is None:
        return None
    try:
        # errors="replace": un banner con byte non decodificabili nel locale (cp1252
        # su Windows) non deve far crashare il confine I/O (§4.7).
        proc = subprocess.run([name, "--version"], capture_output=True, text=True,
                              errors="replace", timeout=_VERSION_TIMEOUT, check=False)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.warning("toolcheck: lettura versione di %r fallita: %s", name, exc)
        return None
    return (proc.stdout or "") + (proc.stderr or "")


def _extract_version(raw: str) -> str | None:
    """Primo `N.N.N` nell'output (gestisce `v3.10.0`, `Version: 0.72.0`, ecc.)."""
    m = _SEMVER_RE.search(raw or "")
    return m.group(0) if m else None


def _parse_semver(v: str) -> tuple[int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return (a, b, c)


def check_tool(name: str) -> ToolStatus:
    """Applica `TOOL_POLICY[name]` leggendo la versione reale (R4). Fail-closed."""
    policy = TOOL_POLICY.get(name)
    if policy is None:
        return ToolStatus(True, None, "nessuna policy: tool ammesso")
    raw = _read_version(name)
    if raw is None:
        return ToolStatus(False, None,
                          "versione non leggibile (fail-closed R4): tool non eseguito")
    ver = _extract_version(raw)
    if ver is None:
        return ToolStatus(False, None,
                          "versione non interpretabile dall'output (fail-closed R4)")
    if ver in policy.get("deny", []):
        return ToolStatus(False, ver,
                          f"versione {ver} VIETATA (CVE nota, R4): tool non eseguito")
    minimum = policy.get("min")
    if minimum and _parse_semver(ver) < _parse_semver(minimum):
        return ToolStatus(False, ver,
                          f"versione {ver} sotto il minimo {minimum} (R4): tool non eseguito")
    return ToolStatus(True, ver, f"versione {ver} ammessa")
