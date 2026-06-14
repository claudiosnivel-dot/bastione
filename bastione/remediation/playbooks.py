"""Motore di rendering dei remediation playbook (§18).

Per ogni `rule_id`/`check_id` rilevante esiste un template Markdown azionabile in
`playbooks/<rule_id>.md` (alla root del repo, sibling di `bastione/`, `baselines/`,
`targets/` — struttura NORMATIVA §4). Questo modulo lo carica, lo renderizza con
Jinja2 a partire da un `context` costruito dal `Finding` (o dal `PostureCheck`) e
ritorna il Markdown pronto per essere iniettato nel report accanto al finding.

Contratto del context (§18) — chiavi disponibili nei template `{{ ... }}`:
  - ``title``            (str)  — titolo del finding/check.
  - ``severity``         (str)  — nome severità in maiuscolo (es. ``"HIGH"``).
  - ``target``           (str)  — URL/nome del target (per ``bastione verify --target``).
  - ``rule_id``          (str)  — il rule_id / check_id (chiave del playbook).
  - ``location``         (dict) — ``{url, endpoint, file, line}`` (può avere ``None``).
  - ``table``            (str)  — ultimo segmento dell'endpoint PostgREST
                                  (``/rest/v1/clienti`` → ``"clienti"``), ``""`` se assente.
  - ``evidence``         (str)  — evidence GIÀ REDATTA a monte (P8): mostrata così com'è.

Resilienza (§4.7):
  - template assente per un `rule_id` → ``render_playbook`` ritorna ``None`` (il
    report cade nel fallback "**Playbook:** <ref>"), MAI un crash;
  - jinja2 assente → lazy import che degrada con grazia (``_load_jinja_env`` → ``None``
    → ``render_playbook`` ritorna ``None``).

P8 (LOCKED): questo modulo NON de-redatta e NON espone segreti in chiaro.
L'``evidence`` entra nel context già redatta e viene resa invariata. Per i template
Markdown l'autoescape è **disabilitato** di proposito (il template è MD, non HTML:
l'autoescape HTML romperebbe la sintassi MD trasformando ``<``/``&``/apici in
entità). I valori del context provengono da finding interni già redatti, non da
input di rete arbitrario: nessuna superficie XSS, e la resa è destinata a un file
``.md``/terminale, non a un browser.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from bastione.enums import Severity
from bastione.models import Finding, PostureCheck

log = logging.getLogger("bastione.remediation")

# Root dei template, monkeypatchabile come `targets/` e `baselines/` (§4): default
# `playbooks/` ALLA ROOT del repo (sibling di `bastione/`). I test la redirigono a
# una dir temporanea nota; la produzione usa questa.
#
# ANCORATA AL PACKAGE, non alla CWD: i template sono contenuto-prodotto bundled (la
# sostanza dello step §18), non dati-utente come `targets/`/`baselines/`. Risolverli
# relativamente alla CWD li farebbe sparire silenziosamente da qualunque esecuzione
# fuori dalla root del repo (servizio, `pip install -e .` da altra dir). Il path è
# `<repo>/playbooks`, calcolato da questo file (bastione/remediation/playbooks.py →
# tre livelli su). Resta monkeypatchabile dai test.
PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"

# Whitelist sintattica STRETTA per `rule_id` (defense-in-depth, §4.7): solo
# maiuscole/cifre/underscore. Contiene il path PRIMA di toccare il filesystem,
# impedendo path-traversal (`../`) e componenti assoluti — e quindi qualunque
# lettura di `.md` arbitrari + SSTI sul contenuto caricato. I rule_id/check_id reali
# (RLS_DISABLED, POSTURE_RLS_<tabella>, ...) rispettano già questo formato; un
# `<tabella>` derivato dal target che NON lo rispetti degrada a None (no template).
_RULE_ID_RE = re.compile(r"[A-Z0-9_]+")


def _load_jinja_env() -> Any | None:
    """Lazy import di Jinja2 (§3/§4.7): ritorna un Environment, oppure ``None`` se
    la libreria non è installata (degrado con grazia).

    autoescape=False: i template sono Markdown, non HTML — vedi nota P8 nel docstring
    di modulo. ``StrictUndefined`` NON è usato: una chiave mancante nel context non
    deve far fallire il render (resilienza §4.7); Jinja rende l'undefined come vuoto.
    """
    try:
        from jinja2 import Environment  # lazy: l'assenza non deve rompere l'import
    except ImportError:  # pragma: no cover — jinja2 è in §3, ma degradiamo comunque
        log.debug("jinja2 non disponibile: i playbook non verranno renderizzati.")
        return None
    return Environment(
        autoescape=False,          # Markdown, non HTML (P8 documentata)
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render_playbook(rule_id: str | None, context: dict) -> str | None:
    """Renderizza ``playbooks/<rule_id>.md`` con ``context`` (§18).

    Ritorna il Markdown renderizzato, oppure ``None`` se:
      - ``rule_id`` è ``None``/vuoto;
      - non esiste un template per quel ``rule_id`` (il report usa il fallback);
      - jinja2 non è disponibile (degrado §4.7).

    Non solleva mai: ogni errore di I/O o di rendering degrada a ``None`` con un log.
    """
    if not rule_id:
        return None

    # Contenimento del path (defense-in-depth §4.7): `rule_id` è una stringa libera
    # che — per i posture check target-derivati (POSTURE_RLS_<tabella>) — può venire
    # da nomi-tabella controllati dal target. Senza guardia, un `rule_id` con `../`
    # o un componente assoluto leggerebbe un `.md` arbitrario e lo renderizzerebbe
    # come template Jinja2 (traversal + SSTI). Rifiutiamo PRIMA di costruire il path
    # tutto ciò che non è una whitelist sintattica stretta [A-Z0-9_].
    if not _RULE_ID_RE.fullmatch(rule_id):
        log.warning("rule_id non valido per un playbook (rifiutato): %r", rule_id)
        return None

    template_path = PLAYBOOKS_DIR / f"{rule_id}.md"

    # Cintura e bretelle: anche dopo la whitelist, verifichiamo il contenimento del
    # path risolto dentro PLAYBOOKS_DIR (la dir è monkeypatchabile; un default
    # diverso non deve mai permettere l'uscita dalla root dei template).
    try:
        base = PLAYBOOKS_DIR.resolve()
        resolved = template_path.resolve()
        if base != resolved and base not in resolved.parents:
            log.warning("path del playbook fuori da PLAYBOOKS_DIR (rifiutato): %r", rule_id)
            return None
    except OSError as exc:  # resolve() può fallire su path patologici: degrada
        log.warning("Risoluzione del path del playbook %r fallita: %s", rule_id, exc)
        return None

    if not template_path.is_file():
        return None

    env = _load_jinja_env()
    if env is None:
        return None

    try:
        source = template_path.read_text(encoding="utf-8")
        return env.from_string(source).render(**context)
    except Exception as exc:  # noqa: BLE001 — resilienza §4.7: mai crash dal render
        log.warning("Render del playbook %s fallito: %s", rule_id, exc)
        return None


# ─── Costruzione del context ──────────────────────────────────────────────────

def _severity_name(severity: Severity | str) -> str:
    """Nome severità in maiuscolo (es. ``"HIGH"``), robusto a enum o stringa."""
    return severity.name if isinstance(severity, Severity) else str(severity)


def _table_from_endpoint(endpoint: str | None) -> str:
    """Deriva il nome tabella dall'ultimo segmento di un endpoint PostgREST.

    ``/rest/v1/clienti`` → ``"clienti"``; ``/rest/v1/ordini?select=*`` → ``"ordini"``.
    Endpoint assente o senza segmenti → ``""`` (gestito, nessun crash).

    NON è una tabella la ROOT dell'API REST (``/rest/v1/`` o ``/rest/v1``): l'ultimo
    segmento lì è ``v1``, il segmento di VERSIONE di PostgREST, non una relazione.
    I finding di enumerazione schema (``SUPABASE_SCHEMA_VIA_BUNDLE`` /
    ``SUPABASE_SCHEMA_NOT_ENUMERABLE``) usano proprio ``endpoint="/rest/v1/"``: senza
    questa guardia il playbook RLS_DISABLED renderebbe ``table="v1"`` e produrrebbe
    SQL ATTIVAMENTE ERRATO (``ALTER TABLE public.v1 ...``, ``public.v1`` non esiste).
    Trattiamo quindi un segmento di versione ``^v\\d+$`` come "nessuna tabella" → ``""``.
    """
    if not endpoint:
        return ""
    # Scarta query string e frammento, poi prende l'ultimo segmento non vuoto.
    path = endpoint.split("?", 1)[0].split("#", 1)[0]
    segments = [s for s in path.split("/") if s]
    if not segments:
        return ""
    last = segments[-1]
    # Segmento di versione PostgREST (es. `v1`): non è una tabella → nessun nome.
    if re.fullmatch(r"v\d+", last):
        return ""
    return last


def _location_dict(loc) -> dict[str, Any]:
    """Espone la Location come dict semplice per i template (campi anche ``None``)."""
    return {
        "url": loc.url,
        "endpoint": loc.endpoint,
        "file": loc.file,
        "line": loc.line,
    }


def context_from_finding(f: Finding) -> dict[str, Any]:
    """Costruisce il context di rendering da un ``Finding`` (§18).

    L'``evidence`` è copiata così com'è: arriva già redatta a monte (P8), questo
    modulo non la trasforma.
    """
    return {
        "title": f.title,
        "severity": _severity_name(f.severity),
        "target": f.target,
        "rule_id": f.rule_id,
        "location": _location_dict(f.location),
        "table": _table_from_endpoint(f.location.endpoint),
        "evidence": f.evidence,
    }


def context_from_posture(c: PostureCheck) -> dict[str, Any]:
    """Costruisce il context di rendering da un ``PostureCheck`` (§18).

    I posture check non hanno una ``location`` né evidence: i campi assenti sono resi
    come stringa vuota / dict con ``None`` così che i template restino renderizzabili.
    """
    return {
        "title": c.title,
        "severity": _severity_name(c.severity_if_failed),
        "target": c.target,
        "rule_id": c.check_id,
        "location": {"url": None, "endpoint": None, "file": None, "line": None},
        "table": "",
        "evidence": c.detail,
    }
