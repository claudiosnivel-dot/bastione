"""Generatore di report HTML single-file (§23, decisione O02).

Stesso CONTENUTO del report Markdown (`report/markdown.py`), reso in un singolo
documento HTML5 **autocontenuto** (CSS e JS INLINE, nessun riferimento esterno),
tema **dark**, con un **posture gauge** visivo e **filtri** lato client per stato
e severità. È il formato condivisibile (§23 riga 899): un file solo, che si apre
offline identico.

Specchio di `to_markdown` (§18/§23): stessa firma, stessi input, stesso ordine —
header+score, NEW/DRIFT in testa, KNOWN, FIXED, limiti di verifica (§26, solo se ce
ne sono), checklist posture; ogni finding col suo playbook iniettabile
(`render_playbook`, seam §18).

GUARDRAIL (LOCKED):

  XSS (CRITICO) — l'HTML è un sink BROWSER. OGNI valore dinamico (title, evidence,
  location, target, rule_id, module, detail, testo dei playbook, nomi-tabella
  derivati dal target) viene HTML-escapato con `html.escape`, `quote=True` (così è
  sicuro anche nei contesti ATTRIBUTO). I dati possono derivare dal target
  (endpoint/tabelle dall'OpenAPI/bundle): un `<script>` o un `onerror=` nel
  contenuto NON deve mai eseguire. Nessun valore dinamico finisce in HTML
  non-escapato — questa è la lezione esplicitamente rimandata allo step 7.

  SINGLE-FILE / NO CDN (O02) — tutto inline. Nessun `<script src>`, `<link href>`,
  `@import url(http...)`, font/CSS/JS da CDN. Il documento è completo da solo.

  P8 — l'evidence arriva GIÀ redatta a monte: la mostriamo così com'è (escapata),
  senza de-redarre né aggiungere segreti.

  Additivo — questo modulo NON tocca SARIF/MD: aggiunge solo `report.html`.
"""

from __future__ import annotations

import html
import logging
from typing import Callable

from bastione.enums import Severity, Status
from bastione.models import Finding, PostureCheck
from bastione.remediation import playbooks
from bastione.report.markdown import is_verification_limit

log = logging.getLogger("bastione.report")

# Stesso seam iniettabile di markdown.py (§18): (rule_id, context) -> playbook MD | None.
PlaybookRenderer = Callable[[str | None, dict], "str | None"]

# Soglie delle fasce del gauge (§17): verde ≥ 80, giallo ≥ 50, rosso sotto.
_FASCIA_BUONA = 80.0
_FASCIA_MEDIA = 50.0

# Colori delle fasce (coerenti col tema dark) — usati per l'arco del gauge.
_COL_BUONA = "#4ade80"   # verde
_COL_MEDIA = "#fbbf24"   # giallo
_COL_BASSA = "#f87171"   # rosso


# ─── Helper di escaping (il cuore di sicurezza §23/XSS) ───────────────────────

def _esc(value: object) -> str:
    """HTML-escape SICURO di qualunque valore dinamico (quote=True).

    `quote=True` escapa anche `"` e `'`, rendendo il valore sicuro pure nei contesti
    ATTRIBUTO (es. `title="..."`, `data-...="..."`): un payload `"><img onerror=...>`
    viene neutralizzato. Vale per testo E attributi: usiamo SEMPRE questa helper su
    OGNI valore che provenga (anche indirettamente) dal target o dai finding.
    """
    return html.escape(str(value), quote=True)


def to_html(
    *,
    target: str,
    posture_score: float,
    findings: list[Finding],
    fixed: list[Finding],
    posture_checks: list[PostureCheck],
    counts: dict,
    render_playbook: PlaybookRenderer = playbooks.render_playbook,
    not_reverified: list[Finding] | None = None,
) -> str:
    """Genera il report HTML single-file di una scan (§23, O02).

    Firma e input identici a `report.markdown.to_markdown` (stessi dati, stesso
    ordine): vedi quel modulo per la semantica dei parametri. Ritorna una stringa
    HTML5 completa, autocontenuta (CSS/JS inline), pronta per essere scritta su file.
    """
    new_findings = [f for f in findings if f.status is Status.NEW]
    drift_checks = [c for c in posture_checks if c.drift]
    known_findings = [
        f for f in findings if f.status in (Status.KNOWN, Status.ACCEPTED)
    ]

    corpo: list[str] = []
    corpo.append(_intestazione(target, posture_score, counts))
    corpo.append(_barra_filtri())
    corpo.append(_sezione_new(new_findings, drift_checks, render_playbook))
    corpo.append(_sezione_known(known_findings, render_playbook))
    corpo.append(_sezione_fixed(fixed))
    corpo.append(_sezione_non_riverificati(not_reverified or []))  # S16: vuota se nulla
    corpo.append(_sezione_limiti_html(findings))   # §26/R6: vuota se nessun limite
    corpo.append(_checklist_posture(posture_checks))

    main = "\n".join(s for s in corpo if s)
    return (
        "<!doctype html>\n"
        '<html lang="it">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Bastione — Report {_esc(target)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        f'<main class="wrap">\n{main}\n</main>\n'
        f"<script>{_JS}</script>\n"
        "</body>\n"
        "</html>\n"
    )


# ─── Intestazione + posture gauge ─────────────────────────────────────────────

def _intestazione(target: str, posture_score: float, counts: dict) -> str:
    """Header con target, posture score, GAUGE visivo e conteggi per stato/severità."""
    by_sev = counts.get("by_severity", {})
    righe_sev = []
    for nome in ("critical", "high", "medium", "low", "info"):
        val = by_sev.get(nome, 0)
        righe_sev.append(
            f'<span class="sev sev-{nome}">{nome.upper()}: {_esc(val)}</span>'
        )
    chip_sev = "\n".join(righe_sev)

    conteggi_stato = (
        '<table class="counts">\n'
        "<thead><tr><th>Stato</th><th>N</th></tr></thead>\n"
        "<tbody>\n"
        f"<tr><td>NEW</td><td>{_esc(counts.get('new', 0))}</td></tr>\n"
        f"<tr><td>KNOWN</td><td>{_esc(counts.get('known', 0))}</td></tr>\n"
        f"<tr><td>FIXED</td><td>{_esc(counts.get('fixed', 0))}</td></tr>\n"
        f"<tr><td>DRIFT</td><td>{_esc(counts.get('drift', 0))}</td></tr>\n"
        + (f"<tr><td>NON RI-VERIFICATI</td>"
           f"<td>{_esc(counts['not_reverified'])}</td></tr>\n"
           if counts.get("not_reverified") else "")
        +
        "</tbody>\n"
        "</table>"
    )

    return (
        "<header>\n"
        "<h1>Bastione — Security Report</h1>\n"
        f'<p class="target"><strong>Target:</strong> {_esc(target)}</p>\n'
        '<div class="header-grid">\n'
        f"{_gauge(posture_score)}\n"
        f'<div class="counts-box">\n{conteggi_stato}\n'
        f'<div class="sev-chips">{chip_sev}</div>\n'
        "</div>\n"
        "</div>\n"
        "</header>"
    )


def _gauge(posture_score: float) -> str:
    """Posture GAUGE: un anello SVG inline (semicerchio) colorato per fascia (§17).

    SVG INLINE (nessuna risorsa esterna): un arco di sfondo + un arco di progresso la
    cui lunghezza è proporzionale allo score 0–100. Tutto autocontenuto, niente CDN.
    """
    # Clamp difensivo: lo score atteso è 0–100, ma non ci fidiamo ciecamente.
    try:
        val = float(posture_score)
    except (TypeError, ValueError):
        val = 0.0
    val = max(0.0, min(100.0, val))

    if val >= _FASCIA_BUONA:
        colore = _COL_BUONA
    elif val >= _FASCIA_MEDIA:
        colore = _COL_MEDIA
    else:
        colore = _COL_BASSA

    # Cerchio: r=80, circonferenza ≈ 502.65. L'offset disegna la frazione di score.
    raggio = 80.0
    circonferenza = 2 * 3.141592653589793 * raggio
    offset = circonferenza * (1.0 - val / 100.0)

    score_txt = _esc(posture_score)
    return (
        '<div class="gauge" role="img" '
        f'aria-label="Posture score {score_txt} su 100">\n'
        '<svg viewBox="0 0 200 200" width="180" height="180">\n'
        '<circle cx="100" cy="100" r="80" fill="none" stroke="#2a2f3a" '
        'stroke-width="18"></circle>\n'
        '<circle cx="100" cy="100" r="80" fill="none" '
        f'stroke="{colore}" stroke-width="18" stroke-linecap="round" '
        f'stroke-dasharray="{circonferenza:.2f}" '
        f'stroke-dashoffset="{offset:.2f}" '
        'transform="rotate(-90 100 100)"></circle>\n'
        f'<text x="100" y="96" text-anchor="middle" class="gauge-val" '
        f'fill="{colore}">{score_txt}</text>\n'
        '<text x="100" y="124" text-anchor="middle" class="gauge-sub">/ 100</text>\n'
        "</svg>\n"
        '<div class="gauge-label">Posture Score</div>\n'
        "</div>"
    )


# ─── Barra filtri (pilotata dal JS inline) ────────────────────────────────────

def _barra_filtri() -> str:
    """Controlli di filtro per stato e severità (il JS inline reagisce ai `change`).

    Valori STATICI noti (non derivano dal target): sicuri, ma li scriviamo comunque
    in chiaro controllato. Il JS legge `data-status`/`data-severity` sui finding."""
    return (
        '<section class="filters" aria-label="Filtri">\n'
        '<label>Stato\n'
        '<select id="f-status">\n'
        '<option value="all">Tutti</option>\n'
        '<option value="new">NEW</option>\n'
        '<option value="drift">DRIFT</option>\n'
        '<option value="known">KNOWN</option>\n'
        '<option value="fixed">FIXED</option>\n'
        "</select>\n"
        "</label>\n"
        '<label>Severità\n'
        '<select id="f-severity">\n'
        '<option value="all">Tutte</option>\n'
        '<option value="critical">CRITICAL</option>\n'
        '<option value="high">HIGH</option>\n'
        '<option value="medium">MEDIUM</option>\n'
        '<option value="low">LOW</option>\n'
        '<option value="info">INFO</option>\n'
        "</select>\n"
        "</label>\n"
        "</section>"
    )


# ─── Sezione NEW + DRIFT (in testa) ───────────────────────────────────────────

def _sezione_new(
    new_findings: list[Finding],
    drift_checks: list[PostureCheck],
    render_playbook: PlaybookRenderer,
) -> str:
    blocchi: list[str] = [
        '<section class="block block-new">',
        "<h2>NEW &amp; DRIFT — Attenzione immediata</h2>",
    ]
    if not new_findings and not drift_checks:
        blocchi.append("<p class=\"empty\">Nessun nuovo finding né regressione di postura.</p>")
        blocchi.append("</section>")
        return "\n".join(blocchi)

    if new_findings:
        blocchi.append("<h3>Finding NEW</h3>")
        for f in new_findings:
            blocchi.append(_render_finding(f, render_playbook))
    if drift_checks:
        blocchi.append("<h3>Drift postura</h3>")
        for c in drift_checks:
            blocchi.append(_render_posture_drift(c, render_playbook))

    blocchi.append("</section>")
    return "\n".join(blocchi)


# ─── Sezione KNOWN ────────────────────────────────────────────────────────────

def _sezione_known(
    known_findings: list[Finding],
    render_playbook: PlaybookRenderer,
) -> str:
    blocchi: list[str] = [
        '<section class="block block-known">',
        "<h2>KNOWN — Finding già noti</h2>",
    ]
    if not known_findings:
        blocchi.append('<p class="empty">Nessun finding noto.</p>')
    else:
        for f in known_findings:
            blocchi.append(_render_finding(f, render_playbook))
    blocchi.append("</section>")
    return "\n".join(blocchi)


# ─── Sezione FIXED ────────────────────────────────────────────────────────────

def _sezione_fixed(fixed: list[Finding]) -> str:
    blocchi: list[str] = [
        '<section class="block block-fixed">',
        "<h2>FIXED — Risolti</h2>",
    ]
    if not fixed:
        blocchi.append('<p class="empty">Nessun finding risolto in questa run.</p>')
    else:
        # Come nel MD: un FIXED è già risolto → niente playbook (renderer no-op).
        for f in fixed:
            blocchi.append(_render_finding(f, _no_playbook))
    blocchi.append("</section>")
    return "\n".join(blocchi)


def _no_playbook(rule_id: str | None, context: dict) -> None:
    """Renderer no-op (§18): per le sezioni dove il playbook non va iniettato (FIXED)."""
    return None


# ─── Sezione NON RI-VERIFICATI (S16, R6) ──────────────────────────────────────

def _sezione_non_riverificati(items: list[Finding]) -> str:
    """Specchio HTML della sezione MD: finding in baseline che la run non poteva
    ri-controllare. Tutto escapato: rule_id/modulo vengono dal file di baseline."""
    if not items:
        return ""
    righe = [
        '<section class="block block-known">',
        "<h2>NON RI-VERIFICATI — restano aperti</h2>",
        '<p class="empty">Erano in baseline e non compaiono in questa run, ma questa '
        "run non poteva ri-controllarli: <strong>non sono risolti</strong>. Rilancia "
        "con il livello indicato.</p>",
        "<ul>",
    ]
    for f in items:
        righe.append(
            f"<li><code>{_esc(f.rule_id)}</code> (id <code>{_esc(f.finding_id)}</code>, "
            f"modulo <code>{_esc(f.module)}</code>, stato "
            f"{_esc(f.status.value.upper())}): {_esc(f.description)}</li>")
    righe.extend(["</ul>", "</section>"])
    return "\n".join(righe)


# ─── Limiti di verifica (§26 / R6) ────────────────────────────────────────────

def _sezione_limiti_html(findings: list[Finding]) -> str:
    """Sezione "Limiti di verifica (§26)": ciò che Bastione NON ha potuto verificare.

    Stesso contenuto della sezione MD (stessa predicata `is_verification_limit`).
    XSS GUARD (§23): rule_id, title ed evidence possono derivare dal target → ogni
    valore dinamico passa per `_esc` (quote=True). Non sono card `.finding`: niente
    `data-status`/`data-severity`, quindi i filtri JS non nascondono mai un limite.
    Ritorna stringa vuota se non ci sono limiti (nessuna sezione orfana)."""
    limiti = [f for f in findings if is_verification_limit(f)]
    if not limiti:
        return ""
    items = "".join(
        f"<li>⚠️ <strong>{_esc(f.rule_id)}</strong> — {_esc(f.title)}: {_esc(f.evidence)}</li>"
        for f in limiti)
    return ('<section class="limiti"><h2>Limiti di verifica (§26)</h2>'
            '<p>Ciò che Bastione <em>non</em> ha potuto verificare (R6):</p>'
            f'<ul>{items}</ul></section>')


# ─── Checklist posture ────────────────────────────────────────────────────────

def _checklist_posture(posture_checks: list[PostureCheck]) -> str:
    blocchi: list[str] = [
        '<section class="block block-posture">',
        "<h2>Checklist Posture</h2>",
    ]
    if not posture_checks:
        blocchi.append('<p class="empty">Nessun posture check registrato.</p>')
        blocchi.append("</section>")
        return "\n".join(blocchi)

    blocchi.append('<ul class="posture-list">')
    for c in posture_checks:
        if c.passed:
            icona, stato, cls = "✅", "passed", "pass"
        else:
            icona, stato, cls = "❌", "failed", "fail"
        drift_tag = ' <span class="drift-tag">⚠️ DRIFT</span>' if c.drift else ""
        blocchi.append(
            f'<li class="posture-item posture-{cls}">'
            f'<span class="icon">{icona}</span> '
            f"<strong>{_esc(c.title)}</strong> "
            f'<code>{_esc(c.check_id)}</code>{drift_tag}'
            f'<div class="detail">{_esc(c.detail)} '
            f'<span class="state">[{_esc(stato)}]</span></div>'
            "</li>"
        )
    blocchi.append("</ul>")
    blocchi.append("</section>")
    return "\n".join(blocchi)


# ─── Render di un singolo Finding ─────────────────────────────────────────────

def _render_finding(f: Finding, render_playbook: PlaybookRenderer) -> str:
    """Card HTML di un Finding (§23). Tutti i valori dinamici sono escapati (_esc).

    GUARDRAIL P8: l'evidence è mostrata invariata (già redatta a monte), solo escapata.
    Gli attributi `data-status`/`data-severity` (valori canonici, lowercase) pilotano
    i filtri JS; il loro valore passa comunque per `_esc` (quote=True) per difesa."""
    sev = f.severity.name if isinstance(f.severity, Severity) else str(f.severity)
    stato = f.status.value if isinstance(f.status, Status) else str(f.status)

    # Filtro per stato: un finding ACCEPTED è renderizzato SOTTO la sezione KNOWN
    # (vedi `_sezione_known`, raggruppa KNOWN+ACCEPTED). Il `<select>` offre l'opzione
    # KNOWN ma non ACCEPTED, quindi mappiamo il suo `data-status` su "known" così che
    # selezionando KNOWN la card resti visibile (coerenza con la sezione che la ospita).
    # L'etichetta visibile (`status-tag`) resta "accepted" — non perdiamo informazione.
    stato_filtro = "known" if stato.lower() == Status.ACCEPTED.value else stato.lower()

    loc = _render_location(f)
    if f.remediation_ref:
        remediation = f"<strong>Playbook:</strong> <code>{_esc(f.remediation_ref)}</code>"
    else:
        remediation = '<em>Nessun playbook associato.</em>'

    playbook_html = _playbook_block(
        render_playbook, f.remediation_ref, playbooks.context_from_finding(f)
    )

    return (
        '<article class="finding" '
        f'data-status="{_esc(stato_filtro)}" '
        f'data-severity="{_esc(sev.lower())}">\n'
        f'<h4><span class="badge badge-{_esc(sev.lower())}">{_esc(sev)}</span> '
        f"{_esc(f.title)} <span class=\"status-tag\">({_esc(stato)})</span></h4>\n"
        '<dl class="meta">\n'
        f"<dt>ID</dt><dd><code>{_esc(f.finding_id)}</code></dd>\n"
        f"<dt>Modulo</dt><dd>{_esc(f.module)} / <code>{_esc(f.rule_id)}</code></dd>\n"
        f"<dt>Posizione</dt><dd>{loc}</dd>\n"
        f"<dt>Evidence</dt><dd><code>{_esc(f.evidence)}</code></dd>\n"
        f"<dt>Remediation</dt><dd>{remediation}</dd>\n"
        "</dl>\n"
        f"{playbook_html}"
        "</article>"
    )


def _render_location(f: Finding) -> str:
    """Stringa compatta (escapata) per la Location di un finding."""
    loc = f.location
    parts: list[str] = []
    if loc.url:
        parts.append(_esc(loc.url))
    if loc.endpoint:
        parts.append(_esc(loc.endpoint))
    if loc.file:
        suffix = f":{_esc(loc.line)}" if loc.line else ""
        parts.append(f"{_esc(loc.file)}{suffix}")
    return " ".join(parts) if parts else "<em>sconosciuta</em>"


# ─── Render di un PostureCheck in DRIFT ───────────────────────────────────────

def _render_posture_drift(c: PostureCheck, render_playbook: PlaybookRenderer) -> str:
    """Card di un PostureCheck regredito (drift=True). Valori escapati (_esc)."""
    sev = (
        c.severity_if_failed.name
        if isinstance(c.severity_if_failed, Severity)
        else str(c.severity_if_failed)
    )
    if c.remediation_ref:
        remediation = f"<strong>Playbook:</strong> <code>{_esc(c.remediation_ref)}</code>"
    else:
        remediation = "<em>Nessun playbook associato.</em>"

    # La chiave del playbook è il remediation_ref se presente, altrimenti il check_id.
    ref = c.remediation_ref or c.check_id
    playbook_html = _playbook_block(
        render_playbook, ref, playbooks.context_from_posture(c)
    )

    return (
        '<article class="finding drift" '
        f'data-status="drift" data-severity="{_esc(sev.lower())}">\n'
        f'<h4><span class="drift-tag">⚠️ DRIFT</span> '
        f'<span class="badge badge-{_esc(sev.lower())}">{_esc(sev)}</span> '
        f"{_esc(c.title)} <code>{_esc(c.check_id)}</code></h4>\n"
        '<dl class="meta">\n'
        f"<dt>Dettaglio</dt><dd>{_esc(c.detail)}</dd>\n"
        f"<dt>Remediation</dt><dd>{remediation}</dd>\n"
        "</dl>\n"
        '<p class="regression"><em>In baseline era <strong>passed</strong>, '
        "ora è <strong>failed</strong> — regressione.</em></p>\n"
        f"{playbook_html}"
        "</article>"
    )


def _playbook_block(
    render_playbook: PlaybookRenderer,
    rule_id: str | None,
    context: dict,
) -> str:
    """Renderizza e formatta (in modo SICURO) il blocco playbook sotto a un finding.

    Il playbook è Markdown: NON lo interpretiamo come HTML. Lo mostriamo dentro un
    `<details><pre>` col testo ESCAPATO (`_esc`) — così resta leggibile (il MD è
    pensato per essere letto) ma un eventuale `<script>` nel template non esegue mai.
    Ritorna stringa vuota se non c'è template (degrado §4.7), come nel MD."""
    if not rule_id:
        return ""
    reso = render_playbook(rule_id, context)
    if not reso:
        return ""
    return (
        '<details class="playbook">\n'
        "<summary>Playbook di remediation</summary>\n"
        f"<pre>{_esc(reso)}</pre>\n"
        "</details>\n"
    )


# ─── CSS inline (tema dark) ───────────────────────────────────────────────────
# Nessuna risorsa esterna: niente @import, niente font da CDN. Tutto qui.

_CSS = """
:root{
  --bg:#0f1115; --panel:#171a21; --panel2:#1d212b; --border:#2a2f3a;
  --fg:#e6e8ee; --muted:#9aa3b2; --accent:#60a5fa;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:24px}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.25rem;margin:1.5rem 0 .75rem;border-bottom:1px solid var(--border);
  padding-bottom:.35rem}
h3{font-size:1.05rem;color:var(--muted);margin:1rem 0 .5rem}
h4{font-size:1rem;margin:0 0 .5rem}
code{background:var(--panel2);padding:.1em .35em;border-radius:4px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em;
  word-break:break-word}
header{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:20px}
.target{color:var(--muted);margin:.25rem 0 1rem}
.header-grid{display:flex;gap:24px;flex-wrap:wrap;align-items:center}
.gauge{text-align:center}
.gauge svg{display:block}
.gauge-val{font-size:2.4rem;font-weight:700}
.gauge-sub{font-size:.9rem;fill:var(--muted)}
.gauge-label{color:var(--muted);font-size:.85rem;margin-top:4px}
.counts-box{flex:1;min-width:240px}
table.counts{border-collapse:collapse;width:100%;max-width:320px}
table.counts th,table.counts td{border:1px solid var(--border);
  padding:.35rem .6rem;text-align:left}
table.counts th{background:var(--panel2);color:var(--muted)}
.sev-chips{margin-top:.75rem;display:flex;gap:.4rem;flex-wrap:wrap}
.sev{font-size:.75rem;padding:.15rem .5rem;border-radius:999px;
  border:1px solid var(--border)}
.sev-critical{background:#3a0d12;color:#fda4af}
.sev-high{background:#3a230d;color:#fdba74}
.sev-medium{background:#3a350d;color:#fde047}
.sev-low{background:#0d2a3a;color:#7dd3fc}
.sev-info{background:#1d212b;color:#9aa3b2}
.filters{display:flex;gap:1rem;flex-wrap:wrap;margin:1.25rem 0;
  background:var(--panel);border:1px solid var(--border);border-radius:10px;
  padding:12px 16px}
.filters label{display:flex;flex-direction:column;font-size:.8rem;
  color:var(--muted);gap:.25rem}
.filters select{background:var(--panel2);color:var(--fg);
  border:1px solid var(--border);border-radius:6px;padding:.35rem .5rem;
  font-size:.9rem}
.block{margin-top:1.5rem}
.empty{color:var(--muted);font-style:italic}
.finding{background:var(--panel);border:1px solid var(--border);
  border-left:4px solid var(--border);border-radius:10px;padding:14px 16px;
  margin:.75rem 0}
.finding.drift{border-left-color:var(--col-medium,#fbbf24)}
.badge{display:inline-block;font-size:.7rem;font-weight:700;padding:.1rem .45rem;
  border-radius:5px;vertical-align:middle;margin-right:.35rem}
.badge-critical{background:#7f1d1d;color:#fff}
.badge-high{background:#9a3412;color:#fff}
.badge-medium{background:#854d0e;color:#fff}
.badge-low{background:#075985;color:#fff}
.badge-info{background:#334155;color:#e2e8f0}
.status-tag{color:var(--muted);font-weight:400;font-size:.85rem}
.drift-tag{color:#fbbf24;font-weight:700;font-size:.8rem}
dl.meta{display:grid;grid-template-columns:auto 1fr;gap:.2rem .75rem;margin:.5rem 0 0}
dl.meta dt{color:var(--muted);font-size:.8rem}
dl.meta dd{margin:0;word-break:break-word}
details.playbook{margin-top:.6rem;background:var(--panel2);
  border:1px solid var(--border);border-radius:8px;padding:.5rem .75rem}
details.playbook summary{cursor:pointer;color:var(--accent);font-size:.85rem}
details.playbook pre{white-space:pre-wrap;word-break:break-word;margin:.5rem 0 0;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;
  color:var(--fg)}
.posture-list{list-style:none;padding:0;margin:0}
.posture-item{background:var(--panel);border:1px solid var(--border);
  border-radius:8px;padding:.6rem .8rem;margin:.4rem 0}
.posture-item .detail{color:var(--muted);font-size:.85rem;margin-top:.2rem}
.posture-fail{border-left:4px solid #f87171}
.posture-pass{border-left:4px solid #4ade80}
.hidden{display:none}
"""


# ─── JS inline (filtri vanilla — nessun framework, nessun CDN) ────────────────
# Legge i <select> e mostra/nasconde le card .finding in base a data-status /
# data-severity. Nessuna fetch, nessuna risorsa esterna. Difesa: il JS NON
# interpola mai dati dinamici (è statico), tutto il contenuto variabile è già
# escapato server-side.

_JS = """
(function(){
  var fs=document.getElementById('f-status');
  var fv=document.getElementById('f-severity');
  if(!fs||!fv)return;
  function apply(){
    var st=fs.value, sv=fv.value;
    var cards=document.querySelectorAll('.finding');
    for(var i=0;i<cards.length;i++){
      var c=cards[i];
      var okS=(st==='all')||(c.getAttribute('data-status')===st);
      var okV=(sv==='all')||(c.getAttribute('data-severity')===sv);
      if(okS&&okV){c.classList.remove('hidden');}
      else{c.classList.add('hidden');}
    }
  }
  fs.addEventListener('change',apply);
  fv.addEventListener('change',apply);
})();
"""
