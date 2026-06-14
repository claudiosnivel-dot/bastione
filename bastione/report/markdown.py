"""Generatore di report Markdown leggibile (§23).

Trasforma i risultati di una scan (finding, posture check, conteggi) in un
documento Markdown strutturato per consumo umano. Le priorità visive rispettano
il principio P7 ("solo delta"): in testa compaiono i NEW e il DRIFT
(posture check regrediti), cioè gli eventi che richiedono attenzione immediata.

GUARDRAIL M0 (P8 — evidence già redatta a monte):
  L'evidence viene mostrata COSÌ COM'È: `to_markdown` non de-redatta,
  non filtra, non trasforma il valore. La redazione avviene a monte (nei moduli
  di scanning); questo modulo è solo un renderer fedele.

Sezioni del documento:
  1. Intestazione — target, posture score, conteggi globali e per severità.
  2. NEW — finding con status NEW (nuovi pericoli).
     DRIFT — posture check con drift=True (regressioni da baseline).
  3. KNOWN — finding con status KNOWN o ACCEPTED (già noti, monitorati).
  4. FIXED — finding risolti rispetto alla baseline (vittorie).
  5. Checklist posture — tutti i PostureCheck con icona verde/rossa.
"""

from __future__ import annotations

import logging
from typing import Callable

from bastione.enums import Severity, Status
from bastione.models import Finding, PostureCheck
from bastione.remediation import playbooks

log = logging.getLogger("bastione.report")

# Tipo del seam iniettabile (§18): (rule_id, context) -> playbook Markdown | None.
# Iniettarlo invece di importarlo "rigido" rende il render testabile in isolamento
# (i test passano una fake deterministica) e mantiene l'I/O dei template DENTRO
# remediation/playbooks.py — markdown.py si limita a chiamarlo.
PlaybookRenderer = Callable[[str | None, dict], "str | None"]

# Icone per la checklist posture (§23).
_ICONA_PASSED = "✅"
_ICONA_FAILED = "❌"
_ICONA_DRIFT  = "⚠️ DRIFT"   # segnalazione di regressione da baseline


def to_markdown(
    *,
    target: str,
    posture_score: float,
    findings: list[Finding],
    fixed: list[Finding],
    posture_checks: list[PostureCheck],
    counts: dict,
    render_playbook: PlaybookRenderer = playbooks.render_playbook,
) -> str:
    """Genera il report Markdown di una scan (§23).

    Parametri:
        target          — URL/nome del target scansionato.
        posture_score   — Score pesato [0–100] calcolato da `posture.checks`.
        findings        — Finding emessi nella run (tutti gli status tranne FIXED).
        fixed           — Finding risolti rispetto alla baseline (status FIXED).
        posture_checks  — PostureCheck con eventuale drift valorizzato.
        counts          — Shape §24: new/known/fixed/drift + by_severity.
        render_playbook — Seam iniettabile (§18): dato un `rule_id`/`check_id` e un
                          context, ritorna il playbook Markdown renderizzato o `None`.
                          Default: il motore reale (`remediation.playbooks`). I test
                          passano una fake deterministica.

    Ritorna:
        Stringa Markdown UTF-8 pronta per essere scritta su file o inviata.
    """
    sezioni: list[str] = []

    # ── 1. Intestazione ────────────────────────────────────────────────────────
    sezioni.append(_intestazione(target, posture_score, counts))

    # ── 2. NEW + DRIFT (in testa — attenzione immediata) ──────────────────────
    new_findings = [f for f in findings if f.status is Status.NEW]
    drift_checks = [c for c in posture_checks if c.drift]

    sezioni.append(_sezione_new(new_findings, drift_checks, render_playbook))

    # ── 3. KNOWN (finding già noti: known + accepted) ─────────────────────────
    known_findings = [
        f for f in findings
        if f.status in (Status.KNOWN, Status.ACCEPTED)
    ]
    sezioni.append(_sezione_known(known_findings, render_playbook))

    # ── 4. FIXED (vittorie — risolti rispetto alla baseline) ──────────────────
    sezioni.append(_sezione_fixed(fixed))

    # ── 5. Checklist posture (tutti i check, con icona) ───────────────────────
    sezioni.append(_checklist_posture(posture_checks))

    return "\n\n".join(s for s in sezioni if s) + "\n"


# ─── Intestazione ─────────────────────────────────────────────────────────────

def _intestazione(target: str, posture_score: float, counts: dict) -> str:
    """Costruisce l'intestazione del report con target, score e conteggi."""
    by_sev = counts.get("by_severity", {})
    righe_sev = []
    # Ordine decrescente di criticità per leggibilità.
    for nome in ("critical", "high", "medium", "low", "info"):
        val = by_sev.get(nome, 0)
        righe_sev.append(f"  - {nome.upper()}: {val}")
    conteggi_sev = "\n".join(righe_sev)

    return (
        f"# Bastione — Security Report\n\n"
        f"**Target:** {target}  \n"
        f"**Posture Score:** {posture_score}/100\n\n"
        f"## Conteggi\n\n"
        f"| Stato  | N |\n"
        f"|--------|---|\n"
        f"| NEW    | {counts.get('new', 0)} |\n"
        f"| KNOWN  | {counts.get('known', 0)} |\n"
        f"| FIXED  | {counts.get('fixed', 0)} |\n"
        f"| DRIFT  | {counts.get('drift', 0)} |\n\n"
        f"**Per severità (finding emessi):**\n"
        f"{conteggi_sev}"
    )


# ─── Sezione NEW + DRIFT ───────────────────────────────────────────────────────

def _sezione_new(
    new_findings: list[Finding],
    drift_checks: list[PostureCheck],
    render_playbook: PlaybookRenderer,
) -> str:
    """Sezione NEW e DRIFT — gli eventi che richiedono attenzione immediata (P7)."""
    blocchi: list[str] = ["## NEW & DRIFT — Attenzione immediata"]

    if not new_findings and not drift_checks:
        blocchi.append("_Nessun nuovo finding né regressione di postura._")
        return "\n\n".join(blocchi)

    if new_findings:
        blocchi.append("### Finding NEW")
        for f in new_findings:
            blocchi.append(_render_finding(f, render_playbook))

    if drift_checks:
        blocchi.append("### Drift postura")
        for c in drift_checks:
            blocchi.append(_render_posture_drift(c, render_playbook))

    return "\n\n".join(blocchi)


# ─── Sezione KNOWN ────────────────────────────────────────────────────────────

def _sezione_known(
    known_findings: list[Finding],
    render_playbook: PlaybookRenderer,
) -> str:
    """Sezione KNOWN — finding già noti (known o accepted), monitorati."""
    blocchi: list[str] = ["## KNOWN — Finding già noti"]

    if not known_findings:
        blocchi.append("_Nessun finding noto._")
        return "\n\n".join(blocchi)

    for f in known_findings:
        blocchi.append(_render_finding(f, render_playbook))

    return "\n\n".join(blocchi)


# ─── Sezione FIXED ────────────────────────────────────────────────────────────

def _sezione_fixed(fixed: list[Finding]) -> str:
    """Sezione FIXED — finding risolti rispetto alla baseline (vittorie)."""
    blocchi: list[str] = ["## FIXED — Risolti"]

    if not fixed:
        blocchi.append("_Nessun finding risolto in questa run._")
        return "\n\n".join(blocchi)

    for f in fixed:
        # Un finding FIXED è già risolto: iniettare il "come ripararlo" sarebbe
        # rumore. Passiamo un renderer no-op → resta solo il riferimento testuale.
        blocchi.append(_render_finding(f, _no_playbook))

    return "\n\n".join(blocchi)


def _no_playbook(rule_id: str | None, context: dict) -> None:
    """Renderer no-op (§18): per le sezioni dove il playbook non va iniettato
    (es. FIXED, già risolti)."""
    return None


# ─── Checklist posture ────────────────────────────────────────────────────────

def _checklist_posture(posture_checks: list[PostureCheck]) -> str:
    """Checklist completa dei PostureCheck con icona verde/rossa (§23)."""
    blocchi: list[str] = ["## Checklist Posture"]

    if not posture_checks:
        blocchi.append("_Nessun posture check registrato._")
        return "\n\n".join(blocchi)

    righe: list[str] = []
    for c in posture_checks:
        if c.passed:
            icona = _ICONA_PASSED
            stato = "passed"
        else:
            icona = _ICONA_FAILED
            stato = "failed"

        drift_tag = f" {_ICONA_DRIFT}" if c.drift else ""
        riga = f"- {icona} **{c.title}** ({c.check_id}){drift_tag}  \n  _{c.detail}_ [{stato}]"
        righe.append(riga)

    blocchi.append("\n".join(righe))
    return "\n\n".join(blocchi)


# ─── Render di un singolo Finding ─────────────────────────────────────────────

def _render_finding(f: Finding, render_playbook: PlaybookRenderer) -> str:
    """Rappresentazione Markdown di un Finding (§23).

    Se esiste un template per il `remediation_ref` del finding, il playbook
    RENDERIZZATO viene iniettato sotto al finding (§18); altrimenti resta il
    fallback testuale "**Playbook:** `<ref>`".

    GUARDRAIL: l'evidence viene mostrata esattamente così com'è — già redatta a
    monte. Questo renderer NON de-redatta né trasforma il valore (P8 — §23).
    """
    sev = f.severity.name if isinstance(f.severity, Severity) else str(f.severity)
    stato = f.status.value if isinstance(f.status, Status) else str(f.status)

    loc = _render_location(f)
    remediation = (
        f"**Playbook:** `{f.remediation_ref}`" if f.remediation_ref
        else "_Nessun playbook associato._"
    )

    blocco = (
        f"#### [{sev}] {f.title} ({stato})\n\n"
        f"- **ID:** `{f.finding_id}`\n"
        f"- **Modulo:** {f.module} / `{f.rule_id}`\n"
        f"- **Posizione:** {loc}\n"
        f"- **Evidence:** `{f.evidence}`\n"
        f"- {remediation}"
    )
    return blocco + _playbook_block(
        render_playbook, f.remediation_ref, playbooks.context_from_finding(f)
    )


def _render_location(f: Finding) -> str:
    """Stringa compatta per la Location di un finding."""
    loc = f.location
    parts: list[str] = []
    if loc.url:
        parts.append(loc.url)
    if loc.endpoint:
        parts.append(loc.endpoint)
    if loc.file:
        suffix = f":{loc.line}" if loc.line else ""
        parts.append(f"{loc.file}{suffix}")
    return " ".join(parts) if parts else "_sconosciuta_"


# ─── Render di un PostureCheck in DRIFT ───────────────────────────────────────

def _render_posture_drift(c: PostureCheck, render_playbook: PlaybookRenderer) -> str:
    """Blocco descrittivo per un PostureCheck regredito (drift=True).

    Come per i finding, se esiste un template per il playbook del check (per chiave
    `remediation_ref`, con fallback al `check_id`) il playbook renderizzato viene
    iniettato sotto al drift (§18); altrimenti resta il fallback testuale.
    """
    sev = (
        c.severity_if_failed.name
        if isinstance(c.severity_if_failed, Severity)
        else str(c.severity_if_failed)
    )
    remediation = (
        f"**Playbook:** `{c.remediation_ref}`" if c.remediation_ref
        else "_Nessun playbook associato._"
    )
    blocco = (
        f"#### {_ICONA_DRIFT} [{sev}] {c.title} ({c.check_id})\n\n"
        f"- **Dettaglio:** {c.detail}\n"
        f"- {remediation}\n"
        f"- _In baseline era **passed**, ora è **failed** — regressione._"
    )
    # La chiave del playbook è il remediation_ref se presente, altrimenti il check_id
    # (i posture check usano il check_id come rule_id, es. POSTURE_HSTS — §18).
    ref = c.remediation_ref or c.check_id
    return blocco + _playbook_block(
        render_playbook, ref, playbooks.context_from_posture(c)
    )


def _playbook_block(
    render_playbook: PlaybookRenderer,
    rule_id: str | None,
    context: dict,
) -> str:
    """Renderizza e formatta il blocco playbook da iniettare sotto a un finding/drift.

    Ritorna stringa vuota se non esiste un template (degrado §4.7): in quel caso il
    finding mostra solo il fallback testuale già presente. Il render non solleva mai
    (la resilienza vive in `remediation.playbooks.render_playbook`)."""
    if not rule_id:
        return ""
    reso = render_playbook(rule_id, context)
    if not reso:
        return ""
    # Separato dal blocco-finding da una riga vuota; il playbook è già Markdown.
    return "\n\n" + reso
