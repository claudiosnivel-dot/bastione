"""Agent Remediation Bundle (§18-bis) — la resa *machine-consumable* della stessa
conoscenza di remediation dei playbook umani (§18).

§18 produce remediation per un **umano** (clicca qui nella dashboard); questo modulo
la produce per un **agente di coding** (Claude Code, Codex, …): un bundle che
l'agente esegue *senza interpretare*. La chiave di mapping è la stessa dei playbook:
il ``rule_id`` → un ``FixBuilder`` auto-registrato.

Output (fase REMEDIATE, §18-bis.2) — un ARTEFATTO LOCALE in ``runs/<target>/<ts>/fix/``::

    fix/
    ├── FIX-PLAN.md          # umano + agente: piano ordinato, con preambolo-istruzioni
    ├── fix-plan.json        # contratto machine-readable (schema bastione-fixplan/1)
    └── migrations/          # SOLO per sql_migration: file .sql letterali pronti
        └── <finding_id>_<slug>.sql

GUARDRAIL (LOCKED, §7/§18-bis.5):
  - La generazione del bundle è **READ_ONLY** rispetto al target: nessuna rete,
    nessuna azione sul target. Si scrive solo dentro ``run_dir/fix/``.
  - ``secret_rotation`` ha **sempre** ``priority=1`` (§18-bis.5): una chiave trapelata
    è compromessa, va ruotata in console (passo umano) → ``applicable_by=AGENT_HUMAN``
    con ``warning`` esplicito.
  - ``code_change`` non porta **mai** una diff letterale (``literal_diff_available=False``):
    Bastione è black-box, non ha il sorgente — solo intent + hint.
  - P8: l'``evidence`` finisce nel bundle SEMPRE redatta (``context.evidence_redacted``).
    Nessun segreto in chiaro nei ``.md``/``.json``/``.sql``.
  - Resilienza (§4.7): un ``FixBuilder`` che fallisce o un ``rule_id`` senza builder
    NON crasha la fase — si logga e si salta (il finding resta nel report, solo senza
    voce nel bundle).
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path

from bastione.enums import Severity, Status
from bastione.models import (
    Applicability,
    FixEntry,
    FixPlan,
    FixType,
    Finding,
    TargetConfig,
    Verification,
)
from bastione.remediation.playbooks import _table_from_endpoint

log = logging.getLogger("bastione.remediation.agent_bundle")

# Status "aperti" su cui si emette un fix (§18-bis.2): mai ACCEPTED/FIXED.
_OPEN_STATUSES = frozenset({Status.NEW, Status.KNOWN})


# ─── FixBuilder: contratto + registry (parallelo a register/register_detector) ─

class FixBuilder(ABC):
    """Costruttore di una ``FixEntry`` per uno specifico ``rule_id`` (§18-bis.4).

    Ogni builder concreto dichiara i propri attributi di classe ``rule_id``,
    ``fix_type``, ``applicable_by`` e implementa ``build``: rende le
    ``instructions`` nella shape LOCKED del proprio ``fix_type`` (§18-bis.4).
    Un nuovo fix = un nuovo builder (drop-in), registrato con ``@register_fix``.
    """

    rule_id: str
    fix_type: FixType
    applicable_by: Applicability

    @abstractmethod
    def build(self, f: Finding, cfg: TargetConfig) -> FixEntry:
        """Costruisce la ``FixEntry`` per il finding ``f`` (target ``cfg``)."""


# Registry globale: rule_id → istanza del builder (§18-bis.4).
FIX_BUILDERS: dict[str, "FixBuilder"] = {}


def register_fix(cls: type[FixBuilder]) -> type[FixBuilder]:
    """Decoratore: istanzia ``cls`` e la registra in ``FIX_BUILDERS`` sotto
    ``cls.rule_id`` (stesso pattern di ``register``/``register_detector``).

    Ritorna la classe invariata (decoratore puro). Un ``rule_id`` duplicato
    sovrascrive (ultima registrazione vince — utile per override nei test).
    """
    istanza = cls()
    if istanza.rule_id in FIX_BUILDERS:
        log.warning(
            "FIX_BUILDERS: %r sovrascrive una registrazione precedente "
            "(§18-bis.4 — ultima registrazione vince).", istanza.rule_id
        )
    FIX_BUILDERS[istanza.rule_id] = istanza
    log.debug("FixBuilder registrato: %r → %r", istanza.rule_id, cls.__qualname__)
    return cls


# ─── helper comuni ────────────────────────────────────────────────────────────

# Slug per i nomi-file delle migration: minuscole/cifre/trattino, niente traversal.
_SLUG_NON_WORD = re.compile(r"[^a-z0-9]+")

# Identificatore SQL non-quotato valido per PostgreSQL: lettera/underscore iniziale,
# poi lettere/cifre/underscore (forma `public.<table>` senza quoting, §18-bis.4).
# Un nome-tabella che NON lo rispetti (spazi, `;`, virgolette, `<tabella>`, …) NON
# va interpolato grezzo in un ``ALTER TABLE public.<table>``: produrrebbe SQL
# malformato o injection-shaped — il builder lo salta (§4.7).
_SQL_IDENT_RE = re.compile(r"[a-z_][a-z0-9_]*", re.IGNORECASE)


def _slug(text: str, *, fallback: str = "fix") -> str:
    """Slug filesystem-safe (es. ``"clienti"`` da una tabella, ``"fix"`` se vuoto).

    Contiene il nome a ``[a-z0-9-]``: niente ``/``, ``..``, spazi — il file
    ``migrations/<finding_id>_<slug>.sql`` non può quindi uscire dalla dir.
    """
    s = _SLUG_NON_WORD.sub("-", (text or "").lower()).strip("-")
    return s or fallback


def _is_valid_sql_identifier(name: str) -> bool:
    """Il nome è un identificatore SQL non-quotato sicuro da interpolare? (§18-bis.4)

    True solo per ``^[a-z_][a-z0-9_]*$`` (case-insensitive): esclude vuoto,
    placeholder ``<tabella>``, spazi/``;``/virgolette e ogni segmento che renderebbe
    malformato o injection-shaped un ``ALTER TABLE public.<name>``.
    """
    return bool(name) and bool(_SQL_IDENT_RE.fullmatch(name))


def _severity_name(severity: Severity) -> str:
    """Nome severità in maiuscolo (es. ``"HIGH"``), robusto a enum o stringa."""
    return severity.name if isinstance(severity, Severity) else str(severity)


def _verification(f: Finding, cfg: TargetConfig) -> Verification:
    """Criterio di accettazione: il fix si chiude solo con un re-scan (§18-bis.8)."""
    return Verification(
        command=f"bastione verify --target {cfg.name}",
        expect=f"finding {f.finding_id} → FIXED",
    )


def _base_context(f: Finding) -> dict:
    """Context comune di una ``FixEntry`` (§18-bis.3).

    P8: l'``evidence`` arriva già redatta a monte e viene messa così com'è in
    ``evidence_redacted`` — questo modulo non de-redige nulla.
    """
    return {
        "resource": _table_from_endpoint(f.location.endpoint) or None,
        "endpoint": f.location.endpoint,
        "file": f.location.file,
        "evidence_redacted": f.evidence,
    }


# ─── Builder concreti (§18-bis.7) ─────────────────────────────────────────────

@register_fix
class RlsDisabledFix(FixBuilder):
    """RLS disabilitata → ``sql_migration`` letterale (ALTER TABLE + CREATE POLICY).

    Deriva la tabella dall'endpoint riusando ``_table_from_endpoint`` (§18 playbooks).
    Emette SQL pronto all'uso con rollback; l'agente lo applica prima su staging.
    """

    rule_id = "RLS_DISABLED"
    fix_type = FixType.SQL_MIGRATION
    applicable_by = Applicability.AGENT

    def build(self, f: Finding, cfg: TargetConfig) -> FixEntry:
        table = _table_from_endpoint(f.location.endpoint)
        # Degrado SICURO (§4.7): un endpoint degenere (vuoto / root REST / solo
        # versione) o un segmento non-identificatore (spazi, `;`, virgolette) NON
        # deve produrre una migration con un nome-tabella inesistente
        # (`public.<tabella>`) o injection-shaped (`public.My Table; DROP`). In quel
        # caso solleviamo: build_fix_plan lo cattura e SALTA il fix (il finding resta
        # nel report, solo senza voce nel bundle) — meglio nessuna migration che una
        # migration plausibile ma errata. I finding RLS_DISABLED reali hanno sempre
        # endpoint=/rest/v1/<table> con table valida (supabase/module.py), quindi
        # questo ramo non è esercitato in produzione: è codice difensivo.
        if not _is_valid_sql_identifier(table):
            raise ValueError(
                f"RLS_DISABLED su finding {f.finding_id}: nome-tabella non derivabile "
                f"in modo sicuro dall'endpoint {f.location.endpoint!r} "
                f"(derivato={table!r}). Salto il fix anziché emettere SQL non valido "
                f"(§4.7/§18-bis.4)."
            )
        slug = _slug(table, fallback="rls")
        migration_sql = (
            f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;\n"
            f"CREATE POLICY sel_own ON public.{table}\n"
            f"  FOR SELECT USING (auth.uid() = user_id);"
        )
        rollback_sql = f"DROP POLICY IF EXISTS sel_own ON public.{table};"
        instructions = {
            "migration_sql": migration_sql,
            "rollback_sql": rollback_sql,
            "apply_to": "staging first",
            # finding_id slug-ato così che il campo dichiarato coincida SEMPRE col
            # file realmente scritto (write_fix_bundle usa Path(declared).name): un
            # finding_id con separatori non farebbe divergere il path (§18-bis.4).
            "file": f"migrations/{_slug(f.finding_id, fallback='fix')}_{slug}.sql",
        }
        return FixEntry(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            severity=f.severity,
            title=f.title,
            fix_type=self.fix_type,
            applicable_by=self.applicable_by,
            priority=2,  # dopo le rotazioni di segreti (priority=1, §18-bis.5)
            context=_base_context(f),
            instructions=instructions,
            verification=_verification(f, cfg),
        )


class _ConfigHeaderFix(FixBuilder):
    """Base per i posture mancanti che si correggono con un header letterale
    (``config_change``): header/_headers o middleware, valore esatto (§18-bis.4)."""

    fix_type = FixType.CONFIG_CHANGE
    applicable_by = Applicability.AGENT
    header_key: str
    header_value: str

    def build(self, f: Finding, cfg: TargetConfig) -> FixEntry:
        instructions = {
            "mechanism": "_headers file / middleware",
            "key": self.header_key,
            "value": self.header_value,
        }
        return FixEntry(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            severity=f.severity,
            title=f.title,
            fix_type=self.fix_type,
            applicable_by=self.applicable_by,
            priority=3,  # dopo segreti (1) e migration strutturali (2)
            context=_base_context(f),
            instructions=instructions,
            verification=_verification(f, cfg),
        )


@register_fix
class HstsFix(_ConfigHeaderFix):
    """HSTS mancante → header ``Strict-Transport-Security`` letterale (§18-bis.4)."""

    rule_id = "POSTURE_HSTS"
    header_key = "Strict-Transport-Security"
    header_value = "max-age=31536000; includeSubDomains; preload"


@register_fix
class MissingCspFix(_ConfigHeaderFix):
    """CSP mancante → header ``Content-Security-Policy`` restrittivo letterale."""

    rule_id = "MISSING_CSP"
    header_key = "Content-Security-Policy"
    header_value = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )


class _SecretRotationFix(FixBuilder):
    """Base per la rotazione di un segreto trapelato (§18-bis.5).

    Una chiave finita nel bundle è **compromessa**: rimuoverla dal codice non basta,
    va **ruotata** (revocata + rigenerata) nella console del provider — passo che un
    agente di coding non può fare. Da qui ``secret_rotation``/``AGENT_HUMAN``,
    ``priority=1`` SEMPRE, ``compromised=True`` e ``warning`` esplicito.
    """

    fix_type = FixType.SECRET_ROTATION
    applicable_by = Applicability.AGENT_HUMAN
    provider: str
    key_name: str
    human_action: str
    agent_followup: str
    warning: str

    def build(self, f: Finding, cfg: TargetConfig) -> FixEntry:
        instructions = {
            "provider": self.provider,
            "compromised": True,
            "human_action": self.human_action,
            "agent_followup": self.agent_followup,
            "warning": self.warning,
        }
        return FixEntry(
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            severity=f.severity,
            title=f.title,
            fix_type=self.fix_type,
            applicable_by=self.applicable_by,
            priority=1,  # secret_rotation è SEMPRE 1 (§18-bis.5), a prescindere dalla severity
            context=_base_context(f),
            instructions=instructions,
            verification=_verification(f, cfg),
        )


@register_fix
class ServiceRoleRotationFix(_SecretRotationFix):
    """``service_role`` Supabase trapelata → rotazione (umano) + ripulitura (agente)."""

    rule_id = "SECRET_SERVICE_ROLE"
    provider = "supabase"
    key_name = "service_role"
    human_action = (
        "Supabase → Project Settings → API → rigenera la `service_role` key e "
        "revoca quella attuale."
    )
    agent_followup = (
        "Sposta la nuova chiave in env server-side (mai nel client/bundle) e rimuovi "
        "ogni riferimento alla service_role dal frontend; le chiamate privilegiate "
        "passano da un endpoint server-side."
    )
    warning = (
        "La chiave trapelata è COMPROMESSA: rimuoverla dal codice NON basta, va "
        "ruotata nella console del provider. Un agente di coding non può farlo."
    )


@register_fix
class StripeKeyRotationFix(_SecretRotationFix):
    """Chiave segreta Stripe (``sk_live_…``) trapelata → rotazione (umano) + ripulitura."""

    rule_id = "SECRET_STRIPE"
    provider = "stripe"
    key_name = "secret API key"
    human_action = (
        "Stripe → Developers → API keys → ruota (roll) la secret key esposta e revoca "
        "quella attuale."
    )
    agent_followup = (
        "Sposta la nuova secret key in env server-side (mai nel client); usa solo la "
        "publishable key nel frontend."
    )
    warning = (
        "La secret key Stripe trapelata è COMPROMESSA e permette operazioni sul tuo "
        "account: va ruotata in console (passo umano), non solo rimossa dal codice."
    )


# ─── Costruzione del piano (§18-bis.2/.4/.5) ──────────────────────────────────

def _is_open(f: Finding) -> bool:
    """Il finding è "aperto" e merita un fix? (NEW/KNOWN; mai ACCEPTED/FIXED)."""
    return f.status in _OPEN_STATUSES


def _sort_key(fe: FixEntry) -> tuple[int, int]:
    """Ordina per priority crescente, poi severity decrescente (§18-bis.4)."""
    return (fe.priority, -int(fe.severity))


def _order_fixes(fixes: list[FixEntry]) -> list[FixEntry]:
    """Ordina i fix per (priority, severity desc) RISPETTANDO ``depends_on`` (§18-bis.5).

    La regola LOCKED §18-bis.5 chiude la rotazione segreti con: «ogni altro fix che
    dipende da quella chiave la mette in ``depends_on``». Perché il campo non sia
    decorativo, l'ordinamento deve garantire che un fix non compaia MAI prima di un
    suo ``depends_on``: facciamo un sort stabile per (priority, -severity) e poi un
    passaggio topologico che promuove le dipendenze prima dei dipendenti, mantenendo
    per il resto l'ordine del sort. Con i builder attuali ``depends_on`` è sempre []
    (la pulizia post-rotazione è inglobata in ``agent_followup``), quindi il passaggio
    è un no-op e l'ordine resta quello del solo ``_sort_key``; il meccanismo è pronto
    per il giorno in cui un builder ``code_change`` dipendente valorizzerà il campo.
    Eventuali ``depends_on`` verso finding_id non presenti nel piano sono ignorati;
    eventuali cicli sono spezzati conservativamente (nessun crash).
    """
    base = sorted(fixes, key=_sort_key)
    present = {fe.finding_id for fe in base}
    by_id = {fe.finding_id: fe for fe in base}
    ordered: list[FixEntry] = []
    emitted: set[str] = set()

    def _emit(fe: FixEntry, on_stack: set[str]) -> None:
        if fe.finding_id in emitted or fe.finding_id in on_stack:
            return  # già emesso, oppure ciclo: spezza conservativamente
        on_stack.add(fe.finding_id)
        for dep in fe.depends_on:
            if dep in present and dep not in emitted:
                _emit(by_id[dep], on_stack)
        on_stack.discard(fe.finding_id)
        if fe.finding_id not in emitted:
            emitted.add(fe.finding_id)
            ordered.append(fe)

    for fe in base:
        _emit(fe, set())
    return ordered


def _build_summary(fixes: list[FixEntry]) -> dict:
    """Riassunto dei conteggi (§18-bis.6): total, agente, umano, per severità.

    "Umano richiesto" = ogni fix che NON è applicabile end-to-end dall'agente
    (``HUMAN`` o ``AGENT_HUMAN``): il piano deve fermarsi su questi e segnalarli.
    """
    by_severity: dict[str, int] = {}
    agent_applicable = 0
    human_required = 0
    for fe in fixes:
        by_severity[_severity_name(fe.severity)] = (
            by_severity.get(_severity_name(fe.severity), 0) + 1
        )
        if fe.applicable_by is Applicability.AGENT:
            agent_applicable += 1
        else:
            human_required += 1
    return {
        "total": len(fixes),
        "agent_applicable": agent_applicable,
        "human_required": human_required,
        "by_severity": by_severity,
    }


def build_fix_plan(
    findings: list[Finding],
    cfg: TargetConfig,
    *,
    now,
    run_dir: str,
) -> FixPlan:
    """Costruisce il ``FixPlan`` dai finding aperti con un builder registrato (§18-bis).

    - Filtra i finding APERTI (``NEW``/``KNOWN``; mai ``ACCEPTED``/``FIXED``, §18-bis.2).
    - Per ogni finding con un ``FixBuilder`` registrato per il suo ``rule_id`` costruisce
      la ``FixEntry``; un ``rule_id`` senza builder è semplicemente saltato (il finding
      resta nel report, solo senza voce nel bundle).
    - Resiliente (§4.7): un builder che solleva viene loggato e saltato, non crasha.
    - Ordina per priority poi severity desc, rispettando ``depends_on`` (un fix non
      è mai prima di una sua dipendenza, §18-bis.5); ``secret_rotation`` resta
      ``priority=1`` (lo impone il builder stesso, §18-bis.5).
    - Popola ``summary`` (§18-bis.6).

    Deterministico: ``now`` (``datetime``) e ``run_dir`` sono passati dal chiamante —
    nessun ``datetime.now()`` reale qui.
    """
    fixes: list[FixEntry] = []
    for f in findings:
        if not _is_open(f):
            continue
        builder = FIX_BUILDERS.get(f.rule_id)
        if builder is None:
            log.debug(
                "Nessun FixBuilder per rule_id=%r (finding %s): salto (§4.7).",
                f.rule_id, f.finding_id,
            )
            continue
        try:
            fixes.append(builder.build(f, cfg))
        except Exception as exc:  # noqa: BLE001 — resilienza §4.7: mai crash dal builder
            log.warning(
                "FixBuilder %r ha sollevato sul finding %s: salto. (%s)",
                f.rule_id, f.finding_id, exc,
            )

    fixes = _order_fixes(fixes)
    return FixPlan(
        target=cfg.name,
        generated_at=now,
        run_dir=run_dir,
        summary=_build_summary(fixes),
        fixes=fixes,
    )


# ─── Scrittura del bundle (§18-bis.2/.6) ──────────────────────────────────────

def _is_human_section(fe: FixEntry) -> bool:
    """Va nella sezione "richiede azione umana"? (HUMAN o AGENT_HUMAN, §18-bis.6)."""
    return fe.applicable_by is not Applicability.AGENT


def _render_human_entry(fe: FixEntry) -> str:
    """Render di una voce 🔴 "Da fare prima — richiede azione umana" (§18-bis.6)."""
    ins = fe.instructions
    return (
        f"### [P{fe.priority}] {fe.title}  ·  `{fe.rule_id}`  ·  {_severity_name(fe.severity)}\n"
        f"- **Cosa:** {ins.get('human_action', '')}\n"
        f"- **Perché non può farlo l'agente:** {ins.get('warning', '')}\n"
        f"- **Dopo, per l'agente:** {ins.get('agent_followup', '')}\n"
        f"- **Criterio di accettazione:** `{fe.verification.command}` → {fe.verification.expect}\n"
    )


def _render_where(fe: FixEntry) -> str:
    """Riga "Dove:" da ``context`` (resource/endpoint/file), senza ``None`` letterali."""
    ctx = fe.context
    parts = [
        str(ctx.get("resource") or ""),
        f"({ctx['endpoint']})" if ctx.get("endpoint") else "",
        str(ctx.get("file") or ""),
    ]
    where = " ".join(p for p in parts if p).strip()
    return where or "—"


def _render_agent_entry(fe: FixEntry) -> str:
    """Render di una voce 🟢 "Applicabile dall'agente" (§18-bis.6).

    Il corpo dipende da ``fix_type``: SQL letterale per ``sql_migration``,
    header letterale per ``config_change``/``infra_change``, intent+hint per
    ``code_change``.
    """
    ins = fe.instructions
    lines = [
        f"### [P{fe.priority}] {fe.title}  ·  `{fe.rule_id}`  ·  {_severity_name(fe.severity)}",
        f"- **Tipo:** {fe.fix_type.value}",
        f"- **Dove:** {_render_where(fe)}",
    ]
    if fe.fix_type is FixType.SQL_MIGRATION:
        lines.append(
            f"- **Applica questa migration** (file: `{ins.get('file', '')}`, prima su staging):"
        )
        lines.append("  ```sql")
        for sql_line in ins.get("migration_sql", "").splitlines():
            lines.append(f"  {sql_line}")
        lines.append("  ```")
        lines.append(f"  Rollback: `{ins.get('rollback_sql', '')}`")
    elif fe.fix_type in (FixType.CONFIG_CHANGE, FixType.INFRA_CHANGE):
        lines.append(
            f"- **Imposta** `{ins.get('key', '')}` = `{ins.get('value', '')}` "
            f"via {ins.get('mechanism', '')}."
        )
    elif fe.fix_type is FixType.CODE_CHANGE:
        lines.append(f"- **Intento:** {ins.get('intent', '')}")
        lines.append(
            f"- **Cerca:** {ins.get('search_hints', [])} — "
            f"**file probabili:** {ins.get('files_likely', [])}"
        )
        lines.append(f"- **Nota:** {ins.get('note', '')}")
    lines.append(
        f"- **Criterio di accettazione:** `{fe.verification.command}` → {fe.verification.expect}"
    )
    return "\n".join(lines) + "\n"


_PREAMBOLO = """## Istruzioni per l'agente di coding (leggi prima di agire)
Stai correggendo vulnerabilità di sicurezza trovate da Bastione su un'app **di proprietà del committente**.
REGOLE:
1. Non toccare MAI ambienti di produzione. Lavora su un branch dedicato; le migration SQL vanno applicate prima su **staging**.
2. Applica SOLO i fix marcati 🟢 "Applicabile dall'agente". I fix 🔴 "Richiede azione umana" NON sono tuoi: segnalali e fermati su quelli.
3. Per i fix di codice non hai una diff pronta: usa `search_hints` e `files_likely` per localizzare il punto nel sorgente, poi applica l'intento descritto.
4. Ogni fix ha un **Criterio di accettazione**. Dopo aver applicato, NON dichiarare risolto: sarà l'utente a eseguire `bastione verify` e a confermare il passaggio a FIXED.
5. Applica i fix nell'ordine in cui sono elencati (già ordinati per priorità: prima le rotazioni di segreti). Se un fix dichiara un campo `depends_on` non vuoto, risolvi prima i `finding_id` che vi compaiono.
"""


def _render_fix_plan_md(plan: FixPlan) -> str:
    """Render normativo del ``FIX-PLAN.md`` (§18-bis.6): preambolo, sezione umana,
    sezione agente (ordinata), loop di verifica finale."""
    human = [fe for fe in plan.fixes if _is_human_section(fe)]
    agent = [fe for fe in plan.fixes if not _is_human_section(fe)]

    out: list[str] = [
        f"# Bastione — Piano di Remediation · target: {plan.target} · {plan.generated_at.isoformat()}",
        "",
        _PREAMBOLO,
    ]

    if not plan.fixes:
        out.append("---")
        out.append(
            "Nessun fix da applicare: non ci sono finding aperti con una remediation "
            "automatizzabile in questa run. (nessun fix)"
        )
        out.append("")
        out.append("## Verifica finale")
        out.append(
            f"In ogni momento puoi ri-controllare lo stato con "
            f"`bastione verify --target {plan.target}`."
        )
        return "\n".join(out) + "\n"

    out.append("---")
    out.append("## 🔴 Da fare prima — richiede azione umana")
    if human:
        for fe in human:
            out.append(_render_human_entry(fe))
    else:
        out.append("_Nessuna azione umana richiesta in questa run._\n")

    out.append("---")
    out.append("## 🟢 Applicabili dall'agente (in ordine)")
    if agent:
        for fe in agent:
            out.append(_render_agent_entry(fe))
    else:
        out.append("_Nessun fix applicabile direttamente dall'agente in questa run._\n")

    out.append("---")
    out.append("## Verifica finale")
    out.append(
        "Dopo aver applicato i fix 🟢 e completato i 🔴, l'utente esegue:"
    )
    out.append(f"`bastione verify --target {plan.target}`")
    out.append(
        "Il piano è chiuso quando tutti i `finding_id` elencati risultano **FIXED**."
    )
    out.append(
        "> Precondizione: lo stato **FIXED** si misura contro la **baseline salvata**. "
        "Per vederlo, la baseline va accettata PRIMA della remediation con "
        f"`bastione scan --target {plan.target} --accept-baseline`; senza, un finding "
        "corretto sparisce dalla ri-scansione invece di risultare FIXED. Loop completo: "
        f"`scan --accept-baseline` → applica i fix → `verify`."
    )
    return "\n".join(out) + "\n"


def write_fix_bundle(plan: FixPlan, run_dir: Path) -> None:
    """Scrive il bundle ``fix/`` sotto ``run_dir`` (§18-bis.2).

    Crea ``run_dir/fix/`` e vi scrive:
      - ``FIX-PLAN.md``   — documento umano+agente (formato §18-bis.6);
      - ``fix-plan.json`` — il ``FixPlan`` serializzato (schema ``bastione-fixplan/1``);
      - ``migrations/<finding_id>_<slug>.sql`` — per ogni ``sql_migration``, l'SQL letterale.

    Se non ci sono fix scrive comunque un ``FIX-PLAN.md`` "nessun fix" e un
    ``fix-plan.json`` valido (con ``fixes: []``): l'assenza di fix è informativa,
    non un errore.

    READ_ONLY rispetto al target: scrive solo dentro ``run_dir/fix/``. P8: il
    contenuto deriva da finding già redatti, nessun segreto in chiaro.
    """
    fix_dir = run_dir / "fix"
    fix_dir.mkdir(parents=True, exist_ok=True)

    # fix-plan.json — contratto machine-readable (schema bastione-fixplan/1).
    (fix_dir / "fix-plan.json").write_text(
        plan.model_dump_json(indent=2), encoding="utf-8"
    )

    # FIX-PLAN.md — documento normativo (§18-bis.6).
    (fix_dir / "FIX-PLAN.md").write_text(_render_fix_plan_md(plan), encoding="utf-8")

    # migrations/*.sql — solo per i fix sql_migration (artefatti applicabili diretti).
    migrations = [fe for fe in plan.fixes if fe.fix_type is FixType.SQL_MIGRATION]
    if migrations:
        mig_dir = fix_dir / "migrations"
        mig_dir.mkdir(parents=True, exist_ok=True)
        for fe in migrations:
            # Il nome-file è quello dichiarato in instructions["file"] (basename, già
            # slug-safe); fallback robusto se assente.
            declared = str(fe.instructions.get("file") or "")
            fname = Path(declared).name if declared else ""
            if not fname:
                fname = f"{_slug(fe.finding_id)}_{_slug(fe.rule_id)}.sql"
            sql = fe.instructions.get("migration_sql", "")
            (mig_dir / fname).write_text(sql + "\n", encoding="utf-8")
