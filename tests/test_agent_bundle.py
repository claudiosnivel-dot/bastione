"""Test dell'Agent Remediation Bundle (§18-bis) — TDD.

Copre `bastione.remediation.agent_bundle`:
  - `FixBuilder` (ABC) + registry `FIX_BUILDERS` + decoratore `register_fix`;
  - i builder concreti (RLS_DISABLED, SECRET_SERVICE_ROLE, SECRET_STRIPE,
    POSTURE_HSTS, MISSING_CSP) e la shape LOCKED di `instructions` per fix_type;
  - `build_fix_plan`: filtra i finding APERTI (NEW/KNOWN), salta ACCEPTED/FIXED e i
    rule_id senza builder, ordina per priority→severity, forza secret_rotation a
    priority=1, popola summary, è resiliente a builder che sollevano;
  - `write_fix_bundle`: scrive FIX-PLAN.md (preambolo + sezioni + loop verifica),
    fix-plan.json (ricaricabile in FixPlan) e i .sql delle migration;
  - P8: nessun segreto in chiaro nei .md/.json/.sql (evidence sempre redatta).

Tutti i test sono OFFLINE e deterministici: `now` e `run_dir` sono passati, mai
`datetime.now()` reale.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bastione.enums import Confidence, Severity, Status
from bastione.models import (
    Applicability,
    FixPlan,
    FixType,
    Finding,
    Location,
    PostureCheck,
    TargetConfig,
)
from bastione.remediation import agent_bundle as ab


NOW = datetime(2026, 1, 1, 12, 0, 0)


# ─── helper di costruzione ────────────────────────────────────────────────────

def _cfg(name: str = "gestionale", base_url: str = "https://staging.example") -> TargetConfig:
    return TargetConfig(
        name=name,
        base_url=base_url,
        environment="staging",
        ownership="owned",
    )


def _finding(
    *,
    finding_id: str = "abc123",
    rule_id: str = "RLS_DISABLED",
    title: str = "RLS disabilitata",
    severity: Severity = Severity.HIGH,
    endpoint: str | None = "/rest/v1/clienti",
    file: str | None = None,
    evidence: str = "[REDACTED]",
    status: Status = Status.NEW,
    target: str = "gestionale",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        module="supabase",
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=Confidence.FIRM,
        target=target,
        location=Location(endpoint=endpoint, file=file),
        evidence=evidence,
        description="desc",
        remediation_ref=rule_id,
        status=status,
    )


# ─── registry / register_fix ──────────────────────────────────────────────────

def test_registry_popolato_con_i_rule_id_attesi():
    for rid in ("RLS_DISABLED", "SECRET_SERVICE_ROLE", "SECRET_STRIPE",
                "POSTURE_HSTS", "MISSING_CSP"):
        assert rid in ab.FIX_BUILDERS, f"builder mancante per {rid}"


def test_register_fix_indicizza_per_rule_id():
    @ab.register_fix
    class _Tmp(ab.FixBuilder):
        rule_id = "TMP_RULE_TEST"
        fix_type = FixType.CONFIG_CHANGE
        applicable_by = Applicability.AGENT

        def build(self, f, cfg):
            return ab.FIX_BUILDERS  # non usato

    assert "TMP_RULE_TEST" in ab.FIX_BUILDERS
    del ab.FIX_BUILDERS["TMP_RULE_TEST"]


# ─── shape instructions per fix_type (LOCKED §18-bis.4) ───────────────────────

def test_rls_disabled_instructions_sql_migration_shape():
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(_finding(endpoint="/rest/v1/clienti"), _cfg())
    assert fe.fix_type is FixType.SQL_MIGRATION
    assert fe.applicable_by is Applicability.AGENT
    ins = fe.instructions
    assert set(ins) >= {"migration_sql", "rollback_sql", "apply_to", "file"}
    assert ins["apply_to"] == "staging first"
    # SQL letterale, tabella derivata dall'endpoint.
    assert "ENABLE ROW LEVEL SECURITY" in ins["migration_sql"]
    assert "clienti" in ins["migration_sql"]
    assert "CREATE POLICY" in ins["migration_sql"]
    assert "DROP POLICY" in ins["rollback_sql"]
    assert ins["file"].endswith(".sql")


def test_config_change_hsts_instructions_shape():
    fe = ab.FIX_BUILDERS["POSTURE_HSTS"].build(_finding(rule_id="POSTURE_HSTS"), _cfg())
    assert fe.fix_type is FixType.CONFIG_CHANGE
    assert fe.applicable_by is Applicability.AGENT
    ins = fe.instructions
    assert set(ins) >= {"mechanism", "key", "value"}
    assert ins["key"] == "Strict-Transport-Security"
    assert "max-age" in ins["value"]


def test_config_change_csp_instructions_shape():
    fe = ab.FIX_BUILDERS["MISSING_CSP"].build(_finding(rule_id="MISSING_CSP"), _cfg())
    assert fe.fix_type is FixType.CONFIG_CHANGE
    ins = fe.instructions
    assert ins["key"] == "Content-Security-Policy"
    assert "default-src" in ins["value"]


def test_secret_rotation_instructions_shape_and_warning():
    fe = ab.FIX_BUILDERS["SECRET_SERVICE_ROLE"].build(
        _finding(rule_id="SECRET_SERVICE_ROLE", severity=Severity.CRITICAL,
                 file="assets/index.js", endpoint=None), _cfg())
    assert fe.fix_type is FixType.SECRET_ROTATION
    assert fe.applicable_by is Applicability.AGENT_HUMAN
    ins = fe.instructions
    assert set(ins) >= {"provider", "compromised", "human_action", "agent_followup", "warning"}
    assert ins["compromised"] is True
    assert ins["warning"]  # warning esplicito, non vuoto
    # secret_rotation è SEMPRE priority=1 (§18-bis.5).
    assert fe.priority == 1


def test_secret_stripe_is_secret_rotation():
    fe = ab.FIX_BUILDERS["SECRET_STRIPE"].build(
        _finding(rule_id="SECRET_STRIPE", file="assets/index.js", endpoint=None), _cfg())
    assert fe.fix_type is FixType.SECRET_ROTATION
    assert fe.priority == 1
    assert fe.instructions["compromised"] is True


# ─── build_fix_plan ───────────────────────────────────────────────────────────

def test_build_fix_plan_esclude_accepted_e_fixed():
    findings = [
        _finding(finding_id="open1", rule_id="RLS_DISABLED", status=Status.NEW),
        _finding(finding_id="known1", rule_id="MISSING_CSP", status=Status.KNOWN),
        _finding(finding_id="acc1", rule_id="POSTURE_HSTS", status=Status.ACCEPTED),
        _finding(finding_id="fix1", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/ordini", status=Status.FIXED),
    ]
    plan = build = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    ids = {fe.finding_id for fe in plan.fixes}
    assert "open1" in ids and "known1" in ids
    assert "acc1" not in ids and "fix1" not in ids


def test_build_fix_plan_skip_rule_id_senza_builder_no_crash():
    findings = [
        _finding(finding_id="o1", rule_id="RLS_DISABLED", status=Status.NEW),
        _finding(finding_id="o2", rule_id="RULE_SENZA_BUILDER", status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    ids = {fe.finding_id for fe in plan.fixes}
    assert ids == {"o1"}


def test_build_fix_plan_ordina_priority_poi_severity():
    # secret_rotation (priority 1) prima, poi per severity desc a parità di priority.
    findings = [
        _finding(finding_id="rls_med", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/a", severity=Severity.MEDIUM, status=Status.NEW),
        _finding(finding_id="rls_crit", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/b", severity=Severity.CRITICAL, status=Status.NEW),
        _finding(finding_id="secret", rule_id="SECRET_SERVICE_ROLE",
                 file="assets/index.js", endpoint=None,
                 severity=Severity.CRITICAL, status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    order = [fe.finding_id for fe in plan.fixes]
    # secret_rotation è priority=1 → primo.
    assert order[0] == "secret"
    # tra gli RLS (stessa priority), CRITICAL prima di MEDIUM.
    assert order.index("rls_crit") < order.index("rls_med")


def test_build_fix_plan_summary_corretto():
    findings = [
        _finding(finding_id="rls", rule_id="RLS_DISABLED",
                 severity=Severity.HIGH, status=Status.NEW),
        _finding(finding_id="csp", rule_id="MISSING_CSP",
                 severity=Severity.MEDIUM, status=Status.NEW),
        _finding(finding_id="secret", rule_id="SECRET_SERVICE_ROLE",
                 file="assets/index.js", endpoint=None,
                 severity=Severity.CRITICAL, status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    s = plan.summary
    assert s["total"] == 3
    # RLS + CSP = agente; secret = AGENT_HUMAN (umano richiesto).
    assert s["agent_applicable"] == 2
    assert s["human_required"] == 1
    assert s["by_severity"]["CRITICAL"] == 1
    assert s["by_severity"]["HIGH"] == 1
    assert s["by_severity"]["MEDIUM"] == 1


def test_build_fix_plan_resiliente_a_builder_che_solleva(monkeypatch):
    class _Boom(ab.FixBuilder):
        rule_id = "BOOM_RULE"
        fix_type = FixType.CONFIG_CHANGE
        applicable_by = Applicability.AGENT

        def build(self, f, cfg):
            raise RuntimeError("kaboom")

    monkeypatch.setitem(ab.FIX_BUILDERS, "BOOM_RULE", _Boom())
    findings = [
        _finding(finding_id="boom", rule_id="BOOM_RULE", status=Status.NEW),
        _finding(finding_id="ok", rule_id="RLS_DISABLED", status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    ids = {fe.finding_id for fe in plan.fixes}
    assert ids == {"ok"}  # il builder che solleva è saltato, non crasha la fase


def test_build_fix_plan_generated_at_deterministico():
    plan = ab.build_fix_plan([], _cfg(), now=NOW, run_dir="runs/g/ts")
    assert plan.generated_at == NOW
    assert plan.run_dir == "runs/g/ts"
    assert plan.target == "gestionale"


# ─── write_fix_bundle ─────────────────────────────────────────────────────────

def _plan_con_fix(run_dir: str = "runs/g/ts"):
    findings = [
        _finding(finding_id="secret7f", rule_id="SECRET_SERVICE_ROLE",
                 file="assets/index.js", endpoint=None,
                 severity=Severity.CRITICAL, status=Status.NEW),
        _finding(finding_id="rls9a", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/clienti",
                 severity=Severity.CRITICAL, status=Status.NEW),
        _finding(finding_id="csp1b", rule_id="MISSING_CSP",
                 severity=Severity.MEDIUM, status=Status.NEW),
    ]
    return ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir=run_dir)


def test_write_fix_bundle_crea_file(tmp_path: Path):
    plan = _plan_con_fix(str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    assert (tmp_path / "fix" / "FIX-PLAN.md").is_file()
    assert (tmp_path / "fix" / "fix-plan.json").is_file()
    assert (tmp_path / "fix" / "migrations").is_dir()


def test_fix_plan_md_ha_preambolo_sezioni_e_loop_verifica(tmp_path: Path):
    plan = _plan_con_fix(str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    md = (tmp_path / "fix" / "FIX-PLAN.md").read_text(encoding="utf-8")
    # Preambolo-istruzioni per l'agente.
    assert "Istruzioni per l'agente" in md
    assert "produzione" in md  # la regola "mai produzione"
    # Sezione umana (secret_rotation = AGENT_HUMAN).
    assert "richiede azione umana" in md
    # Sezione agente.
    assert "Applicabili dall'agente" in md
    # Loop di verifica finale.
    assert "bastione verify --target gestionale" in md
    assert "FIXED" in md


def test_fix_plan_md_separa_umano_da_agente(tmp_path: Path):
    plan = _plan_con_fix(str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    md = (tmp_path / "fix" / "FIX-PLAN.md").read_text(encoding="utf-8")
    # Il secret va nella sezione umana, l'RLS in quella agente.
    human_idx = md.index("richiede azione umana")
    agent_idx = md.index("Applicabili dall'agente")
    assert human_idx < agent_idx
    assert "SECRET_SERVICE_ROLE" in md[human_idx:agent_idx]


def test_fix_plan_json_valido_e_ricaricabile(tmp_path: Path):
    plan = _plan_con_fix(str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    raw = (tmp_path / "fix" / "fix-plan.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["schema_version"] == "bastione-fixplan/1"
    reloaded = FixPlan.model_validate_json(raw)
    assert reloaded.target == "gestionale"
    assert len(reloaded.fixes) == 3


def test_migration_sql_scritta_con_sql_letterale(tmp_path: Path):
    plan = _plan_con_fix(str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    migs = list((tmp_path / "fix" / "migrations").glob("*.sql"))
    assert len(migs) == 1
    content = migs[0].read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in content
    assert "clienti" in content
    assert migs[0].name.startswith("rls9a")  # <finding_id>_<slug>.sql


def test_p8_nessun_segreto_in_chiaro_nel_bundle(tmp_path: Path):
    # Un finding con evidence che (per ipotesi) conterrebbe un segreto: nel bundle
    # deve comparire SOLO la versione redatta passata nell'evidence del finding.
    findings = [
        _finding(finding_id="secret7f", rule_id="SECRET_SERVICE_ROLE",
                 file="assets/index.js", endpoint=None,
                 evidence="eyJ…[REDACTED]…XYZ", severity=Severity.CRITICAL,
                 status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir=str(tmp_path))
    ab.write_fix_bundle(plan, tmp_path)
    for name in ("FIX-PLAN.md", "fix-plan.json"):
        text = (tmp_path / "fix" / name).read_text(encoding="utf-8")
        # Nessun JWT/segreto in chiaro: solo placeholder redatto.
        assert "eyJhbGciOiJ" not in text
        assert "sk_live_" not in text
        assert "service_role_key_in_chiaro" not in text


def test_context_evidence_e_redatta(tmp_path: Path):
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(evidence="[REDACTED:array di 3 righe]"), _cfg())
    assert "evidence_redacted" in fe.context
    assert fe.context["evidence_redacted"] == "[REDACTED:array di 3 righe]"


def test_write_fix_bundle_nessun_fix_grazia(tmp_path: Path):
    plan = ab.build_fix_plan([], _cfg(), now=NOW, run_dir=str(tmp_path))
    # Non deve sollevare; scrive un FIX-PLAN.md "nessun fix" e un json valido.
    ab.write_fix_bundle(plan, tmp_path)
    md_path = tmp_path / "fix" / "FIX-PLAN.md"
    assert md_path.is_file()
    md = md_path.read_text(encoding="utf-8")
    assert "nessun fix" in md.lower()
    raw = (tmp_path / "fix" / "fix-plan.json").read_text(encoding="utf-8")
    assert FixPlan.model_validate_json(raw).fixes == []


def test_secret_rotation_priority_uno_anche_se_severity_bassa():
    # Anche se per assurdo il finding fosse LOW, secret_rotation resta priority=1.
    fe = ab.FIX_BUILDERS["SECRET_STRIPE"].build(
        _finding(rule_id="SECRET_STRIPE", file="x.js", endpoint=None,
                 severity=Severity.LOW), _cfg())
    assert fe.priority == 1


# ─── REGRESSIONE: degrado sicuro su table non interpolabile (§4.7/§18-bis.4) ───

@pytest.mark.parametrize("endpoint", ["/rest/v1/", "/rest/v1", "", "/rest/v1/v1", None])
def test_rls_disabled_table_degenere_solleva_invece_di_sql_placeholder(endpoint):
    """Endpoint degenere (root REST / vuoto / solo-versione) → niente `<tabella>`
    letterale nell'SQL: il builder SOLLEVA (build_fix_plan poi lo salta, §4.7)."""
    f = _finding(rule_id="RLS_DISABLED", endpoint=endpoint)
    with pytest.raises(ValueError):
        ab.FIX_BUILDERS["RLS_DISABLED"].build(f, _cfg())


@pytest.mark.parametrize("endpoint", [
    "/rest/v1/My Table; DROP",       # spazi + `;` injection-shaped
    "/rest/v1/clienti';--",          # virgolette
    "/rest/v1/<tabella>",            # placeholder letterale
    "/rest/v1/tab le",               # spazio interno
])
def test_rls_disabled_table_non_identificatore_solleva(endpoint):
    """Un segmento non-identificatore SQL (spazi/`;`/virgolette) NON va interpolato
    grezzo in `public.<table>`: il builder solleva, niente SQL malformato/injection."""
    f = _finding(rule_id="RLS_DISABLED", endpoint=endpoint)
    with pytest.raises(ValueError):
        ab.FIX_BUILDERS["RLS_DISABLED"].build(f, _cfg())


def test_build_fix_plan_salta_rls_con_table_degenere_senza_crash():
    """build_fix_plan è resiliente (§4.7): un RLS con endpoint degenere viene SALTATO,
    gli altri fix restano. Nessun `<tabella>`/`public.` malformato finisce nel piano."""
    findings = [
        _finding(finding_id="rls_bad", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/", status=Status.NEW),
        _finding(finding_id="rls_ok", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/clienti", status=Status.NEW),
    ]
    plan = ab.build_fix_plan(findings, _cfg(), now=NOW, run_dir="runs/g/ts")
    ids = {fe.finding_id for fe in plan.fixes}
    assert ids == {"rls_ok"}
    # nessun SQL col placeholder o con un nome-tabella inesistente
    for fe in plan.fixes:
        assert "<tabella>" not in fe.instructions.get("migration_sql", "")


def test_rls_disabled_sql_solo_identificatori_validi():
    """Il caso reale (table valida) continua a produrre SQL ben formato."""
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(endpoint="/rest/v1/ordini"), _cfg())
    assert "ALTER TABLE public.ordini ENABLE ROW LEVEL SECURITY" in fe.instructions["migration_sql"]
    assert "<tabella>" not in fe.instructions["migration_sql"]


# ─── M2 step 0: remediation RLS view-aware (tabella vs vista, security_invoker) ─

def test_rls_disabled_migration_e_view_aware_security_invoker():
    """Il problema reale: RLS_DISABLED colpisce spesso una VISTA, non una tabella.
    Su una vista non si abilita RLS: si imposta `security_invoker = on` così la vista
    rispetta la RLS delle tabelle sottostanti. Poiché Bastione è black-box e non sa
    se la relazione sia tabella o vista, l'SQL deve gestire ENTRAMBI i casi a runtime
    (ramo su pg_class.relkind). Il migration_sql deve quindi contenere sia il ramo
    tabella (ALTER TABLE ... ENABLE ROW LEVEL SECURITY) sia il ramo vista
    (ALTER VIEW ... SET (security_invoker = on))."""
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(endpoint="/rest/v1/clienti"), _cfg())
    sql = fe.instructions["migration_sql"]
    # Ramo vista: la clausola corretta per una view (Postgres 15+/Supabase).
    assert "security_invoker" in sql
    assert "ALTER VIEW" in sql
    assert "ALTER VIEW public.clienti SET (security_invoker = on)" in sql
    # Ramo tabella: invariato (compatibilità coi test substring esistenti).
    assert "ALTER TABLE public.clienti ENABLE ROW LEVEL SECURITY" in sql
    assert "CREATE POLICY" in sql


def test_rls_disabled_migration_ramifica_su_relkind_da_pg_class():
    """La scelta tabella-vs-vista è fatta a RUNTIME in Postgres leggendo
    pg_class.relkind ('r' tabella, 'v'/'m' vista/matview): il blocco DO deve
    interrogare pg_class (JOIN pg_namespace) e ramificare sul relkind."""
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(endpoint="/rest/v1/clienti"), _cfg())
    sql = fe.instructions["migration_sql"]
    # Lookup del tipo di relazione da pg_class.relkind.
    assert "pg_class" in sql
    assert "relkind" in sql
    # È un blocco DO che ramifica (EXECUTE per ognuno dei rami).
    assert "DO $$" in sql or "DO $do$" in sql
    assert "EXECUTE" in sql
    # Il ramo vista copre anche le matview ('m') oltre alle view ('v').
    assert "'v'" in sql and "'m'" in sql


def test_rls_disabled_rollback_e_view_aware_e_idempotente():
    """Anche il rollback è view-aware: DROP POLICY (tabella) idempotente e RESET
    della security_invoker (vista), guardato/idempotente — niente crash se non
    applicabile."""
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(endpoint="/rest/v1/clienti"), _cfg())
    rollback = fe.instructions["rollback_sql"]
    # Ramo tabella: DROP POLICY idempotente (compatibilità test esistenti).
    assert "DROP POLICY" in rollback
    assert "IF EXISTS" in rollback
    # Ramo vista: RESET della security_invoker.
    assert "RESET (security_invoker)" in rollback


def test_rls_disabled_migration_ha_commento_tabella_vs_vista():
    """Il blocco DO è corredato da un commento SQL che spiega tabella-vs-vista e
    la ratio di security_invoker, così l'umano che applica capisce il branching."""
    fe = ab.FIX_BUILDERS["RLS_DISABLED"].build(
        _finding(endpoint="/rest/v1/clienti"), _cfg())
    sql = fe.instructions["migration_sql"]
    # Un commento SQL (-- ...) iniziale che menziona vista e security_invoker.
    assert sql.lstrip().startswith("--")
    assert "vista" in sql.lower() or "view" in sql.lower()
    assert "security_invoker" in sql


def test_rls_disabled_view_aware_non_interpola_nomi_non_validati():
    """LOCKED: la validazione _is_valid_sql_identifier resta — un nome non valido
    SOLLEVA (build_fix_plan lo salta), niente interpolazione injection-shaped nelle
    stringhe EXECUTE del blocco DO view-aware."""
    f = _finding(rule_id="RLS_DISABLED", endpoint="/rest/v1/My Table; DROP")
    with pytest.raises(ValueError):
        ab.FIX_BUILDERS["RLS_DISABLED"].build(f, _cfg())


# ─── REGRESSIONE: instructions['file'] coincide col file scritto (§18-bis.4) ───

def test_instructions_file_coincide_col_file_scritto_anche_con_separatori(tmp_path: Path):
    """instructions['file'] è slug-ato anche sul finding_id: il path dichiarato nel
    fix-plan.json coincide SEMPRE col basename realmente scritto sotto migrations/,
    anche se il finding_id (per assurdo) contenesse separatori di percorso."""
    f = _finding(finding_id="../../../../tmp/PWNED", rule_id="RLS_DISABLED",
                 endpoint="/rest/v1/clienti", status=Status.NEW)
    plan = ab.build_fix_plan([f], _cfg(), now=NOW, run_dir=str(tmp_path))
    assert len(plan.fixes) == 1
    declared = plan.fixes[0].instructions["file"]
    # niente separatori nel campo dichiarato
    assert "/" not in declared.split("migrations/", 1)[1]
    assert "\\" not in declared and ".." not in declared
    ab.write_fix_bundle(plan, tmp_path)
    written = list((tmp_path / "fix" / "migrations").glob("*.sql"))
    assert len(written) == 1
    # il basename dichiarato == il file realmente scritto
    assert Path(declared).name == written[0].name
    # e nulla è uscito da fix/
    escaped = [p for p in tmp_path.rglob("PWNED*") if "fix" not in p.parts]
    assert escaped == []


# ─── REGRESSIONE: depends_on rispettato nell'ordinamento (§18-bis.5) ───────────

def test_order_fixes_rispetta_depends_on():
    """Un fix con depends_on non vuoto non è MAI ordinato prima della sua dipendenza,
    anche se priority/severity lo metterebbero prima (§18-bis.5)."""
    from bastione.models import FixEntry, Verification

    def _fe(fid, *, priority, sev, deps=()):
        return FixEntry(
            finding_id=fid, rule_id="X", severity=sev, title=fid,
            fix_type=FixType.CONFIG_CHANGE, applicable_by=Applicability.AGENT,
            priority=priority, depends_on=list(deps), context={},
            instructions={}, verification=Verification(command="c", expect="e"),
        )

    # 'dipendente' avrebbe priority più bassa (verrebbe prima), ma dipende da 'base'.
    base = _fe("base", priority=2, sev=Severity.LOW)
    dependente = _fe("dipendente", priority=1, sev=Severity.CRITICAL, deps=["base"])
    ordered = ab._order_fixes([dependente, base])
    ids = [fe.finding_id for fe in ordered]
    assert ids.index("base") < ids.index("dipendente")


def test_order_fixes_ignora_dep_assente_e_non_va_in_loop():
    """depends_on verso un finding_id assente è ignorato; un ciclo non crasha."""
    from bastione.models import FixEntry, Verification

    def _fe(fid, deps):
        return FixEntry(
            finding_id=fid, rule_id="X", severity=Severity.HIGH, title=fid,
            fix_type=FixType.CONFIG_CHANGE, applicable_by=Applicability.AGENT,
            priority=2, depends_on=list(deps), context={},
            instructions={}, verification=Verification(command="c", expect="e"),
        )

    a = _fe("a", ["nonexistent"])
    b = _fe("b", ["c"])
    c = _fe("c", ["b"])  # ciclo b<->c
    ordered = ab._order_fixes([a, b, c])
    assert {fe.finding_id for fe in ordered} == {"a", "b", "c"}  # tutti presenti, nessun crash


def test_preambolo_non_promette_meccanismo_inattivo():
    """Il preambolo non istruisce più a 'rispettare depends_on' in assoluto come se
    fosse sempre popolato; lo cita solo condizionatamente ('se ... non vuoto')."""
    plan = _plan_con_fix("runs/g/ts")
    md = ab._render_fix_plan_md(plan)
    # l'ordine per priorità resta promesso
    assert "ordine" in md.lower()
    # depends_on è citato solo come condizione ('se ... depends_on non vuoto')
    if "depends_on" in md:
        assert "se un fix" in md.lower() or "non vuoto" in md.lower()


def test_fix_plan_md_verifica_finale_cita_accept_baseline():
    """La sezione 'Verifica finale' del FIX-PLAN.md documenta la precondizione del
    loop: FIXED si misura contro la baseline SALVATA (serve --accept-baseline)."""
    plan = _plan_con_fix("runs/g/ts")
    md = ab._render_fix_plan_md(plan)
    assert "--accept-baseline" in md
    assert "baseline salvata" in md.lower()


def test_fix_plan_md_rollback_multilinea_reso_in_fenced_block():
    """Regressione M2-0: dallo step view-aware il rollback_sql di RLS_DISABLED è un
    blocco DO multi-linea. Il render deve usare un fenced block ```sql (come la
    migration), MAI un inline-span single-backtick con newline dentro — che
    romperebbe il Markdown del FIX-PLAN.md (§18-bis.6)."""
    plan = _plan_con_fix("runs/g/ts")
    rls = next(fe for fe in plan.fixes if fe.rule_id == "RLS_DISABLED")
    # precondizione del test: il rollback è effettivamente multi-linea (view-aware)
    assert "\n" in rls.instructions["rollback_sql"]

    md = ab._render_fix_plan_md(plan)
    # la riga "Rollback:" non deve contenere SQL sulla stessa riga (niente inline
    # span): l'SQL del rollback vive in un blocco fenced sottostante.
    assert "  Rollback:\n" in md
    assert "Rollback: `" not in md
    # ogni riga del rollback compare indentata dentro un fenced block, non avvolta
    # da backtick inline insieme alle newline.
    for sql_line in rls.instructions["rollback_sql"].splitlines():
        if sql_line.strip():
            assert f"  {sql_line}" in md


# ─── M5 (§4.8): posture consumate + rotazioni M5 + RLS/GRANT ──────────────────
# Helper locali rinominati (`_m5`) per non adombrare il `_cfg`/`NOW` del resto del
# file (il `_cfg` esistente ha firma e name diversi: la ridefinizione romperebbe i
# test che asseriscono `plan.target == "gestionale"`).

def _cfg_m5() -> TargetConfig:
    return TargetConfig(name="t", base_url="https://s.example", environment="staging",
                        ownership="owned")


def _now_m5() -> datetime:
    return datetime(2026, 10, 11, tzinfo=timezone.utc)


def test_failed_posture_hsts_becomes_fix():
    pc = PostureCheck(check_id="POSTURE_HSTS", title="HSTS mancante", passed=False,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="assente")
    plan = ab.build_fix_plan([], _cfg_m5(), now=_now_m5(), run_dir="r", posture_checks=[pc])
    assert any(fx.rule_id == "POSTURE_HSTS" for fx in plan.fixes)


def test_posture_csp_aliases_to_missing_csp():
    pc = PostureCheck(check_id="POSTURE_CSP", title="CSP mancante", passed=False,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="assente")
    plan = ab.build_fix_plan([], _cfg_m5(), now=_now_m5(), run_dir="r", posture_checks=[pc])
    assert len(plan.fixes) == 1 and plan.fixes[0].fix_type.value == "config_change"


def test_passed_posture_ignored():
    pc = PostureCheck(check_id="POSTURE_HSTS", title="ok", passed=True,
                      severity_if_failed=Severity.MEDIUM, target="t", detail="presente")
    assert ab.build_fix_plan([], _cfg_m5(), now=_now_m5(), run_dir="r", posture_checks=[pc]).fixes == []


def test_rls_migration_includes_grant():
    f = Finding(finding_id="a"*16, module="supabase", rule_id="RLS_DISABLED", title="RLS",
                severity=Severity.CRITICAL, confidence=Confidence.FIRM, target="t",
                location=Location(endpoint="/rest/v1/clienti"), evidence="1 riga",
                description="", status=Status.NEW)
    plan = ab.build_fix_plan([f], _cfg_m5(), now=_now_m5(), run_dir="r")
    sql = plan.fixes[0].instructions["migration_sql"]
    # lo statement eseguibile, non il solo commento esplicativo
    assert "EXECUTE $q$GRANT SELECT ON public.clienti TO authenticated$q$" in sql
    # rollback: la tabella era già leggibile (aveva i GRANT) → niente REVOKE
    assert "REVOKE" not in plan.fixes[0].instructions["rollback_sql"]


def test_posture_csp_and_real_missing_csp_dedup_to_one_fix():
    """Alias: un Finding MISSING_CSP reale e un PostureCheck POSTURE_CSP fallito sono
    lo stesso fix → un'unica voce nel bundle."""
    f = Finding(finding_id="c"*16, module="headers", rule_id="MISSING_CSP", title="CSP",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target="t",
                location=Location(), evidence="assente", description="", status=Status.NEW)
    pc = PostureCheck(check_id="POSTURE_CSP", title="CSP mancante", passed=False,
                      severity_if_failed=Severity.HIGH, target="t", detail="assente")
    plan = ab.build_fix_plan([f], _cfg_m5(), now=_now_m5(), run_dir="r", posture_checks=[pc])
    assert len(plan.fixes) == 1


def test_new_secret_rotation_builder():
    f = Finding(finding_id="b"*16, module="secrets", rule_id="SECRET_OPENAI", title="OpenAI",
                severity=Severity.HIGH, confidence=Confidence.FIRM, target="t",
                location=Location(file="app.js"), evidence="sk-...", description="", status=Status.NEW)
    plan = ab.build_fix_plan([f], _cfg_m5(), now=_now_m5(), run_dir="r")
    fx = plan.fixes[0]
    assert fx.fix_type.value == "secret_rotation" and fx.priority == 1
    assert fx.applicable_by.value == "agent+human"
