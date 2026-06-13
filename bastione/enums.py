"""Enum del dominio (§5.1 del blueprint, LOCKED).

`Severity` e `IntrusionLevel` sono `IntEnum` perché devono essere ordinabili:
le soglie di alert/CI (§19/§22), il posture score pesato (§17) e il gate di
intrusione (§7) confrontano questi valori. `Confidence`, `Status` e `Phase`
sono enum di stringhe: i loro valori finiscono stabili in report e state.json.
"""

from enum import Enum, IntEnum


class Severity(IntEnum):
    """Ordinabile, per soglie e score."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(str, Enum):
    FIRM = "firm"              # verificato (es. RLS off confermato da una GET)
    TENTATIVE = "tentative"    # euristico (es. stringa ad alta entropia)


class Status(str, Enum):
    NEW = "new"                # assente dalla baseline
    KNOWN = "known"            # presente in baseline, non accettato
    ACCEPTED = "accepted"      # presente in baseline e accettato (rumore noto)
    FIXED = "fixed"            # in baseline ma non più riscontrato in questa run
    DRIFT = "drift"            # SOLO per posture check passante→fallito (PostureCheck.drift,
                               # §5.4/§16); mai assegnato a Finding.status — nei report/counts
                               # indica la regressione


class IntrusionLevel(IntEnum):
    READ_ONLY = 0              # 🟢 passivo: recon, GET, detection segreti
    PROBE = 1                 # 🟡 attivo non-mutante: liveness, tentativi di lettura RLS
    MUTATING = 2              # 🔴 scrittura: canary INSERT/UPDATE/DELETE


class Phase(str, Enum):
    LOAD = "load"
    OWNERSHIP = "ownership"
    RECON = "recon"
    PLAN = "plan"
    SCAN = "scan"
    NORMALIZE = "normalize"
    BASELINE = "baseline"
    POSTURE = "posture"
    REPORT = "report"
    REMEDIATE = "remediate"
    NOTIFY = "notify"
    PERSIST = "persist"
