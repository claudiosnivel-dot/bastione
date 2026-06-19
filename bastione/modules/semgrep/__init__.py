"""Package semgrep — modulo white-box locale (§14 del blueprint).

Marker di package. L'orchestratore importa bastione.modules.semgrep.module per
registrare SemgrepModule in REGISTRY (§9). Non si importa nulla qui per evitare
import ciclici (stessa convenzione degli altri moduli).
"""
