"""Package trivy — modulo white-box esterno (§14 del blueprint).

Marker di package. L'orchestratore importa bastione.modules.trivy.module per
registrare TrivyModule in REGISTRY (§9). Non si importa nulla qui per evitare
import ciclici (stessa convenzione degli altri moduli).
"""
