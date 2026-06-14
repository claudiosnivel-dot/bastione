"""Package zap — modulo black-box esterno (§14 del blueprint).

Marker di package. L'orchestratore importa bastione.modules.zap.module per
registrare ZapModule in REGISTRY (§9). Non si importa nulla qui per evitare
import ciclici (stessa convenzione degli altri moduli).
"""
