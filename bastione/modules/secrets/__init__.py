"""Package secrets — modulo di rilevamento segreti esposti (§10 del blueprint).

Marker di package. L'orchestratore importa bastione.modules.secrets.module
per registrare SecretsModule in REGISTRY (§9). Non si importa nulla qui
per evitare import ciclici (stessa convenzione di bastione/modules/__init__.py).
"""
