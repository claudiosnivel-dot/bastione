"""Package del modulo Supabase probe — la gemma (§11 del blueprint).

Questo file è un marker di package: la classe concreta vive in `module.py` e si
auto-registra nel REGISTRY tramite il decoratore `@register` (§9). Non importa
nulla qui per evitare effetti collaterali all'import del package (il caricamento
del REGISTRY è responsabilità dell'orchestratore in fase PLAN, §6).
"""
