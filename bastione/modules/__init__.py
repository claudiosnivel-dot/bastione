"""Package dei moduli di scansione (§9 del blueprint).

Questo file è un marker di package. NON importa moduli concreti per evitare
import ciclici. Il caricamento del REGISTRY viene eseguito dall'orchestratore
in fase PLAN (§6) dopo che tutti i moduli sono stati scoperti.
"""
