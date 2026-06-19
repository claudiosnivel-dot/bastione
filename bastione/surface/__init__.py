"""Attack-surface inventory (M3): cosa è *esposto* del target, nel tempo.

Feature PURA e deterministica (zero rete, zero subprocess): riusa il modello del
kernel baseline (§16). Da una `Fingerprint` (output di RECON, §8) costruisce uno
`SurfaceSnapshot` ordinato/deduplicato con id deterministico, ne calcola il diff
contro lo snapshot precedente (added/removed per categoria) e lo persiste in un
JSON committabile (`baselines/<target>.surface.json`), così la superficie
d'attacco — tabelle scoperte, endpoint, URL — è tracciata come la baseline dei
finding. La logica vive in `inventory.py`; questo file è solo il marker di package.
"""
