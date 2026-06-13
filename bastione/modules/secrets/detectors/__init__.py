"""Package detector di segreti (§10 del blueprint).

Importare questo package popola DETECTORS con tutti i detector registrati
tramite @register_detector. L'import di .service_role scatena la registrazione
del detector SECRET_SERVICE_ROLE.
"""

from __future__ import annotations

from bastione.modules.secrets.detectors import service_role as _service_role  # noqa: F401

__all__ = ["_service_role"]
