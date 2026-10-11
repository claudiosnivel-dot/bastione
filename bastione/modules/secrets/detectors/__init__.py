"""Package detector di segreti (§10). Importare questo package popola DETECTORS
con tutti i detector registrati via @register_detector (§10/§4.4)."""
from __future__ import annotations

from bastione.modules.secrets.detectors import service_role as _service_role  # noqa: F401
from bastione.modules.secrets.detectors import supabase_secret as _supabase_secret  # noqa: F401
from bastione.modules.secrets.detectors import stripe as _stripe  # noqa: F401
from bastione.modules.secrets.detectors import cloud_repo as _cloud_repo  # noqa: F401
from bastione.modules.secrets.detectors import ai_keys as _ai_keys  # noqa: F401
from bastione.modules.secrets.detectors import misc as _misc  # noqa: F401

__all__ = ["_service_role", "_supabase_secret", "_stripe", "_cloud_repo", "_ai_keys", "_misc"]
