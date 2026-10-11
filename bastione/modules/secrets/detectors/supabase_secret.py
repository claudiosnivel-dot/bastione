"""Detector SECRET_SUPABASE_SECRET_KEY — chiave segreta Supabase nuovo formato (§4.4).

`sb_secret_…` bypassa la RLS esattamente come la legacy `service_role` → CRITICAL.
Liveness rimandata (token opaco, nessun ref): vedi nota R6 nel piano.
"""
from __future__ import annotations
import re
from bastione.enums import Severity
from bastione.models import Location, RawSecret, TextAsset
from bastione.modules.secrets.detectors.base import Detector, register_detector

_RE = re.compile(r"sb_secret_[A-Za-z0-9]+")


@register_detector
class SupabaseSecretKeyDetector(Detector):
    detector_id = "SECRET_SUPABASE_SECRET_KEY"
    title = "Supabase secret key (nuovo formato) esposta"
    severity = Severity.CRITICAL
    gdpr_relevant = False

    def scan(self, asset: TextAsset) -> list[RawSecret]:
        return [RawSecret(detector_id=self.detector_id, value=m,
                          location=Location(file=asset.source))
                for m in _RE.findall(asset.content)]
