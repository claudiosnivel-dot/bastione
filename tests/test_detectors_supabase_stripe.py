from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity
import bastione.modules.secrets.detectors.supabase_secret as ss
import bastione.modules.secrets.detectors.stripe as st


def test_supabase_secret_key_critical():
    s = ss.SupabaseSecretKeyDetector().scan(TextAsset(source="app.js",
        content='const k="sb_secret_AbC123dEf456GhI789jKl";'))
    assert s and s[0].detector_id == "SECRET_SUPABASE_SECRET_KEY"
    assert ss.SupabaseSecretKeyDetector().severity == Severity.CRITICAL


def test_stripe_live_critical_test_high_webhook_high():   # D4
    d = st.StripeDetector()
    live = d.scan(TextAsset(source="x", content='sk_live_ABCdef0123456789XYZ'))
    test = d.scan(TextAsset(source="x", content='sk_test_ABCdef0123456789XYZ'))
    whk  = d.scan(TextAsset(source="x", content='whsec_ABCdef0123456789XYZ'))
    assert live[0].severity_override == Severity.CRITICAL
    assert test[0].severity_override == Severity.HIGH
    assert whk[0].severity_override == Severity.HIGH


def test_stripe_liveness_live_restricted_revoked(monkeypatch):
    d = st.StripeDetector()
    raw = RawSecret(detector_id="SECRET_STRIPE", value="sk_live_"+"A"*20, location=Location(file="x"))
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert d.validate_liveness(raw).mode == "live"
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=403))
    assert d.validate_liveness(raw).mode == "restricted"
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=401))
    r = d.validate_liveness(raw); assert r.alive is False and r.mode == "revoked"


def test_stripe_liveness_no_token_in_detail(monkeypatch):    # P8
    d = st.StripeDetector()
    tok = "sk_live_SENSITIVE000000000"
    raw = RawSecret(detector_id="SECRET_STRIPE", value=tok, location=Location(file="x"))
    monkeypatch.setattr(st, "_identity_get", lambda url, headers: SimpleNamespace(status_code=200))
    assert tok not in d.validate_liveness(raw).detail
