import pytest
from types import SimpleNamespace
from bastione.models import TextAsset, RawSecret, Location
from bastione.enums import Severity
import bastione.modules.secrets.detectors.ai_keys as ai

def test_openai_not_matching_anthropic():
    o = ai.OpenAiDetector()
    assert o.scan(TextAsset(source="x", content="sk-" + "A"*24))
    assert o.scan(TextAsset(source="x", content="sk-ant-" + "A"*24)) == []   # non è OpenAI
    assert o.severity == Severity.HIGH

def test_anthropic_match():
    a = ai.AnthropicDetector()
    assert a.scan(TextAsset(source="x", content="sk-ant-api03-" + "A"*24))

def test_google_low_and_liveness_detail(monkeypatch):
    g = ai.GoogleApiKeyDetector()
    s = g.scan(TextAsset(source="x", content="AIza" + "a"*35))
    assert s and g.severity == Severity.LOW
    raw = s[0]
    monkeypatch.setattr(ai, "_identity_get", lambda url, headers=None: SimpleNamespace(status_code=200))
    r = g.validate_liveness(raw)
    assert r.alive is True and "AI" in r.detail.upper()

def test_openai_liveness(monkeypatch):
    d = ai.OpenAiDetector()
    raw = RawSecret(detector_id="SECRET_OPENAI", value="sk-"+"A"*24, location=Location(file="x"))
    monkeypatch.setattr(ai, "_identity_get", lambda url, headers=None: SimpleNamespace(status_code=401))
    assert d.validate_liveness(raw).alive is False


_CASES = [
    # (detector, valore, status, alive atteso, mode atteso)
    (ai.OpenAiDetector(), "sk-" + "A" * 24, 200, True, "live"),
    (ai.OpenAiDetector(), "sk-" + "A" * 24, 401, False, "revoked"),
    (ai.AnthropicDetector(), "sk-ant-api03-" + "A" * 24, 200, True, "live"),
    (ai.AnthropicDetector(), "sk-ant-api03-" + "A" * 24, 401, False, "revoked"),
    (ai.GoogleApiKeyDetector(), "AIza" + "a" * 35, 200, True, "live"),
    (ai.GoogleApiKeyDetector(), "AIza" + "a" * 35, 400, False, "restricted"),
    (ai.GoogleApiKeyDetector(), "AIza" + "a" * 35, 403, False, "restricted"),
]


@pytest.mark.parametrize("det,value,status,alive,mode", _CASES)
def test_liveness_both_variants_and_p8(monkeypatch, det, value, status, alive, mode):
    calls = []
    def fake(url, headers=None):
        calls.append((url, headers or {}))
        return SimpleNamespace(status_code=status)
    monkeypatch.setattr(ai, "_identity_get", fake)
    raw = RawSecret(detector_id=det.detector_id, value=value, location=Location(file="x"))
    r = det.validate_liveness(raw)
    assert r.alive is alive and r.mode == mode
    assert value not in r.detail                       # P8
    url, headers = calls[0]
    assert value not in url                            # P8: mai in query string/URL
    assert value in "".join(headers.values())          # la chiave viaggia in header


@pytest.mark.parametrize("det", [ai.OpenAiDetector(), ai.AnthropicDetector(),
                                 ai.GoogleApiKeyDetector()])
def test_liveness_unknown_outcome_is_none(monkeypatch, det):
    raw = RawSecret(detector_id=det.detector_id, value="v" * 40, location=Location(file="x"))
    monkeypatch.setattr(ai, "_identity_get", lambda url, headers=None: None)
    assert det.validate_liveness(raw) is None
    monkeypatch.setattr(ai, "_identity_get",
                        lambda url, headers=None: SimpleNamespace(status_code=500))
    assert det.validate_liveness(raw) is None


def test_anthropic_liveness_sends_version_header(monkeypatch):
    seen = {}
    monkeypatch.setattr(ai, "_identity_get",
                        lambda url, headers=None: seen.update(url=url, h=headers) or
                        SimpleNamespace(status_code=200))
    raw = RawSecret(detector_id="SECRET_ANTHROPIC", value="sk-ant-x" + "A" * 24,
                    location=Location(file="x"))
    ai.AnthropicDetector().validate_liveness(raw)
    assert seen["url"] == "https://api.anthropic.com/v1/models"
    assert seen["h"]["anthropic-version"] == "2023-06-01"
