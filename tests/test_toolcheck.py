import bastione.toolcheck as tc


def test_no_policy_tool_is_allowed():
    s = tc.check_tool("whatweb")           # nessuna policy → ammesso
    assert s.ok is True


def test_version_ok(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.72.0")
    s = tc.check_tool("trivy")
    assert s.ok is True and s.version == "0.72.0"


def test_version_below_min_fails(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.71.9")
    s = tc.check_tool("trivy")
    assert s.ok is False and "minimo" in s.reason


def test_version_denied_fails(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Version: 0.69.4")
    s = tc.check_tool("trivy")
    assert s.ok is False and "VIETATA" in s.reason.upper() or "vietat" in s.reason


def test_version_unreadable_fail_closed(monkeypatch):   # Review Focus #4
    monkeypatch.setattr(tc, "_read_version", lambda name: None)
    s = tc.check_tool("nuclei")
    assert s.ok is False and s.version is None


def test_version_garbage_fail_closed(monkeypatch):      # Review Focus #4
    monkeypatch.setattr(tc, "_read_version", lambda name: "nuclei banana split")
    s = tc.check_tool("nuclei")
    assert s.ok is False


def test_nuclei_min_and_extract_from_noise(monkeypatch):
    monkeypatch.setattr(tc, "_read_version", lambda name: "Nuclei Engine Version: v3.10.0")
    assert tc.check_tool("nuclei").ok is True
    monkeypatch.setattr(tc, "_read_version", lambda name: "v3.9.9")
    assert tc.check_tool("nuclei").ok is False


def test_read_version_undecodable_output_does_not_crash(monkeypatch):
    """§4.7: un errore di decodifica dell'output di `--version` degrada a None
    (fail-closed in check_tool), mai un'eccezione fuori dal confine I/O."""
    import subprocess
    monkeypatch.setattr(tc.shutil, "which", lambda name: "/usr/bin/" + name)
    def boom(*a, **k):
        raise UnicodeDecodeError("cp1252", b"\x81", 0, 1, "undefined")
    monkeypatch.setattr(tc.subprocess, "run", boom)
    assert tc._read_version("trivy") is None
    assert tc.check_tool("trivy").ok is False


def test_read_version_decodes_with_replace(monkeypatch):
    seen = {}
    monkeypatch.setattr(tc.shutil, "which", lambda name: "/usr/bin/" + name)
    class _P:
        stdout = "Version: 0.72.0"
        stderr = ""
    def run(argv, **kw):
        seen.update(kw)
        return _P()
    monkeypatch.setattr(tc.subprocess, "run", run)
    assert tc._read_version("trivy") == "Version: 0.72.0"
    assert seen.get("errors") == "replace"
