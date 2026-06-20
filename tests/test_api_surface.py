from bastione.models import ApiEndpoint, Fingerprint, TargetConfig, AuthConfig
from bastione.recon.api_surface import extract_api_paths, build_api_surface


def _cfg(endpoints=None):
    return TargetConfig(name="t", base_url="https://staging.example.com",
                        environment="staging", ownership="owned",
                        auth=AuthConfig(api_endpoints=endpoints or []))


def test_extract_api_paths_from_bundle():
    js = """fetch('/api/orders').then(r=>r.json());
            const u = "/api/users/42"; axios.post("/api/notes", body);
            Array.from('abc'); location = '/login';"""
    paths = extract_api_paths(js)
    assert "/api/orders" in paths
    assert "/api/users/42" in paths
    assert "/api/notes" in paths
    # non-/api path non incluso; dedup+sort deterministico
    assert "/login" not in paths
    assert paths == sorted(set(paths))


def test_build_api_surface_declared_is_ground_truth_plus_assist():
    declared = [ApiEndpoint(method="GET", path_template="/api/orders", kind="list")]
    fp = Fingerprint(target="t", resolved_urls=[], discovered_api_paths=["/api/secret-admin"])
    surface = build_api_surface(fp, _cfg(declared))
    assert [e.path_template for e in surface.endpoints] == ["/api/orders"]
    assert "/api/secret-admin" in surface.extracted_paths


def test_build_api_surface_no_auth_empty():
    fp = Fingerprint(target="t", resolved_urls=[])
    cfg = TargetConfig(name="t", base_url="https://s.example.com",
                       environment="staging", ownership="owned")
    surface = build_api_surface(fp, cfg)
    assert surface.endpoints == []
