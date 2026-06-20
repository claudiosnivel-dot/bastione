import tomllib

from bastione.config import _flatten
from bastione.models import AuthConfig, ApiEndpoint, TestAccount, TargetConfig


def _base_cfg_kwargs():
    return dict(name="t", base_url="https://staging.example.com",
                environment="staging", ownership="owned")


def test_test_account_token_mode_defaults():
    a = TestAccount(label="B", mode="token", token_env="BASTIONE_IDOR_B_TOKEN")
    assert a.label == "B"
    assert a.token_header == "Authorization"
    assert a.token_prefix == "Bearer "
    assert a.login_url is None


def test_test_account_login_post_mode():
    a = TestAccount(label="A", mode="login_post",
                    login_url="https://staging.example.com/api/auth/login",
                    email="a@example.com", password_env="BASTIONE_IDOR_A_PW",
                    session_json_path="access_token")
    assert a.mode == "login_post"
    assert a.session_json_path == "access_token"


def test_api_endpoint_kind_and_public_default():
    e = ApiEndpoint(method="GET", path_template="/api/orders/{id}", kind="read")
    assert e.public is False
    assert e.kind == "read"


def test_targetconfig_auth_defaults_none_and_accepts_authconfig():
    cfg = TargetConfig(**_base_cfg_kwargs())
    assert cfg.auth is None
    auth = AuthConfig(
        test_accounts=[TestAccount(label="A", mode="token", token_env="X"),
                       TestAccount(label="B", mode="token", token_env="Y")],
        api_endpoints=[ApiEndpoint(method="GET", path_template="/api/orders", kind="list")],
        public_endpoints=["/api/health"])
    cfg2 = TargetConfig(**_base_cfg_kwargs(), auth=auth)
    assert len(cfg2.auth.test_accounts) == 2
    assert cfg2.auth.public_endpoints == ["/api/health"]


_AUTH_TOML = """
name = "t"
base_url = "https://staging.example.com"
environment = "staging"
ownership = "owned"

[[auth.test_accounts]]
label = "A"
mode = "login_post"
login_url = "https://staging.example.com/api/auth/login"
email = "a@example.com"
password_env = "BASTIONE_IDOR_A_PW"
session_json_path = "access_token"

[[auth.test_accounts]]
label = "B"
mode = "token"
token_env = "BASTIONE_IDOR_B_TOKEN"

[[auth.api_endpoints]]
method = "GET"
path_template = "/api/orders"
kind = "list"

[[auth.api_endpoints]]
method = "POST"
path_template = "/api/notes"
kind = "create"

[auth.suppression]
public_endpoints = ["/api/health", "/api/public/*"]
"""


def test_flatten_parses_auth_section():
    data = tomllib.loads(_AUTH_TOML)
    cfg = TargetConfig(**_flatten(data))
    assert cfg.auth is not None
    labels = {a.label for a in cfg.auth.test_accounts}
    assert labels == {"A", "B"}
    kinds = {e.kind for e in cfg.auth.api_endpoints}
    assert kinds == {"list", "create"}
    assert cfg.auth.public_endpoints == ["/api/health", "/api/public/*"]


def test_flatten_no_auth_section_leaves_auth_none():
    data = tomllib.loads(
        'name="t"\nbase_url="https://s.example.com"\n'
        'environment="staging"\nownership="owned"\n')
    cfg = TargetConfig(**_flatten(data))
    assert cfg.auth is None
