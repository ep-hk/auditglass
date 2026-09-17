"""Configuration is the read-only boundary, so invalid configuration must fail at
load time with a locator, not at incident time with a traceback."""

from __future__ import annotations

import pytest
import yaml

from auditglass.config import (
    Config,
    EndpointPolicy,
    FieldPolicy,
    load_config,
    parse_duration,
)
from auditglass.errors import ConfigError


def test_durations_parse():
    assert parse_duration("30s") == 30
    assert parse_duration("15m") == 900
    assert parse_duration("6h") == 21_600
    assert parse_duration("7d") == 604_800


@pytest.mark.parametrize("bad", ["", "6", "6x", "-1h", "1.5h", "six hours"])
def test_bad_durations_are_rejected(bad):
    with pytest.raises(ConfigError, match="invalid duration"):
        parse_duration(bad)


def test_endpoint_paths_must_be_exact():
    with pytest.raises(ValueError, match="must be exact"):
        EndpointPolicy(name="x", backend="loki", host="h", paths=["/api/*"])


def test_endpoint_paths_must_be_absolute():
    with pytest.raises(ValueError, match="must start with"):
        EndpointPolicy(name="x", backend="loki", host="h", paths=["api/v1/query"])


def test_unknown_keys_are_rejected(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(
        yaml.safe_dump({"scope": {"services": ["a"]}, "typo_key": 1}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(path)


def test_provider_referencing_an_undeclared_endpoint_fails(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "scope": {"services": ["a"]},
                "providers": [{"backend": "loki", "kind": "loki", "endpoint": "nope"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match=r"not declared in policy\.endpoints"):
        load_config(path)


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "absent.yaml")


def test_field_policy_free_text_must_be_allowed():
    with pytest.raises(ValueError, match="must also be in allow"):
        FieldPolicy(allow=["a"], free_text=["b"])


def test_field_policy_cannot_both_scan_and_tokenise():
    with pytest.raises(ValueError, match="cannot be both"):
        FieldPolicy(allow=["a"], free_text=["a"], pseudonymise={"a": "X"})


def test_config_hash_changes_when_policy_changes(config):
    before = config.config_hash()
    config.policy.endpoints.append(
        EndpointPolicy(name="new", backend="loki", host="loki.example", paths=["/x"])
    )
    assert config.config_hash() != before


def test_config_hash_is_stable_for_identical_content(config):
    assert config.config_hash() == config.config_hash()


def test_paths_resolve_relative_to_the_config_file(config):
    for path in config.template_files:
        assert path.is_absolute()
        assert path.is_file()


def test_demo_config_declares_no_network_endpoint_with_credentials(config):
    """The demo must not imply a deployment needs to reach anything real."""
    for endpoint in config.policy.endpoints:
        assert endpoint.host.endswith(".invalid") or endpoint.backend == "fixture"


def test_empty_scope_is_rejected():
    with pytest.raises(ValueError):
        Config(scope={"services": []})
