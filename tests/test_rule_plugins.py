"""Tests for pyaegis.rule_plugins — community rule pack manager."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from pyaegis.rule_plugins import RulePluginManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mgr(tmp_path):
    return RulePluginManager(rules_dir=str(tmp_path / "rules"))


@pytest.fixture
def sample_pack(tmp_path):
    """Write a valid YAML rule pack to disk and return its path."""
    data = {
        "inputs": ["environ.get", "getenv"],
        "sinks": ["ldap.search"],
        "sanitizers": ["escape"],
        "conditional_sinks": [],
        "source_decorators": [],
    }
    p = tmp_path / "sample_pack.yml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def test_install_local(mgr, sample_pack):
    name = mgr.install(sample_pack, name="test-pack")
    assert name == "test-pack"
    installed = mgr.list_installed()
    assert len(installed) == 1
    assert installed[0]["name"] == "test-pack"


def test_install_auto_name(mgr, sample_pack):
    name = mgr.install(sample_pack)  # name inferred from filename
    assert name == "sample_pack"


def test_install_duplicate_raises(mgr, sample_pack):
    mgr.install(sample_pack, name="dup")
    with pytest.raises(ValueError, match="already installed"):
        mgr.install(sample_pack, name="dup")


def test_install_duplicate_force(mgr, sample_pack):
    mgr.install(sample_pack, name="dup")
    name = mgr.install(sample_pack, name="dup", force=True)
    assert name == "dup"
    assert len(mgr.list_installed()) == 1


def test_install_invalid_yaml(mgr, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("[unclosed bracket\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        mgr.install(str(bad), name="bad")


def test_install_non_mapping_yaml(mgr, tmp_path):
    p = tmp_path / "list.yml"
    p.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a YAML mapping"):
        mgr.install(str(p), name="list")


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


def test_remove_installed(mgr, sample_pack):
    mgr.install(sample_pack, name="to-remove")
    result = mgr.remove("to-remove")
    assert result is True
    assert mgr.list_installed() == []


def test_remove_nonexistent(mgr):
    result = mgr.remove("ghost")
    assert result is False


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


def test_list_empty(mgr):
    assert mgr.list_installed() == []


def test_list_multiple(mgr, tmp_path, sample_pack):
    pack2 = tmp_path / "pack2.yml"
    pack2.write_text(yaml.safe_dump({"sinks": ["eval"]}), encoding="utf-8")
    mgr.install(sample_pack, name="p1")
    mgr.install(str(pack2), name="p2")
    names = {p["name"] for p in mgr.list_installed()}
    assert names == {"p1", "p2"}


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def test_merged_rules_includes_plugin(mgr, sample_pack):
    mgr.install(sample_pack, name="extra")
    merged = mgr.merged_rules(include_builtin=False)
    assert "environ.get" in merged["inputs"]
    assert "ldap.search" in merged["sinks"]


def test_merged_rules_deduplicates(mgr, tmp_path):
    p1 = tmp_path / "p1.yml"
    p2 = tmp_path / "p2.yml"
    p1.write_text(yaml.safe_dump({"inputs": ["os.environ"]}), encoding="utf-8")
    p2.write_text(
        yaml.safe_dump({"inputs": ["os.environ", "getenv"]}), encoding="utf-8"
    )
    mgr.install(str(p1), name="p1")
    mgr.install(str(p2), name="p2")
    merged = mgr.merged_rules(include_builtin=False)
    assert merged["inputs"].count("os.environ") == 1


def test_merged_rules_path_creates_file(mgr, sample_pack):
    mgr.install(sample_pack, name="mp")
    path = mgr.merged_rules_path(include_builtin=False)
    assert Path(path).exists()
    content = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    assert "sinks" in content
    Path(path).unlink()  # cleanup


# ---------------------------------------------------------------------------
# has_plugins
# ---------------------------------------------------------------------------


def test_has_plugins_false(mgr):
    assert mgr.has_plugins() is False


def test_has_plugins_true(mgr, sample_pack):
    mgr.install(sample_pack, name="any")
    assert mgr.has_plugins() is True


# ---------------------------------------------------------------------------
# Index persistence
# ---------------------------------------------------------------------------


def test_index_persists_across_instances(tmp_path, sample_pack):
    rules_dir = str(tmp_path / "rules")
    mgr1 = RulePluginManager(rules_dir=rules_dir)
    mgr1.install(sample_pack, name="persist")

    mgr2 = RulePluginManager(rules_dir=rules_dir)
    names = {p["name"] for p in mgr2.list_installed()}
    assert "persist" in names
