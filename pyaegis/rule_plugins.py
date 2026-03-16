"""
PyAegis Rule Plugin Manager
============================

允许社区通过 URL 或本地路径安装额外的 YAML 规则包。
规则包会被保存到 ~/.pyaegis/rules/ 目录，并在下次扫描时自动合并。

用法::

    pyaegis install-rules https://example.com/my-rules.yml
    pyaegis install-rules ./local-rules.yml --name custom
    pyaegis list-installed-rules
    pyaegis remove-rules custom

编程接口::

    from pyaegis.rule_plugins import RulePluginManager
    mgr = RulePluginManager()
    mgr.install("https://example.com/rules.yml", name="community")
    merged = mgr.merged_rules_path()  # 合并所有规则后的临时文件路径
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_RULES_DIR = Path.home() / ".pyaegis" / "rules"
_INDEX_FILE = _DEFAULT_RULES_DIR / "index.json"
_BUILTIN_RULES = Path(__file__).parent / "rules" / "default.yml"


# ---------------------------------------------------------------------------
# Index helpers
# ---------------------------------------------------------------------------


def _load_index(rules_dir: Path) -> Dict[str, dict]:
    idx_path = rules_dir / "index.json"
    if not idx_path.exists():
        return {}
    try:
        return json.loads(idx_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_index(rules_dir: Path, index: Dict[str, dict]) -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# RulePluginManager
# ---------------------------------------------------------------------------


class RulePluginManager:
    """Install, list, and merge community YAML rule packs."""

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Install
    # ------------------------------------------------------------------

    def install(
        self,
        source: str,
        name: Optional[str] = None,
        force: bool = False,
    ) -> str:
        """Install a rule pack from a URL or local path.

        Returns the installed rule pack name.
        """
        # Determine name from source if not given
        if not name:
            stem = Path(source.split("?")[0]).stem
            name = stem if stem else "custom"
        # Sanitise name
        name = "".join(c for c in name if c.isalnum() or c in "-_")

        index = _load_index(self.rules_dir)
        if name in index and not force:
            raise ValueError(
                f"Rule pack '{name}' already installed. Use --force to overwrite."
            )

        # Fetch content
        content = self._fetch(source)

        # Validate it's parseable YAML with expected keys
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in rule pack: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Rule pack must be a YAML mapping (dict).")

        # Save to rules dir
        dest = self.rules_dir / f"{name}.yml"
        dest.write_text(content, encoding="utf-8")

        # Update index
        sha256 = hashlib.sha256(content.encode()).hexdigest()[:16]
        index[name] = {
            "name": name,
            "source": source,
            "file": str(dest),
            "sha256": sha256,
            "keys": list(data.keys()),
        }
        _save_index(self.rules_dir, index)
        return name

    # ------------------------------------------------------------------
    # Remove
    # ------------------------------------------------------------------

    def remove(self, name: str) -> bool:
        """Remove an installed rule pack. Returns True if removed."""
        index = _load_index(self.rules_dir)
        if name not in index:
            return False
        rule_file = Path(index[name]["file"])
        if rule_file.exists():
            rule_file.unlink()
        del index[name]
        _save_index(self.rules_dir, index)
        return True

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_installed(self) -> List[dict]:
        """Return list of installed rule packs."""
        return list(_load_index(self.rules_dir).values())

    # ------------------------------------------------------------------
    # Merge
    # ------------------------------------------------------------------

    def merged_rules(self, include_builtin: bool = True) -> dict:
        """Merge all installed rule packs into a single rules dict."""
        merged: dict = {
            "inputs": [],
            "sinks": [],
            "sanitizers": [],
            "conditional_sinks": [],
            "source_decorators": [],
        }

        sources = []
        if include_builtin and _BUILTIN_RULES.exists():
            sources.append(_BUILTIN_RULES)

        index = _load_index(self.rules_dir)
        for entry in index.values():
            fp = Path(entry["file"])
            if fp.exists():
                sources.append(fp)

        for src in sources:
            try:
                data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            for key in (
                "inputs",
                "sinks",
                "sanitizers",
                "conditional_sinks",
                "source_decorators",
            ):
                if key in data and isinstance(data[key], list):
                    merged[key].extend(data[key])

        # Deduplicate string entries
        for key in ("inputs", "sinks", "sanitizers", "source_decorators"):
            seen = []
            for item in merged[key]:
                if item not in seen:
                    seen.append(item)
            merged[key] = seen

        return merged

    def merged_rules_path(self, include_builtin: bool = True) -> str:
        """Write merged rules to a temp file and return the path.

        Useful for passing to CLI --rules flag.
        """
        merged = self.merged_rules(include_builtin=include_builtin)
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yml",
            prefix="pyaegis_merged_",
            delete=False,
            encoding="utf-8",
        )
        yaml.safe_dump(merged, tmp)
        tmp.close()
        return tmp.name

    def has_plugins(self) -> bool:
        """Return True if any community rule packs are installed."""
        return bool(_load_index(self.rules_dir))

    # ------------------------------------------------------------------
    # Fetch helper
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch(source: str) -> str:
        """Fetch rule pack content from URL or local path."""
        if source.startswith(("http://", "https://")):
            req = urllib.request.Request(
                source,
                headers={"User-Agent": "PyAegis-RuleInstaller/0.3"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                return resp.read().decode("utf-8", errors="replace")
        else:
            return Path(source).read_text(encoding="utf-8")
