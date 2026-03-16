"""
SampleStore - 本地威胁样本数据集管理系统

功能：
- 入库新样本（含元数据）
- 按标签/家族/来源查询
- 导出训练集（JSONL格式）
- 统计数据集分布
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class SampleEntry:
    sha256: str
    label: str  # malicious / suspicious / clean
    malware_family: str = ""
    source: str = "manual"  # manual / virustotal / malwarebazaar / feedback
    tags: list[str] = field(default_factory=list)
    file_type: str = ""
    file_size: int = 0
    added_at: float = field(default_factory=time.time)
    notes: str = ""


class SampleStore:
    """
    本地样本库。

    目录结构::

        store_dir/
            index.jsonl          # 元数据索引
            <sha256[:2]>/<sha256> # 样本文件（可选）
    """

    def __init__(self, store_dir: str = "samples") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.store_dir / "index.jsonl"

    def add(self, entry: SampleEntry, file_path: Optional[str] = None) -> None:
        """Add a sample entry to the store."""
        with open(self._index_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        if file_path:
            dest = self.store_dir / entry.sha256[:2] / entry.sha256
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest)

    def query(
        self,
        label: Optional[str] = None,
        family: Optional[str] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> Iterator[SampleEntry]:
        """Query entries by optional filters."""
        if not self._index_path.exists():
            return
        with open(self._index_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                e = SampleEntry(**d)
                if label and e.label != label:
                    continue
                if family and e.malware_family != family:
                    continue
                if source and e.source != source:
                    continue
                if tag and tag not in e.tags:
                    continue
                yield e

    def stats(self) -> dict:
        """Return distribution statistics."""
        counts: dict = {"total": 0, "by_label": {}, "by_family": {}}
        for e in self.query():
            counts["total"] += 1
            counts["by_label"][e.label] = counts["by_label"].get(e.label, 0) + 1
            if e.malware_family:
                counts["by_family"][e.malware_family] = (
                    counts["by_family"].get(e.malware_family, 0) + 1
                )
        return counts

    @staticmethod
    def sha256_of(file_path: str) -> str:
        """Compute SHA-256 of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
