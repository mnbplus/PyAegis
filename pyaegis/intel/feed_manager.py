"""
ThreatFeedManager - 威胁情报源管理器

支持接入外部威胁情报：
- VirusTotal API（文件哈希查询）
- MalwareBazaar API（样本数据库）
- 本地自定义规则源
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

logger = logging.getLogger(__name__)


@dataclass
class ThreatRecord:
    """一条威胁情报记录"""

    sha256: str
    sha1: str = ""
    md5: str = ""
    source: str = "unknown"  # virustotal / malwarebazaar / local
    verdict: str = "unknown"  # malicious / suspicious / clean / unknown
    malware_family: str = ""
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 ~ 1.0
    fetched_at: float = field(default_factory=time.time)
    raw: dict = field(default_factory=dict)


class ThreatFeedManager:
    """
    统一威胁情报接口。

    用法::

        mgr = ThreatFeedManager(cache_dir=".cache/intel",
                                vt_api_key="YOUR_KEY")
        record = mgr.query_file(Path("suspicious.exe"))
        print(record.verdict, record.malware_family)
    """

    VT_URL = "https://www.virustotal.com/api/v3/files/{}"
    MB_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(
        self,
        cache_dir: str | Path = ".cache/intel",
        vt_api_key: Optional[str] = None,
        mb_enabled: bool = True,
        cache_ttl: int = 86400,  # 缓存有效期，默认 24h
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.vt_api_key = vt_api_key
        self.mb_enabled = mb_enabled
        self.cache_ttl = cache_ttl

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    def query_file(self, path: Path) -> ThreatRecord:
        """查询一个文件的威胁情报（先读缓存，再联网）。"""
        sha256 = self._sha256(path)
        cached = self._load_cache(sha256)
        if cached:
            logger.debug("[intel] cache hit for %s", sha256[:16])
            return cached

        record = self._fetch(sha256)
        self._save_cache(record)
        return record

    def query_hash(self, sha256: str) -> ThreatRecord:
        """直接用哈希查询。"""
        cached = self._load_cache(sha256)
        if cached:
            return cached
        record = self._fetch(sha256)
        self._save_cache(record)
        return record

    # ------------------------------------------------------------------
    # 私有方法
    # ------------------------------------------------------------------

    def _fetch(self, sha256: str) -> ThreatRecord:
        """依次尝试 VirusTotal -> MalwareBazaar，返回首个有效结果。"""
        if self.vt_api_key:
            rec = self._query_virustotal(sha256)
            if rec.verdict != "unknown":
                return rec

        if self.mb_enabled:
            rec = self._query_malwarebazaar(sha256)
            if rec.verdict != "unknown":
                return rec

        return ThreatRecord(sha256=sha256, source="none", verdict="unknown")

    def _query_virustotal(self, sha256: str) -> ThreatRecord:
        if not _HAS_REQUESTS:
            logger.warning("[intel] requests not installed, skipping VT query")
            return ThreatRecord(sha256=sha256, source="virustotal", verdict="unknown")

        url = self.VT_URL.format(sha256)
        headers = {"x-apikey": self.vt_api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 404:
                return ThreatRecord(
                    sha256=sha256, source="virustotal", verdict="unknown"
                )
            resp.raise_for_status()
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            confidence = (malicious + suspicious * 0.5) / total

            if malicious > 3:
                verdict = "malicious"
            elif malicious > 0 or suspicious > 3:
                verdict = "suspicious"
            else:
                verdict = "clean"

            family = (
                data["data"]["attributes"]
                .get("popular_threat_classification", {})
                .get("suggested_threat_label", "")
            )
            return ThreatRecord(
                sha256=sha256,
                source="virustotal",
                verdict=verdict,
                malware_family=family,
                confidence=round(confidence, 4),
                raw=stats,
            )
        except Exception as e:
            logger.warning("[intel] VirusTotal query failed: %s", e)
            return ThreatRecord(sha256=sha256, source="virustotal", verdict="unknown")

    def _query_malwarebazaar(self, sha256: str) -> ThreatRecord:
        if not _HAS_REQUESTS:
            return ThreatRecord(
                sha256=sha256, source="malwarebazaar", verdict="unknown"
            )

        payload = {"query": "get_info", "hash": sha256}
        try:
            resp = requests.post(self.MB_URL, data=payload, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") != "ok":
                return ThreatRecord(
                    sha256=sha256, source="malwarebazaar", verdict="unknown"
                )

            entry = data["data"][0]
            tags = entry.get("tags") or []
            family = entry.get("signature") or ""
            return ThreatRecord(
                sha256=sha256,
                sha1=entry.get("sha1", ""),
                md5=entry.get("md5", ""),
                source="malwarebazaar",
                verdict="malicious",
                malware_family=family,
                tags=tags,
                confidence=0.9,
                raw=entry,
            )
        except Exception as e:
            logger.warning("[intel] MalwareBazaar query failed: %s", e)
            return ThreatRecord(
                sha256=sha256, source="malwarebazaar", verdict="unknown"
            )

    # ------------------------------------------------------------------
    # 缓存
    # ------------------------------------------------------------------

    def _cache_path(self, sha256: str) -> Path:
        return self.cache_dir / f"{sha256}.json"

    def _load_cache(self, sha256: str) -> Optional[ThreatRecord]:
        p = self._cache_path(sha256)
        if not p.exists():
            return None
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            fetched_at = raw.get("fetched_at", 0)
            if time.time() - fetched_at > self.cache_ttl:
                p.unlink(missing_ok=True)
                return None
            return ThreatRecord(**raw)
        except Exception:
            return None

    def _save_cache(self, record: ThreatRecord) -> None:
        p = self._cache_path(record.sha256)
        try:
            import dataclasses

            p.write_text(
                json.dumps(dataclasses.asdict(record), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning("[intel] cache write failed: %s", e)

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
