"""Cache for vulnerability data."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from depguard.models import CVSSScore, Reference, Severity, Vulnerability


DEFAULT_CACHE_DIR = ".depguard-cache"
DEFAULT_TTL_HOURS = 24


@dataclass
class CacheEntry:
    """A cached vulnerability lookup result."""
    package: str
    version: str
    ecosystem: str
    vulnerabilities: List[Dict[str, Any]]
    cached_at: str  # ISO format datetime
    
    def is_expired(self, ttl_hours: int = DEFAULT_TTL_HOURS) -> bool:
        """Check if cache entry has expired."""
        cached_time = datetime.fromisoformat(self.cached_at)
        expiry = cached_time + timedelta(hours=ttl_hours)
        return datetime.now() > expiry


class VulnerabilityCache:
    """File-based cache for vulnerability lookups."""
    
    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_hours: int = DEFAULT_TTL_HOURS,
        enabled: bool = True,
    ):
        self.cache_dir = Path(cache_dir) if cache_dir else Path(DEFAULT_CACHE_DIR)
        self.ttl_hours = ttl_hours
        self.enabled = enabled
        
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _cache_key(self, package: str, version: str, ecosystem: str) -> str:
        """Generate cache key for a package lookup."""
        key_str = f"{ecosystem}:{package}:{version}"
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]
    
    def _cache_path(self, cache_key: str) -> Path:
        """Get cache file path for a key."""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(
        self,
        package: str,
        version: str,
        ecosystem: str = "PyPI",
    ) -> Optional[List[Vulnerability]]:
        """Get cached vulnerabilities for a package.
        
        Returns None if not cached or expired.
        """
        if not self.enabled:
            return None
        
        cache_key = self._cache_key(package, version, ecosystem)
        cache_path = self._cache_path(cache_key)
        
        if not cache_path.exists():
            return None
        
        try:
            data = json.loads(cache_path.read_text(encoding='utf-8'))
            entry = CacheEntry(**data)
            
            if entry.is_expired(self.ttl_hours):
                # Remove expired entry
                cache_path.unlink(missing_ok=True)
                return None
            
            return self._deserialize_vulnerabilities(entry.vulnerabilities)
        
        except (json.JSONDecodeError, KeyError, TypeError):
            # Invalid cache entry, remove it
            cache_path.unlink(missing_ok=True)
            return None
    
    def set(
        self,
        package: str,
        version: str,
        vulnerabilities: List[Vulnerability],
        ecosystem: str = "PyPI",
    ) -> None:
        """Cache vulnerabilities for a package."""
        if not self.enabled:
            return
        
        cache_key = self._cache_key(package, version, ecosystem)
        cache_path = self._cache_path(cache_key)
        
        entry = CacheEntry(
            package=package,
            version=version,
            ecosystem=ecosystem,
            vulnerabilities=self._serialize_vulnerabilities(vulnerabilities),
            cached_at=datetime.now().isoformat(),
        )
        
        try:
            cache_path.write_text(
                json.dumps(asdict(entry), indent=2, default=str),
                encoding='utf-8'
            )
        except OSError:
            pass  # Cache write failures are non-fatal
    
    def _serialize_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Dict[str, Any]]:
        """Serialize vulnerabilities for caching."""
        result = []
        for vuln in vulnerabilities:
            data = {
                "id": vuln.id,
                "aliases": vuln.aliases,
                "summary": vuln.summary,
                "details": vuln.details,
                "severity": vuln.severity.value,
                "affected_versions": vuln.affected_versions,
                "fixed_versions": vuln.fixed_versions,
                "cwe": vuln.cwe,
            }
            
            if vuln.cvss:
                data["cvss"] = {
                    "score": vuln.cvss.score,
                    "vector": vuln.cvss.vector,
                    "version": vuln.cvss.version,
                }
            
            if vuln.published:
                data["published"] = vuln.published.isoformat()
            if vuln.modified:
                data["modified"] = vuln.modified.isoformat()
            
            data["references"] = [
                {"type": ref.type, "url": ref.url}
                for ref in vuln.references
            ]
            
            result.append(data)
        
        return result
    
    def _deserialize_vulnerabilities(
        self,
        data: List[Dict[str, Any]],
    ) -> List[Vulnerability]:
        """Deserialize vulnerabilities from cache."""
        result = []
        
        for item in data:
            cvss = None
            if "cvss" in item:
                cvss = CVSSScore(
                    score=item["cvss"]["score"],
                    vector=item["cvss"].get("vector", ""),
                    version=item["cvss"].get("version", "3.1"),
                )
            
            published = None
            if "published" in item:
                try:
                    published = datetime.fromisoformat(item["published"])
                except ValueError:
                    pass
            
            modified = None
            if "modified" in item:
                try:
                    modified = datetime.fromisoformat(item["modified"])
                except ValueError:
                    pass
            
            references = [
                Reference(type=ref["type"], url=ref["url"])
                for ref in item.get("references", [])
            ]
            
            vuln = Vulnerability(
                id=item["id"],
                aliases=item.get("aliases", []),
                summary=item.get("summary", ""),
                details=item.get("details", ""),
                severity=Severity(item.get("severity", "unknown")),
                cvss=cvss,
                affected_versions=item.get("affected_versions", ""),
                fixed_versions=item.get("fixed_versions", []),
                published=published,
                modified=modified,
                references=references,
                cwe=item.get("cwe", []),
            )
            result.append(vuln)
        
        return result
    
    def clear(self) -> int:
        """Clear all cached entries. Returns number of entries cleared."""
        if not self.enabled or not self.cache_dir.exists():
            return 0
        
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except OSError:
                pass
        
        return count
    
    def clear_expired(self) -> int:
        """Clear only expired cache entries. Returns number cleared."""
        if not self.enabled or not self.cache_dir.exists():
            return 0
        
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(cache_file.read_text(encoding='utf-8'))
                entry = CacheEntry(**data)
                
                if entry.is_expired(self.ttl_hours):
                    cache_file.unlink()
                    count += 1
            except (json.JSONDecodeError, KeyError, TypeError, OSError):
                # Invalid or unreadable entry
                try:
                    cache_file.unlink()
                    count += 1
                except OSError:
                    pass
        
        return count
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.enabled or not self.cache_dir.exists():
            return {"enabled": False, "entries": 0, "size_bytes": 0}
        
        entries = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in entries if f.exists())
        
        return {
            "enabled": True,
            "entries": len(entries),
            "size_bytes": total_size,
            "cache_dir": str(self.cache_dir.absolute()),
            "ttl_hours": self.ttl_hours,
        }
