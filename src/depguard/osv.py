"""OSV API client for vulnerability data."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from depguard.models import (
    CVSSScore,
    Reference,
    Severity,
    Vulnerability,
)


OSV_API_URL = "https://api.osv.dev/v1"
DEFAULT_TIMEOUT = 30.0
DEFAULT_BATCH_SIZE = 100
DEFAULT_RATE_LIMIT = 100  # requests per minute


class OSVError(Exception):
    """Exception raised for OSV API errors."""
    pass


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, max_requests: int = DEFAULT_RATE_LIMIT, per_seconds: int = 60):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.requests: List[float] = []
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        now = time.time()
        
        # Remove old requests outside the window
        self.requests = [r for r in self.requests if now - r < self.per_seconds]
        
        if len(self.requests) >= self.max_requests:
            # Calculate wait time
            oldest = self.requests[0]
            wait_time = self.per_seconds - (now - oldest)
            if wait_time > 0:
                time.sleep(wait_time)
        
        self.requests.append(time.time())


class OSVClient:
    """Client for querying the OSV (Open Source Vulnerabilities) database."""
    
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit: int = DEFAULT_RATE_LIMIT,
    ):
        self.timeout = timeout
        self.rate_limiter = RateLimiter(max_requests=rate_limit)
        self._client: Optional[httpx.Client] = None
    
    def __enter__(self) -> "OSVClient":
        self._client = httpx.Client(timeout=self.timeout)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            self._client.close()
    
    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client
    
    def query_package(
        self,
        package: str,
        version: str,
        ecosystem: str = "PyPI",
    ) -> List[Vulnerability]:
        """Query vulnerabilities for a single package."""
        self.rate_limiter.wait_if_needed()
        
        url = f"{OSV_API_URL}/query"
        payload = {
            "package": {
                "name": package,
                "ecosystem": ecosystem,
            }
        }
        
        if version and version != "*":
            payload["version"] = version
        
        try:
            response = self.client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            
            return self._parse_vulnerabilities(data.get("vulns", []))
        
        except httpx.TimeoutException:
            # Handle timeout gracefully
            return []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return []  # No vulnerabilities found
            raise OSVError(f"OSV API error: {e}")
        except Exception as e:
            raise OSVError(f"Failed to query OSV: {e}")
    
    def query_batch(
        self,
        packages: List[Dict[str, str]],
        ecosystem: str = "PyPI",
    ) -> Dict[str, List[Vulnerability]]:
        """Query vulnerabilities for multiple packages in batch.
        
        Args:
            packages: List of dicts with 'name' and 'version' keys
            ecosystem: Package ecosystem (PyPI, npm, etc.)
        
        Returns:
            Dict mapping package names to their vulnerabilities
        """
        self.rate_limiter.wait_if_needed()
        
        url = f"{OSV_API_URL}/querybatch"
        
        # Build batch query
        queries = []
        for pkg in packages:
            query: Dict[str, Any] = {
                "package": {
                    "name": pkg["name"],
                    "ecosystem": ecosystem,
                }
            }
            version = pkg.get("version", "*")
            if version and version != "*":
                query["version"] = version
            queries.append(query)
        
        try:
            response = self.client.post(url, json={"queries": queries})
            response.raise_for_status()
            data = response.json()
            
            results: Dict[str, List[Vulnerability]] = {}
            
            for i, result in enumerate(data.get("results", [])):
                pkg_name = packages[i]["name"]
                vulns = self._parse_vulnerabilities(result.get("vulns", []))
                results[pkg_name] = vulns
            
            return results
        
        except httpx.TimeoutException:
            # Return empty results on timeout
            return {pkg["name"]: [] for pkg in packages}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {pkg["name"]: [] for pkg in packages}
            raise OSVError(f"OSV API batch error: {e}")
        except Exception as e:
            raise OSVError(f"Failed to query OSV batch: {e}")
    
    def _parse_vulnerabilities(self, vulns_data: List[Dict]) -> List[Vulnerability]:
        """Parse OSV vulnerability data into Vulnerability objects."""
        vulnerabilities = []
        
        for data in vulns_data:
            vuln = self._parse_single_vulnerability(data)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_single_vulnerability(self, data: Dict) -> Optional[Vulnerability]:
        """Parse a single vulnerability from OSV format."""
        vuln_id = data.get("id", "")
        if not vuln_id:
            return None
        
        # Parse aliases (CVE, GHSA, etc.)
        aliases = data.get("aliases", [])
        
        # Parse severity and CVSS
        severity = Severity.UNKNOWN
        cvss = None
        
        severity_data = data.get("severity", [])
        if severity_data:
            for sev in severity_data:
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        # Parse CVSS vector to get score
                        score = self._extract_cvss_score(score_str)
                        cvss = CVSSScore(score=score, vector=score_str)
                        severity = Severity.from_cvss(score)
                    except ValueError:
                        pass
                    break
        
        # If no CVSS, try database_specific severity
        if severity == Severity.UNKNOWN:
            db_specific = data.get("database_specific", {})
            sev_str = db_specific.get("severity", "").upper()
            if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = Severity(sev_str.lower())
        
        # Parse affected versions
        affected_str = ""
        fixed_versions = []
        
        for affected in data.get("affected", []):
            for range_data in affected.get("ranges", []):
                for event in range_data.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])
                    if "introduced" in event:
                        if affected_str:
                            affected_str += ", "
                        affected_str += f">= {event['introduced']}"
        
        # Parse references
        references = []
        for ref in data.get("references", []):
            references.append(Reference(
                type=ref.get("type", "WEB"),
                url=ref.get("url", "")
            ))
        
        # Parse dates
        published = None
        modified = None
        
        if "published" in data:
            try:
                published = datetime.fromisoformat(data["published"].replace("Z", "+00:00"))
            except ValueError:
                pass
        
        if "modified" in data:
            try:
                modified = datetime.fromisoformat(data["modified"].replace("Z", "+00:00"))
            except ValueError:
                pass
        
        return Vulnerability(
            id=vuln_id,
            aliases=aliases,
            summary=data.get("summary", ""),
            details=data.get("details", ""),
            severity=severity,
            cvss=cvss,
            affected_versions=affected_str,
            fixed_versions=fixed_versions,
            published=published,
            modified=modified,
            references=references,
            cwe=data.get("database_specific", {}).get("cwe_ids", []),
        )
    
    def _extract_cvss_score(self, vector: str) -> float:
        """Extract CVSS score from vector string.
        
        This is a simplified calculation. For accurate scores,
        use a proper CVSS calculator library.
        """
        if not vector:
            return 0.0
        
        # Simple heuristic based on attack vector and impact metrics
        score = 5.0  # Base score
        
        vector_upper = vector.upper()
        
        if "AV:N" in vector_upper:
            score += 2.0
        if "AC:L" in vector_upper:
            score += 1.0
        if "PR:N" in vector_upper:
            score += 1.0
        if "C:H" in vector_upper or "I:H" in vector_upper or "A:H" in vector_upper:
            score += 1.0
        
        return min(10.0, score)


def query_vulnerabilities(
    package: str,
    version: str,
    ecosystem: str = "PyPI",
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Vulnerability]:
    """Convenience function to query vulnerabilities for a package.
    
    Args:
        package: Package name
        version: Package version
        ecosystem: Package ecosystem (PyPI, npm, etc.)
        timeout: Request timeout in seconds
    
    Returns:
        List of vulnerabilities, or empty list if none found or error
    """
    with OSVClient(timeout=timeout) as client:
        return client.query_package(package, version, ecosystem)


def query_vulnerabilities_with_timeout(
    package: str,
    version: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[List[Vulnerability]]:
    """Query vulnerabilities with explicit timeout handling.
    
    Returns None on timeout, empty list if no vulnerabilities.
    """
    try:
        with OSVClient(timeout=timeout) as client:
            return client.query_package(package, version)
    except Exception:
        return None
