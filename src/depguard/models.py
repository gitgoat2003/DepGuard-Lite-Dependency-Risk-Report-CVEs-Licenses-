"""Data models for DepGuard Lite."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.UNKNOWN
    
    @property
    def emoji(self) -> str:
        """Get emoji for severity level."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟡",
            Severity.MEDIUM: "🟠",
            Severity.LOW: "🟢",
            Severity.UNKNOWN: "⚪",
        }.get(self, "⚪")


class LicenseType(Enum):
    """License type categories."""
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    WEAK_COPYLEFT = "weak_copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class LicenseRisk(Enum):
    """License risk levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class CVSSScore:
    """CVSS score information."""
    score: float
    vector: str = ""
    version: str = "3.1"
    
    @property
    def severity(self) -> Severity:
        """Get severity from CVSS score."""
        return Severity.from_cvss(self.score)


@dataclass
class Reference:
    """Reference link for vulnerability."""
    type: str  # ADVISORY, FIX, WEB, ARTICLE
    url: str


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    id: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss: Optional[CVSSScore] = None
    affected_versions: str = ""
    fixed_versions: List[str] = field(default_factory=list)
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: List[Reference] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    
    @property
    def cve_id(self) -> Optional[str]:
        """Extract CVE ID from id or aliases."""
        if self.id.startswith("CVE-"):
            return self.id
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return None
    
    @property
    def ghsa_id(self) -> Optional[str]:
        """Extract GHSA ID from id or aliases."""
        if self.id.startswith("GHSA-"):
            return self.id
        for alias in self.aliases:
            if alias.startswith("GHSA-"):
                return alias
        return None


@dataclass
class License:
    """License information for a package."""
    name: str
    spdx_id: str = ""
    url: str = ""
    type: LicenseType = LicenseType.UNKNOWN
    risk: LicenseRisk = LicenseRisk.UNKNOWN
    requires_attribution: bool = False
    allows_commercial: bool = True
    allows_modification: bool = True
    allows_distribution: bool = True
    copyleft: bool = False
    patent_grant: bool = False
    
    @property
    def requires_review(self) -> bool:
        """Check if license requires legal review."""
        return self.type in (LicenseType.COPYLEFT, LicenseType.PROPRIETARY) or \
               self.risk in (LicenseRisk.HIGH, LicenseRisk.UNKNOWN)


@dataclass
class Package:
    """Represents an analyzed package."""
    name: str
    version: str
    ecosystem: str = "pypi"
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    license: Optional[License] = None
    
    @property
    def normalized_name(self) -> str:
        """Get normalized package name."""
        import re
        return re.sub(r"[-_.]+", "-", self.name).lower()
    
    @property
    def has_vulnerabilities(self) -> bool:
        """Check if package has any vulnerabilities."""
        return len(self.vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        """Count critical severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def max_severity(self) -> Severity:
        """Get maximum severity of all vulnerabilities."""
        if not self.vulnerabilities:
            return Severity.UNKNOWN
        
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for severity in severity_order:
            if any(v.severity == severity for v in self.vulnerabilities):
                return severity
        return Severity.UNKNOWN


@dataclass
class ScanResult:
    """Result of a dependency scan."""
    packages: List[Package] = field(default_factory=list)
    scan_date: datetime = field(default_factory=datetime.now)
    dependency_file: str = ""
    project_name: str = ""
    
    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return sum(len(p.vulnerabilities) for p in self.packages)
    
    @property
    def vulnerable_packages(self) -> int:
        """Number of packages with vulnerabilities."""
        return sum(1 for p in self.packages if p.has_vulnerabilities)
    
    def severity_breakdown(self) -> Dict[Severity, int]:
        """Get count of vulnerabilities by severity."""
        counts: Dict[Severity, int] = {s: 0 for s in Severity}
        for pkg in self.packages:
            for vuln in pkg.vulnerabilities:
                counts[vuln.severity] += 1
        return counts
    
    def license_breakdown(self) -> Dict[LicenseType, int]:
        """Get count of packages by license type."""
        counts: Dict[LicenseType, int] = {t: 0 for t in LicenseType}
        for pkg in self.packages:
            if pkg.license:
                counts[pkg.license.type] += 1
            else:
                counts[LicenseType.UNKNOWN] += 1
        return counts
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-10)."""
        if not self.packages:
            return 0.0
        
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.UNKNOWN: 2,
        }
        
        total_weight = 0
        for pkg in self.packages:
            for vuln in pkg.vulnerabilities:
                total_weight += severity_weights.get(vuln.severity, 0)
        
        # Normalize to 0-10 scale
        max_score = len(self.packages) * 10
        score = min(10, (total_weight / max(max_score, 1)) * 10)
        return round(score, 1)
