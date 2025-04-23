"""License analysis and detection module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class LicenseType(Enum):
    """License type categories."""
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    WEAK_COPYLEFT = "weak_copyleft"
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public_domain"
    UNKNOWN = "unknown"


class LicenseRisk(Enum):
    """License risk levels for commercial/proprietary use."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class LicenseInfo:
    """Information about a software license."""
    name: str
    spdx_id: str
    type: LicenseType
    risk: LicenseRisk
    url: str = ""
    
    # License characteristics
    requires_attribution: bool = False
    allows_commercial: bool = True
    allows_modification: bool = True
    allows_distribution: bool = True
    copyleft: bool = False
    patent_grant: bool = False
    network_copyleft: bool = False  # For AGPL-style licenses
    
    # Additional flags
    flags: List[str] = field(default_factory=list)
    implications: List[str] = field(default_factory=list)
    
    @property
    def requires_review(self) -> bool:
        """Check if license requires legal review."""
        return (
            self.type in (LicenseType.COPYLEFT, LicenseType.PROPRIETARY) or
            self.risk == LicenseRisk.HIGH or
            self.copyleft or
            self.network_copyleft
        )


# License database with SPDX identifiers
LICENSE_DATABASE: Dict[str, LicenseInfo] = {
    # Permissive licenses
    "MIT": LicenseInfo(
        name="MIT License",
        spdx_id="MIT",
        type=LicenseType.PERMISSIVE,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/MIT",
        requires_attribution=True,
        allows_commercial=True,
        allows_modification=True,
        allows_distribution=True,
    ),
    "Apache-2.0": LicenseInfo(
        name="Apache License 2.0",
        spdx_id="Apache-2.0",
        type=LicenseType.PERMISSIVE,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/Apache-2.0",
        requires_attribution=True,
        allows_commercial=True,
        allows_modification=True,
        allows_distribution=True,
        patent_grant=True,
    ),
    "BSD-2-Clause": LicenseInfo(
        name="BSD 2-Clause License",
        spdx_id="BSD-2-Clause",
        type=LicenseType.PERMISSIVE,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/BSD-2-Clause",
        requires_attribution=True,
    ),
    "BSD-3-Clause": LicenseInfo(
        name="BSD 3-Clause License",
        spdx_id="BSD-3-Clause",
        type=LicenseType.PERMISSIVE,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/BSD-3-Clause",
        requires_attribution=True,
    ),
    "ISC": LicenseInfo(
        name="ISC License",
        spdx_id="ISC",
        type=LicenseType.PERMISSIVE,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/ISC",
        requires_attribution=True,
    ),
    "Unlicense": LicenseInfo(
        name="The Unlicense",
        spdx_id="Unlicense",
        type=LicenseType.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        url="https://unlicense.org/",
    ),
    "CC0-1.0": LicenseInfo(
        name="Creative Commons Zero v1.0",
        spdx_id="CC0-1.0",
        type=LicenseType.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        url="https://creativecommons.org/publicdomain/zero/1.0/",
    ),
    "0BSD": LicenseInfo(
        name="Zero-Clause BSD",
        spdx_id="0BSD",
        type=LicenseType.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        url="https://opensource.org/licenses/0BSD",
    ),
    
    # Weak copyleft licenses
    "LGPL-2.1": LicenseInfo(
        name="GNU Lesser General Public License v2.1",
        spdx_id="LGPL-2.1-only",
        type=LicenseType.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        url="https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html",
        requires_attribution=True,
        copyleft=True,
        flags=["weak_copyleft"],
        implications=[
            "Modifications to the library must use the same license",
            "Can be used in proprietary software if dynamically linked",
        ],
    ),
    "LGPL-3.0": LicenseInfo(
        name="GNU Lesser General Public License v3.0",
        spdx_id="LGPL-3.0-only",
        type=LicenseType.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        url="https://www.gnu.org/licenses/lgpl-3.0.html",
        requires_attribution=True,
        copyleft=True,
        patent_grant=True,
        flags=["weak_copyleft"],
        implications=[
            "Modifications to the library must use the same license",
            "Can be used in proprietary software if dynamically linked",
        ],
    ),
    "MPL-2.0": LicenseInfo(
        name="Mozilla Public License 2.0",
        spdx_id="MPL-2.0",
        type=LicenseType.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        url="https://opensource.org/licenses/MPL-2.0",
        requires_attribution=True,
        copyleft=True,
        patent_grant=True,
        flags=["file_level_copyleft"],
        implications=[
            "Modifications to MPL-licensed files must use the same license",
            "Can combine with proprietary code in separate files",
        ],
    ),
    
    # Strong copyleft licenses
    "GPL-2.0": LicenseInfo(
        name="GNU General Public License v2.0",
        spdx_id="GPL-2.0-only",
        type=LicenseType.COPYLEFT,
        risk=LicenseRisk.HIGH,
        url="https://www.gnu.org/licenses/old-licenses/gpl-2.0.html",
        requires_attribution=True,
        copyleft=True,
        flags=["copyleft", "viral", "requires_source_disclosure"],
        implications=[
            "Derivative works must use GPL-2.0",
            "Source code disclosure required",
            "Incompatible with proprietary software",
        ],
    ),
    "GPL-3.0": LicenseInfo(
        name="GNU General Public License v3.0",
        spdx_id="GPL-3.0-only",
        type=LicenseType.COPYLEFT,
        risk=LicenseRisk.HIGH,
        url="https://www.gnu.org/licenses/gpl-3.0.html",
        requires_attribution=True,
        copyleft=True,
        patent_grant=True,
        flags=["copyleft", "viral", "requires_source_disclosure"],
        implications=[
            "Derivative works must use GPL-3.0",
            "Source code disclosure required",
            "Patent grant requirements",
            "Incompatible with proprietary software",
        ],
    ),
    "AGPL-3.0": LicenseInfo(
        name="GNU Affero General Public License v3.0",
        spdx_id="AGPL-3.0-only",
        type=LicenseType.COPYLEFT,
        risk=LicenseRisk.HIGH,
        url="https://www.gnu.org/licenses/agpl-3.0.html",
        requires_attribution=True,
        copyleft=True,
        network_copyleft=True,
        patent_grant=True,
        flags=["copyleft", "viral", "network_copyleft", "requires_source_disclosure"],
        implications=[
            "Derivative works must use AGPL-3.0",
            "Source code disclosure required even for network use",
            "Most restrictive open source license",
            "Incompatible with proprietary software",
        ],
    ),
    
    # Proprietary/restrictive
    "SSPL-1.0": LicenseInfo(
        name="Server Side Public License v1.0",
        spdx_id="SSPL-1.0",
        type=LicenseType.PROPRIETARY,
        risk=LicenseRisk.HIGH,
        url="https://www.mongodb.com/licensing/server-side-public-license",
        copyleft=True,
        network_copyleft=True,
        flags=["not_osi_approved", "restrictive"],
        implications=[
            "Not OSI approved",
            "Requires open-sourcing entire service stack",
            "Effectively prohibits commercial cloud hosting",
        ],
    ),
    "BSL-1.1": LicenseInfo(
        name="Business Source License 1.1",
        spdx_id="BSL-1.1",
        type=LicenseType.PROPRIETARY,
        risk=LicenseRisk.HIGH,
        url="https://mariadb.com/bsl11/",
        flags=["not_osi_approved", "time_limited"],
        implications=[
            "Not OSI approved open source",
            "Production use may require license",
            "Converts to open source after change date",
        ],
    ),
}

# Aliases for common license name variations
LICENSE_ALIASES: Dict[str, str] = {
    "Apache License 2.0": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "Apache-2": "Apache-2.0",
    "Apache": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "BSD-2": "BSD-2-Clause",
    "BSD-3": "BSD-3-Clause",
    "BSD 2-Clause": "BSD-2-Clause",
    "BSD 3-Clause": "BSD-3-Clause",
    "GPL-2": "GPL-2.0",
    "GPL-3": "GPL-3.0",
    "GPLv2": "GPL-2.0",
    "GPLv3": "GPL-3.0",
    "GPL v2": "GPL-2.0",
    "GPL v3": "GPL-3.0",
    "GPL2": "GPL-2.0",
    "GPL3": "GPL-3.0",
    "LGPL-2": "LGPL-2.1",
    "LGPL-3": "LGPL-3.0",
    "LGPLv2": "LGPL-2.1",
    "LGPLv3": "LGPL-3.0",
    "AGPL-3": "AGPL-3.0",
    "AGPLv3": "AGPL-3.0",
    "MPL": "MPL-2.0",
    "MPL2": "MPL-2.0",
    "MPL 2.0": "MPL-2.0",
    "Public Domain": "Unlicense",
    "CC0": "CC0-1.0",
    "WTFPL": "Unlicense",  # Treat as public domain equivalent
}


def normalize_license_name(name: str) -> str:
    """Normalize a license name to its SPDX identifier."""
    if not name:
        return ""
    
    # Check if it's already a known SPDX ID
    if name in LICENSE_DATABASE:
        return name
    
    # Check aliases
    if name in LICENSE_ALIASES:
        return LICENSE_ALIASES[name]
    
    # Try case-insensitive match
    name_upper = name.upper().strip()
    for spdx_id in LICENSE_DATABASE:
        if spdx_id.upper() == name_upper:
            return spdx_id
    
    for alias, spdx_id in LICENSE_ALIASES.items():
        if alias.upper() == name_upper:
            return spdx_id
    
    # Check for partial matches
    for spdx_id in LICENSE_DATABASE:
        if spdx_id.upper() in name_upper or name_upper in spdx_id.upper():
            return spdx_id
    
    return name  # Return original if not found


def get_license_info(name: str) -> LicenseInfo:
    """Get license information by name or SPDX ID."""
    normalized = normalize_license_name(name)
    
    if normalized in LICENSE_DATABASE:
        return LICENSE_DATABASE[normalized]
    
    # Return unknown license
    return LicenseInfo(
        name=name,
        spdx_id="",
        type=LicenseType.UNKNOWN,
        risk=LicenseRisk.UNKNOWN,
        flags=["unknown"],
        implications=["License not recognized, manual review required"],
    )


@dataclass
class LicenseAnalysisResult:
    """Result of license analysis for packages."""
    package: str
    version: str
    license_name: str
    license_info: LicenseInfo
    flag: Optional[str] = None
    risk_level: str = "unknown"
    alternatives: List[str] = field(default_factory=list)


def analyze_license(license_name: str) -> Dict[str, Any]:
    """Analyze a license and return risk assessment.
    
    This is the main function for testing GPL license flagging.
    """
    info = get_license_info(license_name)
    
    result: Dict[str, Any] = {
        "name": info.name,
        "spdx_id": info.spdx_id,
        "type": info.type.value,
        "risk_level": info.risk.value,
        "flag": None,
        "requires_review": info.requires_review,
        "implications": info.implications,
    }
    
    # Flag copyleft licenses for review
    if info.copyleft or info.type == LicenseType.COPYLEFT:
        result["flag"] = "review_needed"
    
    # Flag unknown licenses
    if info.type == LicenseType.UNKNOWN:
        result["flag"] = "unknown"
    
    return result


def analyze_licenses(licenses: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Analyze multiple licenses and return assessments.
    
    Args:
        licenses: Dict mapping license names to their metadata
    
    Returns:
        Dict with analysis results for each license
    """
    results = {}
    
    for license_name, metadata in licenses.items():
        info = get_license_info(license_name)
        
        result = {
            "name": info.name,
            "spdx_id": info.spdx_id,
            "type": info.type.value,
            "risk_level": info.risk.value,
            "flag": None,
            "requires_review": info.requires_review,
        }
        
        # Set flag based on license type
        if info.copyleft or info.type == LicenseType.COPYLEFT:
            result["flag"] = "review_needed"
        elif info.type == LicenseType.UNKNOWN:
            result["flag"] = "unknown"
        elif info.type == LicenseType.PROPRIETARY:
            result["flag"] = "proprietary"
        
        results[license_name] = result
    
    return results


class LicensePolicy:
    """Policy for license compatibility checking."""
    
    def __init__(
        self,
        allowed: Optional[List[str]] = None,
        review_required: Optional[List[str]] = None,
        forbidden: Optional[List[str]] = None,
    ):
        self.allowed = set(allowed or [])
        self.review_required = set(review_required or [])
        self.forbidden = set(forbidden or [])
    
    @classmethod
    def default(cls) -> "LicensePolicy":
        """Create default license policy."""
        return cls(
            allowed=[
                "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
                "ISC", "Unlicense", "CC0-1.0", "0BSD",
            ],
            review_required=[
                "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
                "AGPL-3.0", "MPL-2.0",
            ],
            forbidden=[
                "SSPL-1.0",
            ],
        )
    
    def check(self, license_name: str) -> str:
        """Check license against policy.
        
        Returns: "allowed", "review_required", "forbidden", or "unknown"
        """
        normalized = normalize_license_name(license_name)
        
        if normalized in self.forbidden:
            return "forbidden"
        if normalized in self.review_required:
            return "review_required"
        if normalized in self.allowed:
            return "allowed"
        
        return "unknown"


def check_license_compatibility(
    licenses: List[str],
) -> Dict[str, Any]:
    """Check compatibility between multiple licenses.
    
    Returns compatibility analysis for the license combination.
    """
    normalized = [normalize_license_name(lic) for lic in licenses]
    
    # Check for copyleft conflicts
    has_gpl2 = "GPL-2.0" in normalized
    has_gpl3 = "GPL-3.0" in normalized
    has_agpl = "AGPL-3.0" in normalized
    has_apache = "Apache-2.0" in normalized
    
    issues = []
    
    # GPL-2.0 and Apache-2.0 are incompatible
    if has_gpl2 and has_apache:
        issues.append({
            "type": "incompatible",
            "licenses": ["GPL-2.0", "Apache-2.0"],
            "reason": "GPL-2.0 and Apache-2.0 have incompatible patent clauses",
        })
    
    # Multiple copyleft licenses
    copyleft_licenses = [lic for lic in normalized 
                         if lic in ("GPL-2.0", "GPL-3.0", "AGPL-3.0")]
    if len(copyleft_licenses) > 1:
        issues.append({
            "type": "multiple_copyleft",
            "licenses": copyleft_licenses,
            "reason": "Multiple copyleft licenses may have compatibility issues",
        })
    
    return {
        "compatible": len(issues) == 0,
        "issues": issues,
        "requires_review": has_gpl2 or has_gpl3 or has_agpl,
    }


def get_license_statistics(packages: List[Dict[str, str]]) -> Dict[str, int]:
    """Get license distribution statistics.
    
    Args:
        packages: List of dicts with 'name' and 'license' keys
    
    Returns:
        Dict with counts by license type
    """
    stats: Dict[str, int] = {
        "permissive": 0,
        "copyleft": 0,
        "weak_copyleft": 0,
        "proprietary": 0,
        "public_domain": 0,
        "unknown": 0,
    }
    
    for pkg in packages:
        license_name = pkg.get("license", "")
        info = get_license_info(license_name)
        stats[info.type.value] += 1
    
    return stats


# Suggested alternatives for copyleft packages
ALTERNATIVES: Dict[str, List[str]] = {
    "some-gpl-package": ["alternative-package", "another-option"],
    # Add more known alternatives here
}


def get_alternatives(package_name: str) -> List[str]:
    """Get suggested alternative packages with permissive licenses."""
    return ALTERNATIVES.get(package_name.lower(), [])
