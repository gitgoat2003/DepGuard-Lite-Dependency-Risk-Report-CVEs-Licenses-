"""Tests for license analysis."""

import pytest

from depguard.license import (
    LicenseInfo,
    LicenseType,
    LicenseRisk,
    LICENSE_DATABASE,
    normalize_license_name,
    get_license_info,
    analyze_license,
    analyze_licenses,
    LicensePolicy,
    check_license_compatibility,
    get_license_statistics,
    get_alternatives,
)


class TestLicenseDatabase:
    """Tests for license database."""
    
    def test_common_licenses_present(self):
        """Test that common licenses are in database."""
        common = ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0", "LGPL-3.0"]
        
        for lic in common:
            assert lic in LICENSE_DATABASE
    
    def test_license_info_structure(self):
        """Test license info has required fields."""
        mit = LICENSE_DATABASE["MIT"]
        
        assert mit.name == "MIT License"
        assert mit.spdx_id == "MIT"
        assert mit.type == LicenseType.PERMISSIVE
        assert mit.risk == LicenseRisk.LOW
        assert mit.requires_attribution is True


class TestLicenseNormalization:
    """Tests for license name normalization."""
    
    def test_normalize_known_license(self):
        """Test normalization of known licenses."""
        assert normalize_license_name("MIT") == "MIT"
        assert normalize_license_name("Apache-2.0") == "Apache-2.0"
    
    def test_normalize_aliases(self):
        """Test normalization of license aliases."""
        assert normalize_license_name("Apache 2.0") == "Apache-2.0"
        assert normalize_license_name("Apache License 2.0") == "Apache-2.0"
        assert normalize_license_name("GPLv3") == "GPL-3.0"
        assert normalize_license_name("GPL v3") == "GPL-3.0"
    
    def test_normalize_case_insensitive(self):
        """Test case-insensitive normalization."""
        assert normalize_license_name("mit") == "MIT"
        assert normalize_license_name("APACHE-2.0") == "Apache-2.0"


class TestGPLFlagging:
    """Tests for GPL license flagging - Required Test #3."""
    
    def test_flag_gpl_license(self):
        """Required Test #3: Verify GPL dependencies flagged for review."""
        licenses = {
            "GPL-3.0": {"type": "copyleft", "requires_review": True}
        }
        
        result = analyze_licenses(licenses)
        
        assert result["GPL-3.0"]["flag"] == "review_needed"
        assert result["GPL-3.0"]["risk_level"] == "high"
    
    def test_flag_gpl2_license(self):
        """Test GPL-2.0 is flagged for review."""
        result = analyze_license("GPL-2.0")
        
        assert result["flag"] == "review_needed"
        assert result["risk_level"] == "high"
        assert result["requires_review"] is True
    
    def test_flag_agpl_license(self):
        """Test AGPL-3.0 is flagged for review."""
        result = analyze_license("AGPL-3.0")
        
        assert result["flag"] == "review_needed"
        assert result["risk_level"] == "high"
    
    def test_permissive_license_no_flag(self):
        """Required Test #3: Permissive licenses not flagged."""
        licenses = {
            "MIT": {"type": "permissive"}
        }
        
        result = analyze_licenses(licenses)
        
        assert result["MIT"]["flag"] is None
        assert result["MIT"]["risk_level"] == "low"
    
    def test_apache_license_no_flag(self):
        """Test Apache-2.0 is not flagged."""
        result = analyze_license("Apache-2.0")
        
        assert result["flag"] is None
        assert result["risk_level"] == "low"
        assert result["requires_review"] is False
    
    def test_bsd_license_no_flag(self):
        """Test BSD licenses are not flagged."""
        for lic in ["BSD-2-Clause", "BSD-3-Clause"]:
            result = analyze_license(lic)
            assert result["flag"] is None
            assert result["risk_level"] == "low"


class TestLicenseRiskScoring:
    """Tests for license risk scoring."""
    
    def test_permissive_low_risk(self):
        """Test permissive licenses have low risk."""
        permissive = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
        
        for lic in permissive:
            info = get_license_info(lic)
            assert info.risk == LicenseRisk.LOW
    
    def test_copyleft_high_risk(self):
        """Test strong copyleft licenses have high risk."""
        copyleft = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]
        
        for lic in copyleft:
            info = get_license_info(lic)
            assert info.risk == LicenseRisk.HIGH
    
    def test_weak_copyleft_medium_risk(self):
        """Test weak copyleft licenses have medium risk."""
        weak = ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"]
        
        for lic in weak:
            info = get_license_info(lic)
            assert info.risk == LicenseRisk.MEDIUM


class TestLicensePolicy:
    """Tests for license policy enforcement."""
    
    def test_default_policy(self):
        """Test default policy settings."""
        policy = LicensePolicy.default()
        
        assert policy.check("MIT") == "allowed"
        assert policy.check("Apache-2.0") == "allowed"
        assert policy.check("GPL-3.0") == "review_required"
        assert policy.check("SSPL-1.0") == "forbidden"
    
    def test_custom_policy(self):
        """Test custom policy."""
        policy = LicensePolicy(
            allowed=["MIT"],
            review_required=["Apache-2.0"],
            forbidden=["GPL-3.0"],
        )
        
        assert policy.check("MIT") == "allowed"
        assert policy.check("Apache-2.0") == "review_required"
        assert policy.check("GPL-3.0") == "forbidden"
        assert policy.check("Unknown-License") == "unknown"


class TestLicenseCompatibility:
    """Tests for license compatibility checking."""
    
    def test_permissive_compatible(self):
        """Test permissive licenses are compatible."""
        result = check_license_compatibility(["MIT", "Apache-2.0", "BSD-3-Clause"])
        
        assert result["compatible"] is True
        assert len(result["issues"]) == 0
    
    def test_gpl2_apache_incompatible(self):
        """Test GPL-2.0 and Apache-2.0 incompatibility."""
        result = check_license_compatibility(["GPL-2.0", "Apache-2.0"])
        
        assert result["compatible"] is False
        assert len(result["issues"]) > 0
        assert any("incompatible" in issue["type"] for issue in result["issues"])
    
    def test_multiple_copyleft_flagged(self):
        """Test multiple copyleft licenses are flagged."""
        result = check_license_compatibility(["GPL-2.0", "GPL-3.0"])
        
        assert result["requires_review"] is True


class TestLicenseStatistics:
    """Tests for license statistics."""
    
    def test_get_statistics(self):
        """Test license distribution statistics."""
        packages = [
            {"name": "pkg1", "license": "MIT"},
            {"name": "pkg2", "license": "Apache-2.0"},
            {"name": "pkg3", "license": "GPL-3.0"},
            {"name": "pkg4", "license": "Unknown"},
        ]
        
        stats = get_license_statistics(packages)
        
        assert stats["permissive"] == 2
        assert stats["copyleft"] == 1
        assert stats["unknown"] == 1


class TestUnknownLicenses:
    """Tests for unknown license handling."""
    
    def test_unknown_license(self):
        """Test handling of unknown license."""
        info = get_license_info("SomeUnknownLicense")
        
        assert info.type == LicenseType.UNKNOWN
        assert info.risk == LicenseRisk.UNKNOWN
        assert info.requires_review is True
    
    def test_analyze_unknown_license(self):
        """Test analyzing unknown license."""
        result = analyze_license("SomeUnknownLicense")
        
        assert result["flag"] == "unknown"
        assert result["requires_review"] is True


class TestLicenseProperties:
    """Tests for license property detection."""
    
    def test_copyleft_property(self):
        """Test copyleft property detection."""
        gpl = get_license_info("GPL-3.0")
        assert gpl.copyleft is True
        
        mit = get_license_info("MIT")
        assert mit.copyleft is False
    
    def test_patent_grant(self):
        """Test patent grant detection."""
        apache = get_license_info("Apache-2.0")
        assert apache.patent_grant is True
        
        mit = get_license_info("MIT")
        assert mit.patent_grant is False
    
    def test_network_copyleft(self):
        """Test network copyleft detection."""
        agpl = get_license_info("AGPL-3.0")
        assert agpl.network_copyleft is True
        
        gpl = get_license_info("GPL-3.0")
        assert gpl.network_copyleft is False
