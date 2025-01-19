"""Tests for report generation."""

import json
import pytest
from datetime import datetime

from depguard.report import (
    MarkdownReportGenerator,
    JsonReportGenerator,
    HtmlReportGenerator,
    CsvReportGenerator,
    SarifReportGenerator,
    generate_report,
    format_for_pr_comment,
)
from depguard.models import (
    ScanResult,
    Package,
    Vulnerability,
    License,
    LicenseType,
    LicenseRisk,
    Severity,
    CVSSScore,
)


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result for testing."""
    vuln1 = Vulnerability(
        id="CVE-2023-12345",
        summary="Test critical vulnerability",
        severity=Severity.CRITICAL,
        cvss=CVSSScore(score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        fixed_versions=["2.31.0"],
    )
    
    vuln2 = Vulnerability(
        id="CVE-2023-67890",
        summary="Test high vulnerability",
        severity=Severity.HIGH,
        cvss=CVSSScore(score=7.5),
        fixed_versions=["1.5.0"],
    )
    
    pkg1 = Package(
        name="requests",
        version="2.25.0",
        ecosystem="pypi",
        vulnerabilities=[vuln1],
        license=License(
            name="Apache License 2.0",
            spdx_id="Apache-2.0",
            type=LicenseType.PERMISSIVE,
            risk=LicenseRisk.LOW,
        ),
    )
    
    pkg2 = Package(
        name="flask",
        version="1.0.0",
        ecosystem="pypi",
        vulnerabilities=[vuln2],
        license=License(
            name="BSD License",
            spdx_id="BSD-3-Clause",
            type=LicenseType.PERMISSIVE,
            risk=LicenseRisk.LOW,
        ),
    )
    
    pkg3 = Package(
        name="some-gpl-package",
        version="1.0.0",
        ecosystem="pypi",
        vulnerabilities=[],
        license=License(
            name="GPL-3.0",
            spdx_id="GPL-3.0",
            type=LicenseType.COPYLEFT,
            risk=LicenseRisk.HIGH,
            copyleft=True,
        ),
    )
    
    return ScanResult(
        packages=[pkg1, pkg2, pkg3],
        scan_date=datetime(2025, 1, 15, 10, 30, 0),
        dependency_file="requirements.txt",
        project_name="test-project",
    )


class TestMarkdownReportGenerator:
    """Tests for markdown report generation."""
    
    def test_generate_basic_report(self, sample_scan_result):
        """Test basic markdown report generation."""
        generator = MarkdownReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "# 🛡️ DepGuard Lite Security Report" in report
        assert "test-project" in report
        assert "requirements.txt" in report or "Dependencies Analyzed" in report
    
    def test_report_contains_vulnerabilities(self, sample_scan_result):
        """Test report contains vulnerability information."""
        generator = MarkdownReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "CVE-2023-12345" in report
        assert "Critical" in report or "CRITICAL" in report or "🔴" in report
    
    def test_report_contains_packages(self, sample_scan_result):
        """Test report contains package information."""
        generator = MarkdownReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "requests" in report
        assert "flask" in report
    
    def test_report_contains_license_info(self, sample_scan_result):
        """Test report contains license information."""
        generator = MarkdownReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "License" in report
    
    def test_report_with_collapsible_sections(self, sample_scan_result):
        """Test report with collapsible sections."""
        generator = MarkdownReportGenerator(collapsible_details=True)
        report = generator.generate(sample_scan_result)
        
        assert "<details>" in report
        assert "<summary>" in report
    
    def test_report_without_collapsible_sections(self, sample_scan_result):
        """Test report without collapsible sections."""
        generator = MarkdownReportGenerator(collapsible_details=False)
        report = generator.generate(sample_scan_result)
        
        # Should still generate valid report
        assert "DepGuard Lite" in report


class TestJsonReportGenerator:
    """Tests for JSON report generation."""
    
    def test_generate_valid_json(self, sample_scan_result):
        """Test JSON report is valid."""
        generator = JsonReportGenerator()
        report = generator.generate(sample_scan_result)
        
        # Should parse without error
        data = json.loads(report)
        assert "metadata" in data
        assert "summary" in data
        assert "vulnerabilities" in data
    
    def test_json_schema(self, sample_scan_result):
        """Test JSON report schema."""
        generator = JsonReportGenerator()
        report = generator.generate(sample_scan_result)
        data = json.loads(report)
        
        assert data["metadata"]["tool"] == "DepGuard Lite"
        assert "total_dependencies" in data["summary"]
        assert "severity_breakdown" in data["summary"]
    
    def test_json_contains_vulnerabilities(self, sample_scan_result):
        """Test JSON contains vulnerability data."""
        generator = JsonReportGenerator()
        report = generator.generate(sample_scan_result)
        data = json.loads(report)
        
        assert len(data["vulnerabilities"]) > 0
        assert data["vulnerabilities"][0]["package"] == "requests"


class TestHtmlReportGenerator:
    """Tests for HTML report generation."""
    
    def test_generate_valid_html(self, sample_scan_result):
        """Test HTML report structure."""
        generator = HtmlReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "<!DOCTYPE html>" in report
        assert "<html" in report
        assert "</html>" in report
        assert "DepGuard Lite" in report
    
    def test_html_has_styling(self, sample_scan_result):
        """Test HTML has CSS styling."""
        generator = HtmlReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "<style>" in report


class TestCsvReportGenerator:
    """Tests for CSV report generation."""
    
    def test_generate_valid_csv(self, sample_scan_result):
        """Test CSV report generation."""
        generator = CsvReportGenerator()
        report = generator.generate(sample_scan_result)
        
        lines = report.strip().split('\n')
        assert len(lines) > 1  # Header + data
        
        # Check header
        header = lines[0]
        assert "Package" in header
        assert "Vulnerability ID" in header
    
    def test_csv_contains_data(self, sample_scan_result):
        """Test CSV contains vulnerability data."""
        generator = CsvReportGenerator()
        report = generator.generate(sample_scan_result)
        
        assert "requests" in report
        assert "CVE-2023-12345" in report


class TestSarifReportGenerator:
    """Tests for SARIF report generation."""
    
    def test_generate_valid_sarif(self, sample_scan_result):
        """Test SARIF report is valid JSON."""
        generator = SarifReportGenerator()
        report = generator.generate(sample_scan_result)
        
        data = json.loads(report)
        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
    
    def test_sarif_has_rules(self, sample_scan_result):
        """Test SARIF contains rules."""
        generator = SarifReportGenerator()
        report = generator.generate(sample_scan_result)
        data = json.loads(report)
        
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0


class TestReportFactory:
    """Tests for report factory function."""
    
    def test_generate_markdown(self, sample_scan_result):
        """Test factory generates markdown."""
        report = generate_report(sample_scan_result, format="markdown")
        assert "# 🛡️ DepGuard Lite" in report
    
    def test_generate_json(self, sample_scan_result):
        """Test factory generates JSON."""
        report = generate_report(sample_scan_result, format="json")
        data = json.loads(report)
        assert "metadata" in data
    
    def test_generate_html(self, sample_scan_result):
        """Test factory generates HTML."""
        report = generate_report(sample_scan_result, format="html")
        assert "<!DOCTYPE html>" in report
    
    def test_unknown_format_raises(self, sample_scan_result):
        """Test unknown format raises error."""
        with pytest.raises(ValueError):
            generate_report(sample_scan_result, format="unknown")


class TestPRComment:
    """Tests for PR comment formatting."""
    
    def test_format_for_pr(self, sample_scan_result):
        """Test PR comment formatting."""
        comment = format_for_pr_comment(sample_scan_result)
        
        assert len(comment) <= 65000
        assert "DepGuard Lite" in comment
    
    def test_truncation(self, sample_scan_result):
        """Test very long reports are truncated."""
        # This would need a very large scan result to trigger
        comment = format_for_pr_comment(sample_scan_result, max_length=1000)
        
        assert len(comment) <= 1000


class TestEmptyResult:
    """Tests for empty scan results."""
    
    def test_empty_packages(self):
        """Test report with no packages."""
        result = ScanResult(
            packages=[],
            scan_date=datetime.now(),
            project_name="empty-project",
        )
        
        generator = MarkdownReportGenerator()
        report = generator.generate(result)
        
        assert "DepGuard Lite" in report
        assert "0" in report or "empty" in report.lower()
    
    def test_no_vulnerabilities(self):
        """Test report with packages but no vulnerabilities."""
        pkg = Package(
            name="safe-package",
            version="1.0.0",
            vulnerabilities=[],
        )
        
        result = ScanResult(
            packages=[pkg],
            scan_date=datetime.now(),
            project_name="safe-project",
        )
        
        generator = MarkdownReportGenerator()
        report = generator.generate(result)
        
        assert "DepGuard Lite" in report
