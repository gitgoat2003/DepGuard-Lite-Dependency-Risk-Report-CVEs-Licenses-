"""Tests for OSV API client."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from depguard.osv import (
    OSVClient,
    OSVError,
    RateLimiter,
    query_vulnerabilities,
    query_vulnerabilities_with_timeout,
)
from depguard.models import Severity, Vulnerability


class TestRateLimiter:
    """Tests for rate limiter."""
    
    def test_rate_limiter_allows_requests(self):
        """Test that rate limiter allows requests within limit."""
        limiter = RateLimiter(max_requests=10, per_seconds=1)
        
        # Should not raise or block significantly
        for _ in range(5):
            limiter.wait_if_needed()


class TestOSVClient:
    """Tests for OSV API client."""
    
    def test_client_context_manager(self):
        """Test client context manager."""
        with OSVClient() as client:
            assert client._client is not None
    
    @patch('depguard.osv.httpx.Client')
    def test_query_package_success(self, mock_client_class):
        """Test successful vulnerability query."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "CVE-2023-12345",
                    "summary": "Test vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                }
            ]
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        with OSVClient() as client:
            client._client = mock_client
            result = client.query_package("requests", "2.25.0")
        
        assert len(result) == 1
        assert result[0].id == "CVE-2023-12345"
    
    @patch('depguard.osv.httpx.Client')
    def test_osv_empty_result(self, mock_client_class):
        """Required Test #2: Handles OSV API empty result gracefully."""
        mock_response = Mock()
        mock_response.json.return_value = {"vulns": []}
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        with OSVClient() as client:
            client._client = mock_client
            result = client.query_package("safe-package", "1.0.0")
        
        # Should return empty list, not crash
        assert result == []
        assert not result  # Empty list is falsy
    
    @patch('depguard.osv.httpx.Client')
    def test_osv_no_vulnerabilities(self, mock_client_class):
        """Test handling package with no known vulnerabilities."""
        mock_response = Mock()
        mock_response.json.return_value = {}  # No vulns key
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        with OSVClient() as client:
            client._client = mock_client
            result = client.query_package("unknown-package", "1.0.0")
        
        assert result == []


class TestOSVTimeout:
    """Tests for OSV API timeout handling."""
    
    @patch('depguard.osv.httpx.Client')
    def test_osv_api_timeout(self, mock_client_class):
        """Required Test #2: Handles timeout gracefully."""
        import httpx
        
        mock_client = Mock()
        mock_client.post.side_effect = httpx.TimeoutException("Connection timed out")
        mock_client_class.return_value = mock_client
        
        # Should handle timeout gracefully, not crash
        result = query_vulnerabilities_with_timeout("package", "1.0.0", timeout=0.001)
        
        # Returns None or empty list on timeout
        assert result is None or result == []
    
    @patch('depguard.osv.httpx.Client')
    def test_osv_connection_error(self, mock_client_class):
        """Test handling of connection errors."""
        import httpx
        
        mock_client = Mock()
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")
        mock_client_class.return_value = mock_client
        
        result = query_vulnerabilities_with_timeout("package", "1.0.0")
        
        # Should not crash
        assert result is None or result == []


class TestVulnerabilityParsing:
    """Tests for vulnerability data parsing."""
    
    def test_parse_cve_id(self):
        """Test CVE ID extraction."""
        vuln = Vulnerability(
            id="GHSA-1234-5678-abcd",
            aliases=["CVE-2023-12345", "PYSEC-2023-123"]
        )
        
        assert vuln.cve_id == "CVE-2023-12345"
        assert vuln.ghsa_id == "GHSA-1234-5678-abcd"
    
    def test_parse_cve_id_primary(self):
        """Test when CVE is primary ID."""
        vuln = Vulnerability(
            id="CVE-2023-12345",
            aliases=["GHSA-1234-5678-abcd"]
        )
        
        assert vuln.cve_id == "CVE-2023-12345"
        assert vuln.ghsa_id == "GHSA-1234-5678-abcd"
    
    def test_severity_from_cvss(self):
        """Test severity calculation from CVSS score."""
        assert Severity.from_cvss(9.8) == Severity.CRITICAL
        assert Severity.from_cvss(7.5) == Severity.HIGH
        assert Severity.from_cvss(5.0) == Severity.MEDIUM
        assert Severity.from_cvss(2.0) == Severity.LOW
        assert Severity.from_cvss(0.0) == Severity.UNKNOWN


class TestBatchQuery:
    """Tests for batch vulnerability queries."""
    
    @patch('depguard.osv.httpx.Client')
    def test_batch_query_success(self, mock_client_class):
        """Test successful batch query."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "results": [
                {"vulns": [{"id": "CVE-2023-1", "summary": "Vuln 1"}]},
                {"vulns": []},
            ]
        }
        mock_response.raise_for_status = Mock()
        
        mock_client = Mock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        with OSVClient() as client:
            client._client = mock_client
            result = client.query_batch([
                {"name": "requests", "version": "2.25.0"},
                {"name": "flask", "version": "1.0.0"},
            ])
        
        assert "requests" in result
        assert len(result["requests"]) == 1
        assert "flask" in result
        assert result["flask"] == []
    
    @patch('depguard.osv.httpx.Client')
    def test_batch_query_timeout(self, mock_client_class):
        """Test batch query timeout handling."""
        import httpx
        
        mock_client = Mock()
        mock_client.post.side_effect = httpx.TimeoutException("Timeout")
        mock_client_class.return_value = mock_client
        
        with OSVClient() as client:
            client._client = mock_client
            result = client.query_batch([
                {"name": "package1", "version": "1.0.0"},
                {"name": "package2", "version": "2.0.0"},
            ])
        
        # Should return empty results, not crash
        assert result["package1"] == []
        assert result["package2"] == []
