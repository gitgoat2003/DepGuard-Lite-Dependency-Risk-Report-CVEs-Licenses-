"""Tests for dependency parsers."""

import pytest
from pathlib import Path

from depguard.parse import (
    RequirementsParser,
    PyProjectParser,
    PoetryLockParser,
    PackageJsonParser,
    PackageLockParser,
    YarnLockParser,
    PipfileParser,
    parse_file,
    auto_detect_files,
    normalize_package_name,
    Dependency,
    ParserError,
)


# Fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestRequirementsParser:
    """Tests for requirements.txt parser."""
    
    def test_parse_simple_requirements(self):
        """Test parsing simple requirements with version specs."""
        content = """
requests==2.25.0
flask>=1.1.0
django~=3.0.0
numpy
"""
        parser = RequirementsParser()
        result = parser.parse(content)
        
        assert "requests" in result
        assert result["requests"].version == "2.25.0"
        assert result["requests"].version_spec == "=="
        
        assert "flask" in result
        assert result["flask"].version == "1.1.0"
        assert result["flask"].version_spec == ">="
        
        assert "django" in result
        assert "numpy" in result
    
    def test_parse_requirements_with_extras(self):
        """Test parsing requirements with extras."""
        content = "requests[security,socks]==2.25.0"
        parser = RequirementsParser()
        result = parser.parse(content)
        
        assert "requests" in result
        assert result["requests"].extras == ["security", "socks"]
    
    def test_parse_requirements_with_comments(self):
        """Test parsing requirements with comments."""
        content = """
# This is a comment
requests==2.25.0  # inline comment
# Another comment
flask>=1.0.0
"""
        parser = RequirementsParser()
        result = parser.parse(content)
        
        assert len(result) == 2
        assert "requests" in result
        assert "flask" in result
    
    def test_parse_requirements_txt_file(self):
        """Required Test #1: Correctly parses requirements.txt."""
        fixtures_path = FIXTURES_DIR / "requirements.txt"
        if fixtures_path.exists():
            result = parse_file(fixtures_path)
            
            assert "requests" in result
            assert result["requests"].version == "2.25.0"
            
            assert "flask" in result
            assert "django" in result
            assert "numpy" in result
            assert "pillow" in result
            assert "cryptography" in result


class TestPoetryLockParser:
    """Tests for poetry.lock parser."""
    
    def test_parse_poetry_lock(self):
        """Required Test #1: Correctly parses poetry.lock."""
        content = '''
[[package]]
name = "requests"
version = "2.28.0"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "2.0.1"
description = "A simple framework for building complex web applications."
'''
        parser = PoetryLockParser()
        result = parser.parse(content)
        
        assert len(result) > 0
        assert "requests" in result
        assert result["requests"].version == "2.28.0"
        assert result["requests"].version_spec == "=="
        
        assert "flask" in result
        assert result["flask"].version == "2.0.1"


class TestPyProjectParser:
    """Tests for pyproject.toml parser."""
    
    def test_parse_poetry_format(self):
        """Test parsing Poetry-style pyproject.toml."""
        content = '''
[tool.poetry]
name = "test-project"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"
flask = {version = "^2.0.0", optional = true}
'''
        parser = PyProjectParser()
        result = parser.parse(content)
        
        assert "requests" in result
        assert result["requests"].version == "2.28.0"
        
        assert "flask" in result
    
    def test_parse_pep621_format(self):
        """Test parsing PEP 621 style pyproject.toml."""
        content = '''
[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
    "flask~=2.0.0",
]
'''
        parser = PyProjectParser()
        result = parser.parse(content)
        
        assert "requests" in result
        assert "flask" in result


class TestPackageJsonParser:
    """Tests for package.json parser."""
    
    def test_parse_package_json(self):
        """Test parsing package.json with npm dependencies."""
        content = '''
{
    "name": "test-project",
    "version": "1.0.0",
    "dependencies": {
        "express": "^4.17.0",
        "lodash": "~4.17.15"
    },
    "devDependencies": {
        "jest": "^27.0.0"
    }
}
'''
        parser = PackageJsonParser()
        result = parser.parse(content)
        
        assert "express" in result
        assert result["express"].version == "4.17.0"
        assert result["express"].version_spec == "^"
        assert result["express"].ecosystem == "npm"
        
        assert "lodash" in result
        assert result["lodash"].version_spec == "~"
        
        assert "jest" in result


class TestNormalization:
    """Tests for package name normalization."""
    
    def test_normalize_package_name(self):
        """Test package name normalization per PEP 503."""
        assert normalize_package_name("Flask") == "flask"
        assert normalize_package_name("Django-REST-Framework") == "django-rest-framework"
        assert normalize_package_name("some_package") == "some-package"
        assert normalize_package_name("Some.Package") == "some-package"


class TestAutoDetection:
    """Tests for file auto-detection."""
    
    def test_auto_detect_files(self, tmp_path):
        """Test auto-detection of dependency files."""
        # Create test files
        (tmp_path / "requirements.txt").write_text("requests==2.0.0")
        (tmp_path / "package.json").write_text('{"dependencies": {}}')
        
        found = auto_detect_files(tmp_path)
        
        assert len(found) == 2
        filenames = [f.name for f in found]
        assert "requirements.txt" in filenames
        assert "package.json" in filenames


class TestParserErrors:
    """Tests for parser error handling."""
    
    def test_parse_invalid_toml(self):
        """Test handling of invalid TOML content."""
        parser = PyProjectParser()
        
        with pytest.raises(ParserError):
            parser.parse("invalid toml [ content")
    
    def test_parse_invalid_json(self):
        """Test handling of invalid JSON content."""
        parser = PackageJsonParser()
        
        with pytest.raises(ParserError):
            parser.parse("{ invalid json }")
    
    def test_parse_nonexistent_file(self):
        """Test handling of non-existent file."""
        with pytest.raises(ParserError):
            parse_file(Path("/nonexistent/path/requirements.txt"))


class TestVersionRanges:
    """Tests for version specification parsing."""
    
    def test_parse_complex_version_specs(self):
        """Test parsing complex version specifications."""
        content = """
package1>=1.0.0,<2.0.0
package2>=1.0.0,!=1.5.0
package3~=1.4.2
"""
        parser = RequirementsParser()
        result = parser.parse(content)
        
        assert "package1" in result
        assert "package2" in result
        assert "package3" in result
