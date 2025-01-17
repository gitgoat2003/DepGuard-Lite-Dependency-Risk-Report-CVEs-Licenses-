"""Dependency file parsers for multiple package formats."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any


@dataclass
class Dependency:
    """Represents a parsed dependency."""
    name: str
    version: str
    version_spec: str = ""  # e.g., ">=", "==", "^"
    extras: List[str] = field(default_factory=list)
    ecosystem: str = "pypi"  # pypi, npm, etc.
    
    @property
    def normalized_name(self) -> str:
        """Normalize package name for consistency."""
        return normalize_package_name(self.name)


def normalize_package_name(name: str) -> str:
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


class ParserError(Exception):
    """Exception raised when parsing fails."""
    pass


class RequirementsParser:
    """Parser for requirements.txt files."""
    
    VERSION_PATTERN = re.compile(
        r'^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)\s*([<>=!~]+)?\s*([0-9a-zA-Z.*,<>=!~\s]+)?'
    )
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse requirements.txt content."""
        dependencies = {}
        
        for line in content.strip().split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Remove inline comments
            if '#' in line:
                line = line.split('#')[0].strip()
            
            dep = self._parse_line(line)
            if dep:
                dependencies[dep.normalized_name] = dep
        
        return dependencies
    
    def _parse_line(self, line: str) -> Optional[Dependency]:
        """Parse a single requirement line."""
        # Handle extras like requests[security]
        match = self.VERSION_PATTERN.match(line)
        if not match:
            return None
        
        name = match.group(1)
        extras = []
        
        # Extract extras
        if '[' in name:
            base_name, extras_str = name.split('[', 1)
            extras_str = extras_str.rstrip(']')
            extras = [e.strip() for e in extras_str.split(',')]
            name = base_name
        
        version_spec = match.group(2) or ""
        version = match.group(3) or "*"
        
        # Clean up version
        version = version.strip()
        if ',' in version:
            # Multiple version specs, take the first
            version = version.split(',')[0].strip()
        
        return Dependency(
            name=name,
            version=version,
            version_spec=version_spec,
            extras=extras,
            ecosystem="pypi"
        )


class PyProjectParser:
    """Parser for pyproject.toml files (PEP 621 and Poetry)."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse pyproject.toml content."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        dependencies = {}
        
        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ParserError(f"Failed to parse TOML: {e}")
        
        # PEP 621 format
        if 'project' in data and 'dependencies' in data['project']:
            for dep_str in data['project']['dependencies']:
                dep = self._parse_pep_dependency(dep_str)
                if dep:
                    dependencies[dep.normalized_name] = dep
        
        # Poetry format
        if 'tool' in data and 'poetry' in data['tool']:
            poetry = data['tool']['poetry']
            
            for section in ['dependencies', 'dev-dependencies']:
                if section in poetry:
                    for name, version_info in poetry[section].items():
                        if name.lower() == 'python':
                            continue
                        dep = self._parse_poetry_dependency(name, version_info)
                        if dep:
                            dependencies[dep.normalized_name] = dep
        
        return dependencies
    
    def _parse_pep_dependency(self, dep_str: str) -> Optional[Dependency]:
        """Parse PEP 621 dependency string."""
        # Simple regex for package[extras]>=version
        match = re.match(r'^([a-zA-Z0-9_-]+)(?:\[([^\]]+)\])?\s*(.*)$', dep_str)
        if not match:
            return None
        
        name = match.group(1)
        extras = match.group(2).split(',') if match.group(2) else []
        version_str = match.group(3).strip()
        
        version_spec = ""
        version = "*"
        
        if version_str:
            spec_match = re.match(r'^([<>=!~]+)\s*(.+)$', version_str)
            if spec_match:
                version_spec = spec_match.group(1)
                version = spec_match.group(2)
        
        return Dependency(
            name=name,
            version=version,
            version_spec=version_spec,
            extras=extras,
            ecosystem="pypi"
        )
    
    def _parse_poetry_dependency(self, name: str, version_info: Any) -> Optional[Dependency]:
        """Parse Poetry-style dependency."""
        if isinstance(version_info, str):
            version = version_info.lstrip('^~>=<!')
            version_spec = version_info[0] if version_info[0] in '^~>=<!' else ""
            return Dependency(
                name=name,
                version=version,
                version_spec=version_spec,
                ecosystem="pypi"
            )
        elif isinstance(version_info, dict):
            version = version_info.get('version', '*').lstrip('^~>=<!')
            return Dependency(
                name=name,
                version=version,
                version_spec="^" if 'version' in version_info else "",
                ecosystem="pypi"
            )
        return None


class PoetryLockParser:
    """Parser for poetry.lock files."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse poetry.lock content."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        dependencies = {}
        
        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ParserError(f"Failed to parse poetry.lock: {e}")
        
        packages = data.get('package', [])
        for pkg in packages:
            name = pkg.get('name', '')
            version = pkg.get('version', '*')
            
            if name:
                dep = Dependency(
                    name=name,
                    version=version,
                    version_spec="==",  # Lock files have exact versions
                    ecosystem="pypi"
                )
                dependencies[dep.normalized_name] = dep
        
        return dependencies


class PackageJsonParser:
    """Parser for package.json files."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse package.json content."""
        dependencies = {}
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ParserError(f"Failed to parse package.json: {e}")
        
        # Parse both dependencies and devDependencies
        for section in ['dependencies', 'devDependencies', 'peerDependencies']:
            if section in data:
                for name, version in data[section].items():
                    dep = self._parse_npm_version(name, version)
                    if dep:
                        dependencies[dep.normalized_name] = dep
        
        return dependencies
    
    def _parse_npm_version(self, name: str, version: str) -> Dependency:
        """Parse npm version string."""
        version_spec = ""
        clean_version = version
        
        if version.startswith('^'):
            version_spec = "^"
            clean_version = version[1:]
        elif version.startswith('~'):
            version_spec = "~"
            clean_version = version[1:]
        elif version.startswith('>='):
            version_spec = ">="
            clean_version = version[2:]
        elif version.startswith('>'):
            version_spec = ">"
            clean_version = version[1:]
        
        return Dependency(
            name=name,
            version=clean_version,
            version_spec=version_spec,
            ecosystem="npm"
        )


class PackageLockParser:
    """Parser for package-lock.json files."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse package-lock.json content."""
        dependencies = {}
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ParserError(f"Failed to parse package-lock.json: {e}")
        
        # Handle both v2/v3 and v1 formats
        packages = data.get('packages', {})
        if packages:
            # v2/v3 format
            for path, info in packages.items():
                if path == '':
                    continue  # Skip root package
                name = path.replace('node_modules/', '').split('/')[-1]
                if name.startswith('@'):
                    # Handle scoped packages
                    parts = path.replace('node_modules/', '').split('/')
                    if len(parts) >= 2:
                        name = f"{parts[-2]}/{parts[-1]}"
                
                version = info.get('version', '*')
                dep = Dependency(
                    name=name,
                    version=version,
                    version_spec="==",
                    ecosystem="npm"
                )
                dependencies[dep.normalized_name] = dep
        else:
            # v1 format
            deps = data.get('dependencies', {})
            for name, info in deps.items():
                version = info.get('version', '*')
                dep = Dependency(
                    name=name,
                    version=version,
                    version_spec="==",
                    ecosystem="npm"
                )
                dependencies[dep.normalized_name] = dep
        
        return dependencies


class YarnLockParser:
    """Parser for yarn.lock files."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse yarn.lock content."""
        dependencies = {}
        current_package = None
        current_version = None
        
        for line in content.split('\n'):
            line = line.rstrip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Package definition line (ends with :)
            if line.endswith(':') and not line.startswith(' '):
                # Extract package name from format like "package@^1.0.0:"
                parts = line.rstrip(':').split('@')
                if len(parts) >= 2:
                    # Handle scoped packages and regular packages
                    if parts[0] == '':
                        # Scoped package like @scope/name@version
                        current_package = f"@{parts[1]}"
                    else:
                        current_package = parts[0]
                    current_version = None
            
            # Version line
            elif line.strip().startswith('version'):
                match = re.match(r'\s*version\s+"?([^"]+)"?', line)
                if match and current_package:
                    current_version = match.group(1)
                    dep = Dependency(
                        name=current_package,
                        version=current_version,
                        version_spec="==",
                        ecosystem="npm"
                    )
                    dependencies[dep.normalized_name] = dep
        
        return dependencies


class PipfileParser:
    """Parser for Pipfile files."""
    
    def parse(self, content: str) -> Dict[str, Dependency]:
        """Parse Pipfile content."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib
        
        dependencies = {}
        
        try:
            data = tomllib.loads(content)
        except Exception as e:
            raise ParserError(f"Failed to parse Pipfile: {e}")
        
        for section in ['packages', 'dev-packages']:
            if section in data:
                for name, version_info in data[section].items():
                    dep = self._parse_pipfile_dependency(name, version_info)
                    if dep:
                        dependencies[dep.normalized_name] = dep
        
        return dependencies
    
    def _parse_pipfile_dependency(self, name: str, version_info: Any) -> Optional[Dependency]:
        """Parse Pipfile dependency entry."""
        if version_info == "*":
            return Dependency(name=name, version="*", ecosystem="pypi")
        elif isinstance(version_info, str):
            # Parse version like ">=1.0.0"
            match = re.match(r'^([<>=!~]+)?\s*(.*)$', version_info)
            if match:
                return Dependency(
                    name=name,
                    version=match.group(2) or "*",
                    version_spec=match.group(1) or "",
                    ecosystem="pypi"
                )
        elif isinstance(version_info, dict):
            version = version_info.get('version', '*')
            if version != '*':
                match = re.match(r'^([<>=!~]+)?\s*(.*)$', version)
                if match:
                    return Dependency(
                        name=name,
                        version=match.group(2) or "*",
                        version_spec=match.group(1) or "",
                        ecosystem="pypi"
                    )
            return Dependency(name=name, version="*", ecosystem="pypi")
        
        return Dependency(name=name, version="*", ecosystem="pypi")


# Parser factory
PARSERS = {
    'requirements.txt': RequirementsParser,
    'pyproject.toml': PyProjectParser,
    'poetry.lock': PoetryLockParser,
    'package.json': PackageJsonParser,
    'package-lock.json': PackageLockParser,
    'yarn.lock': YarnLockParser,
    'Pipfile': PipfileParser,
}


def detect_file_type(file_path: Path) -> Optional[str]:
    """Detect dependency file type from path."""
    name = file_path.name
    if name in PARSERS:
        return name
    return None


def parse_file(file_path: Path) -> Dict[str, Dependency]:
    """Parse a dependency file and return dependencies."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise ParserError(f"File not found: {file_path}")
    
    file_type = detect_file_type(file_path)
    if not file_type:
        raise ParserError(f"Unsupported file type: {file_path.name}")
    
    content = file_path.read_text(encoding='utf-8')
    parser_class = PARSERS[file_type]
    parser = parser_class()
    
    return parser.parse(content)


def auto_detect_files(directory: Path) -> List[Path]:
    """Auto-detect dependency files in a directory."""
    directory = Path(directory)
    found_files = []
    
    for filename in PARSERS.keys():
        file_path = directory / filename
        if file_path.exists():
            found_files.append(file_path)
    
    return found_files
