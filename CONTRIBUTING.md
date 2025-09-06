# Contributing to DepGuard Lite

Thank you for your interest in contributing to DepGuard Lite! 🛡️

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/DepGuard-Lite.git
   ```
3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes

3. Run tests:
   ```bash
   pytest tests/ -v
   ```

4. Commit using conventional commits:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `docs:` - Documentation
   - `test:` - Tests
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance

5. Push and create a Pull Request

## Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for public functions
- Keep functions focused and small

## Testing

- Write tests for new functionality
- Ensure all tests pass before submitting
- Aim for 85%+ test coverage

## Reporting Issues

Please include:
- Python version
- OS and version
- Steps to reproduce
- Expected vs actual behavior

## Questions?

Open a discussion on GitHub or reach out to the maintainers.
