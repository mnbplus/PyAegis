# Contributing to PyAegis

First off, thank you for considering contributing to PyAegis! It's people like you that make PyAegis an incredible open source static analysis security tool.

## Code of Conduct
By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/mnbplus/PyAegis.git
   cd PyAegis
   ```
3. **Set up virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Or `venv\Scripts\activate` on Windows
   ```
4. **Install dependencies**:
   ```bash
   pip install -e .[dev]
   pre-commit install
   ```

## Development Workflow

- We follow **Test-Driven Development (TDD)** where possible. Add tests for your changes in the `tests/` directory.
- All code must pass `black`, `flake8`, and `pytest`.
- Run tests before submitting a PR:
   ```bash
   pytest tests/
   ```

## Creating a Pull Request
1. Create a feature branch derived from `main`.
2. Commit your changes with clear, descriptive commit messages.
3. Push to your fork and submit a Pull Request.
4. Ensure all CI checks pass.
