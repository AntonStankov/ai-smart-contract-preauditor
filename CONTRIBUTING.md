# Contributing to Contract AI Auditor

We welcome contributions to the Contract AI Auditor project! This document provides guidelines for contributing.

## Development Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd contract-ai-auditor
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

## Code Standards

- Follow PEP 8 style guidelines
- Use type hints for all function signatures
- Write comprehensive docstrings for all public APIs
- Maintain test coverage above 80%

## Testing

Run the test suite:
```bash
pytest tests/
```

Run specific test categories:
```bash
pytest tests/unit/          # Unit tests
pytest tests/integration/   # Integration tests
```

## Submitting Changes

1. Create a feature branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and add tests

3. Run the test suite:
```bash
pytest
```

4. Run code formatting:
```bash
black .
flake8 .
mypy .
```

5. Commit your changes:
```bash
git commit -m "Add feature: your feature description"
```

6. Push to your fork and submit a pull request

## Security Considerations

- Never commit API keys or secrets
- Test all changes on local blockchain only
- Validate that vulnerability detection improvements don't increase false negatives
- Document any changes to model behavior or training data

## Reporting Issues

Please use GitHub Issues to report:
- Bugs
- Feature requests
- Documentation improvements
- Performance issues

Include:
- Python version
- Dependency versions
- Steps to reproduce
- Expected vs actual behavior

## Code Review Process

All submissions require review. We review:
- Code quality and style
- Test coverage
- Documentation updates
- Security implications
- Model performance impacts

## License

By contributing, you agree that your contributions will be licensed under the MIT License.