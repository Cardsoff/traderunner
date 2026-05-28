# Contributing to TradeRunner

Thank you for considering a contribution!

## Quick Start

1. Fork the repo and clone your fork
2. Create a virtualenv and install dev dependencies:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   pip install pytest
   ```
3. Run tests: `pytest tests/`
4. Make your changes
5. Submit a Pull Request

## Code Style

- Python: PEP 8, 4 spaces, max line ~100 chars
- JS: 2 spaces, vanilla ES6+ (no transpilation), no jQuery
- HTML/CSS: keep it readable; no minification in the repo

## Adding a New Exchange

TradeRunner currently supports Bitunix. To add another exchange:

1. Create `<exchange>_client.py` modeled after `bitunix_client.py`
2. Implement: `get_equity()`, `get_trade_history(start_ms, end_ms)`, `get_open_positions()`
3. Add ENV constants to `models.py` (`<exchange>_api_key`, `<exchange>_api_secret`)
4. Update `crypto_keys.is_encrypted_key()` whitelist
5. Add UI for connecting in `templates/index.html`

PRs that add new exchanges are very welcome.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- TradeRunner version (`git rev-parse HEAD`)
- Python version, OS

For security issues, see [SECURITY.md](SECURITY.md) — please **do not** post publicly.

## License

By contributing, you agree that your contributions will be licensed under [AGPL-3.0](LICENSE).
