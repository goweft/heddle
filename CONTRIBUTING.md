# Contributing

Heddle is currently a solo project. Contributions are welcome but the scope is intentionally narrow.

## What helps

- **Bug reports** — if you try Heddle and something breaks, open an issue with the config you used and the error you got.
- **Starter packs** — if you write a config for a service that isn't covered (Docker, PagerDuty, Datadog, etc.), submit it as a PR to `packs/`.
- **Security findings** — see [SECURITY.md](SECURITY.md) for reporting guidelines.
- **Documentation fixes** — typos, broken links, unclear explanations.

## What to expect

This project moves in focused bursts. PRs may sit for a while before review. If you're planning a large change, open an issue first to check alignment.

## Development

```bash
git clone https://github.com/goweft/heddle.git
cd heddle
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

All tests must pass before merging. Agent configs must validate with `heddle validate`.

## Style

- Python 3.11+, type hints on public functions
- Pydantic v2 for data models
- Security controls must log to the audit trail
- New tools must declare `access: read` or `access: write`
