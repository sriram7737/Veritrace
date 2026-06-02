# Release Checklist

Use this checklist for public releases.

## Preflight

```bash
python -m pip install -U build twine
python -m pip install -e ".[dev,api,redis,postgres,dashboard]"
veritrace --help
python -m compileall -q veritrace tests
python -m pytest -q --tb=no
veritrace redteam --json --dynamic --attacks 200 --seed 999
```

Confirm the version matches in:

- `pyproject.toml`
- `veritrace/__init__.py`
- `veritrace/api/app.py`

Confirm the release positioning:

- PyPI classifier is `Development Status :: 3 - Alpha`.
- README/PyPI long description contains the Alpha maturity notice.
- Release notes reference `docs/LIVE_TEST_RESULTS.md`.
- `docs/IMPLEMENTATION_STATUS.md` and `docs/HARDENING_GUIDE.md` are included
  in the built artifacts.
- QuantumLayer is described only as future research, not as an exposed feature.

## Build

```bash
python -m build
python -m twine check dist/*
```

## GitHub

```bash
git status --short
git tag -a v0.4.1 -m "v0.4.1"
git push origin main
git push origin v0.4.1
```

Create a GitHub Release from tag `v0.4.1` and include:

- Test result: `363 passed, 2 warnings`
- Dynamic red-team result: `200/200 caught`, seed `999`
- Live Sepolia transaction hash from `docs/LIVE_TEST_RESULTS.md`
- S3 archive/restore smoke result from `docs/LIVE_TEST_RESULTS.md`
- Links to `docs/IMPLEMENTATION_STATUS.md` and `docs/HARDENING_GUIDE.md`
- Honest limits: Alpha maturity, no external pen test, no SSO/OIDC/RBAC, no
  regulated-production certification

## PyPI

Publishing requires a PyPI API token with permission for the `veritrace`
project.

Go ahead with PyPI publication when the preflight, build, twine check, and
positioning checks above pass.

```bash
python -m twine upload dist/*
```

The PyPI page uses `README.md` as the long description. Do not publish if the
Alpha maturity notice or honest-limits section has been removed.

Use TestPyPI first when validating a new publishing setup:

```bash
python -m twine upload --repository testpypi dist/*
```

## Post-release Smoke

```bash
pip install "veritrace[api,dashboard,redis,postgres]"
veritrace --help
veritrace redteam --json --dynamic --attacks 200 --seed 999
```
