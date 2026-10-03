# horo-next

An **unofficial** PyPI distribution of [Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous Research.

Upstream no longer publishes Hermes Agent to PyPI. horo-next rebuilds each upstream release as a pip-installable wheel. It is not affiliated with, endorsed by, or sponsored by Nous Research.

```bash
pip install horo-next
hermes
```

The command is `hermes` and the data directory is `~/.hermes`, as upstream. Do not install horo-next and `hermes-agent` into the same environment: both provide the same top-level modules.

## What differs from upstream

Packaging only. Product behaviour is upstream's.

- Bundled skills and locales are packaged inside the wheel.
- `hermes update` points to `pip install -U horo-next`.
- Direct dependencies with a published vulnerability fix are raised to the fixed version. Each release notes which.
- Python 3.11 is kept supported; the upper bound follows each upstream release.
- Dependencies only available from a URL (not on PyPI) are left out and must be installed separately.

## Versions

`horo-next X.Y.Z` is built from upstream `Hermes Agent vX.Y.Z`. A packaging-only fix on the same upstream release is published as `X.Y.Z.postN`.

## Offline installation

Each release attaches `requirements-X.Y.Z.txt`, the full resolved dependency set. On a machine with internet access:

```bash
pip download horo-next==X.Y.Z -d wheelhouse
```

Then on the offline machine:

```bash
pip install --no-index --find-links wheelhouse horo-next
```

## License

MIT. Hermes Agent is copyright Nous Research; bundled skills carry their own licenses.
