# Witnesslint Development Instructions

## Releasing a new version

1. Bump version number in `witnesslint/__init__.py` and `pyproject.toml` to next release version.
Write an entry for the new version in `doc/Changelog.md`. Commit these changes and nothing else.

2. Build the release archives with `poetry build`. Test the archives and make sure all necessary files are included.

3. Upload the generated archives to PyPI with `poetry publish`. This requires a PyPI account.
You can use either your username/password combination or an API token for authentication.
Please refer to `https://python-poetry.org/docs/repositories/#configuring-credentials` for details.

4. Create and push a git tag for the new release.

5. Create a release on GitHub from the tag.

6. Bump version number in `witnesslint/__init__.py` and `pyproject.toml` to next development version.
Commit only these changes.