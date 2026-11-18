<p align="center">
  <a href="https://github.com/lupaxa-developers-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/developers-toolbox/readme-logo.png" alt="Developers Toolbox" />
  </a>
</p>

<h1 align="center">Package Autopsy</h1>

Package Autopsy inspects Python wheels and source distributions without
installing them, executing their code, or talking to the network. It reports
what a distribution contains, whether its metadata and RECORD hashes are
consistent, and what changed between releases.

The PyPI name is `lupaxa-package-autopsy`. The import path is
`lupaxa.package_autopsy`. The console script is `package-autopsy`. `lupaxa`
is a namespace package.

Inspection is not installation. Matching RECORD hashes prove consistency with
this archive, not publisher identity.

## Install

```bash
pip install lupaxa-package-autopsy
```

Requires Python 3.11+.

> **Note:** `NO_COLOR`, including an empty value, turns colour off.
> `--no-colour` does the same.

## Formats

Both wheels and source distributions are first-class inputs. The tool
never installs them or puts them on `sys.path`.

| Kind                | Extensions                | Recognised by                                        |
| ------------------- | ------------------------- | ---------------------------------------------------- |
| Wheel               | `.whl`                    | ZIP with `.dist-info`, `METADATA`, `WHEEL`, `RECORD` |
| Source distribution | `.tar.gz`, `.tgz`, `.zip` | `PKG-INFO` and/or `pyproject.toml`                   |

A tarball or ZIP without that metadata is an ordinary archive, not a
Python package. Misleading extensions are reported. RECORD hash
verification applies to wheels; sdists have no `RECORD` file.

## Quick Start

```bash
package-autopsy inspect dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy inspect dist/mypackage-1.0.0.tar.gz
package-autopsy modules dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy validate dist/mypackage-1.0.0.tar.gz
package-autopsy verify dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy audit dist/mypackage-1.0.0-py3-none-any.whl
```

## What it Does

`package-autopsy` treats distributions as untrusted archives. It reads wheel
and sdist metadata, inventories files, discovers importable modules
(including implicit namespace packages), lists entry points, evaluates
declared dependencies and markers, and checks RECORD hashes. It never imports
packaged modules, never runs `setup.py`, and never invokes a build backend.

```bash
package-autopsy inspect package-1.2.0-py3-none-any.whl --json
package-autopsy contents package.whl --tree --sort size
package-autopsy dependencies package.whl --python-version 3.12 --platform linux
package-autopsy compare package-1.0.0-py3-none-any.whl package-1.1.0-py3-none-any.whl
package-autopsy consistency package-1.0.0.tar.gz package-1.0.0-py3-none-any.whl
package-autopsy check dist/ --config package-autopsy.toml
package-autopsy report package.whl --format html --output package-report.html
```

## Commands

| Command         | Description                                                                 |
| --------------- | --------------------------------------------------------------------------- |
| `inspect`       | Overview of identity, files, modules, dependencies, and RECORD status.      |
| `contents`      | List packaged files and directories; optional tree, sort, and regex filter. |
| `modules`       | Discover importable packages, modules, and implicit namespaces.             |
| `commands`      | List console scripts, GUI scripts, and other entry points.                  |
| `dependencies`  | Analyse Requires-Dist, extras, and environment markers.                     |
| `compatibility` | Check Requires-Python and wheel tags against a target interpreter.          |
| `metadata`      | Show core metadata, dynamic fields, and the declared build backend.         |
| `licences`      | Inspect licence expressions, legacy License fields, and bundled files.      |
| `binaries`      | Identify compiled extensions and bundled native binaries.                   |
| `validate`      | Check distribution structure and metadata completeness.                     |
| `verify`        | Recalculate RECORD hashes and check archive integrity.                      |
| `compare`       | Diff two distributions: files, metadata, and modules.                       |
| `consistency`   | Compare a wheel against its matching sdist.                                 |
| `audit`         | Detect packaging issues and unexpected files.                               |
| `graph`         | Show declared dependency relationships.                                     |
| `report`        | Write a detailed report in text, Markdown, HTML, JSON, or CSV.              |
| `check`         | Enforce packaging policy from TOML configuration.                           |
| `formats`       | List supported archive formats and capabilities.                            |

## JSON Output

`--json` prints a UTF-8 document with `schema_version` `"1.0"`. Byte counts
are numbers. Unavailable fields are `null`. Secrets are redacted. Progress
messages are not mixed into machine output.

## Configuration

Settings are TOML. CLI options override `--config`, which overrides
`~/.config/package-autopsy/package-autopsy.toml`, which overrides built-in
defaults.

```toml
[policy]
fail_on = "error"
max_distribution_size = "20MB"
require_licence = true
require_valid_record = true
disallow_secrets = true

[policy.files]
deny = ["*.env", "*.pem", "*.key", "__pycache__/**", ".git/**"]

[policy.dependencies]
allow_direct_urls = false
```

## Exit Codes

| Code | Result                                          |
| ---- | ----------------------------------------------- |
| `0`  | Successful completion                           |
| `1`  | General operational error                       |
| `2`  | Invalid arguments or configuration              |
| `3`  | Invalid distribution                            |
| `4`  | Integrity verification failure                  |
| `5`  | Packaging policy violation                      |
| `6`  | Unsupported format or capability                |
| `7`  | Resource limit exceeded                         |
| `8`  | Partial batch failure                           |
| `9`  | Incomplete required analysis                    |

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
