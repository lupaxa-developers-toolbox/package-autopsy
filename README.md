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

## Quick Start

```bash
package-autopsy inspect dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy modules dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy validate dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy verify dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy audit dist/mypackage-1.0.0-py3-none-any.whl
package-autopsy --version
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

Commands: `inspect`, `contents`, `modules`, `commands`, `dependencies`,
`compatibility`, `metadata`, `licences`, `binaries`, `validate`, `verify`,
`compare`, `consistency`, `audit`, `graph`, `report`, `check`, `formats`,
and `version`.

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

```bash
package-autopsy version
```

```text
package-autopsy 0.0.0
```

`package-autopsy --version` prints the same line.

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
