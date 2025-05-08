# OSPS Baseline Checker

A simple Python CLI tool to assess a GitHub repository against **all Level 1 controls** of the [OpenSSF OSPS Security Baseline v2025-02-25](https://baseline.openssf.org/versions/2025-02-25).

---

## Features

- Authenticates via GitHub Personal Access Token
- Checks for:
  - MFA enforcement (OSPS-AC-01.01)
  - Default collaborator permissions (OSPS-AC-02.01)
  - Branch protection (OSPS-AC-03.01 & 03.02)
  - Presence of CI workflows (OSPS-BR-01.01)
  - HTTPS project homepage (OSPS-BR-03.01)
  - User guide documentation (OSPS-DO-01.01)
  - Defect reporting guide (OSPS-DO-02.01)
  - Public discussion mechanisms (issues/wiki) (OSPS-GV-02.01)
  - Contribution guide (OSPS-GV-03.01)
  - SPDX-compliant license (OSPS-LE-02.01)
  - License file / assets (OSPS-LE-02.02 & 03.02)
  - Public repository (OSPS-QA-01.01)
  - Commit history (OSPS-QA-01.02)
  - Dependency manifest files (OSPS-QA-02.01)
  - Subprojects listing (OSPS-QA-04.01)
  - No binary artifacts checked in (OSPS-QA-05.01)
  - Security contacts (`SECURITY.md`) (OSPS-VM-02.01)

---

## Prerequisites

- Python 3.7+
- A GitHub Personal Access Token with **repo** and **read:org** scopes
- [`PyGithub`](https://github.com/PyGithub/PyGithub)
- [`click`](https://click.palletsprojects.com/)

---

## Installation

1. Clone this repository (or copy `osps_baseline_checker.py` into your project):
   ```bash
   git clone https://github.com/your-org/osps-baseline-checker.git
   cd ossp-baseline-checker

2. Creat environment

```shell
python3 -m venv .venv
source .venv/bin/activate
```

3. install dependencies

```shell
pip install PyGithub click
```

## Usage

```shell
export GITHUB_TOKEN="ghp_XXXXXXXXXXXXXXXXXXXX"
chmod +x osps_baseline_checker.py
./osps_baseline_checker.py --repo owner/name
```

or 


```shell
python osps_baseline_checker.py --repo openssf/baseline --token ghp_XXXXXXXXXXXXXXXX

```
