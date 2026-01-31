# 🛡️ ThirdGen Security Scanner

[![GitHub Release](https://img.shields.io/github/v/release/haidaralimasu/thirdgen-scanner?color=purple&label=Latest%20Version)](https://github.com/haidaralimasu/thirdgen-scanner/releases)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docker](https://img.shields.io/badge/container-ghcr.io-blue?logo=docker)](https://github.com/haidaralimasu/thirdgen-scanner/pkgs/container/thirdgen-scanner)

**Automated Smart Contract Security Audit for GitHub Pull Requests.**

ThirdGen Scanner is a "Zero Config" security orchestrator that combines the power of industry-standard tools into a single, unified report. It runs automatically on every Pull Request and posts a summary comment directly to your team.

### ⚡ Features

- **Zero Configuration:** Just add the workflow file. No Python scripts, no Dockerfiles, no manual setup.
- **Triple-Engine Analysis:** Runs **Slither** (Static), **Aderyn** (Rust-based Static), and **Mythril** (Symbolic Execution) in parallel.
- **Unified Reporting:** De-duplicates and merges findings into one clean report.
- **Sticky Comments:** Updates the same comment on your PR instead of spamming 50 new notifications.
- **Smart Filtering:** Ignore "Informational" or "Low" severity issues via a simple config file.

---

## 🚀 Quick Start (Copy & Paste)

Create a file in your repository at `.github/workflows/security.yml` and paste this code.

**That's it. You are done.**

```yaml
name: Smart Contract Security Scan

on: [pull_request]

permissions:
  contents: read
  pull-requests: write # Required to post the report comment

jobs:
  thirdgen-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Security Scanner
        uses: haidaralimasu/thirdgen-scanner@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 📊 Dashboard Integration

Track all your scans, findings, and security trends in the **ThirdGen Dashboard**.

### Setup

1. Sign up at [app.thirdgen.security](https://app.thirdgen.security)
2. Create a team and add your repository
3. Copy your Team API Key from Settings
4. Add `THIRDGEN_API_KEY` to your repository secrets

### Updated Workflow

```yaml
name: Smart Contract Security Scan

on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  thirdgen-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Security Scanner
        uses: haidaralimasu/thirdgen-scanner@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          api_key: ${{ secrets.THIRDGEN_API_KEY }}
```

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `token` | Yes | GitHub token for PR comments |
| `api_key` | No | ThirdGen API key for dashboard integration |
| `api_url` | No | Custom API URL (defaults to production) |
