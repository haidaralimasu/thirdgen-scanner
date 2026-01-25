import subprocess
import json
import os
import requests
import sys
import glob

# --- CONFIGURATION & CONSTANTS ---
TIMEOUT_SLITHER = 300
TIMEOUT_MYTHRIL = 600
TIMEOUT_ADERYN = 120
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Default paths to ignore if config is missing
DEFAULT_EXCLUDES = ["lib/", "node_modules/", "test/", "script/", "mock/"]

# --- HELPER: LOAD CONFIG ---


def load_config():
    config = {
        "exclude_paths": DEFAULT_EXCLUDES,
        "solc_version": "0.8.25"
    }

    if os.path.exists("thirdgen.config.json"):
        try:
            with open("thirdgen.config.json", "r") as f:
                user_conf = json.load(f)
                if "exclude_paths" in user_conf:
                    config["exclude_paths"] = user_conf["exclude_paths"]
        except Exception as e:
            print(f"⚠️ Could not load config: {e}")

    return config

# --- HELPER: RUN COMMAND ---


def run_command(command, timeout=300):
    try:
        if not command or not command[0]:
            return None
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

# --- HELPER: GEMINI CLIENT ---


def query_gemini(prompt):
    if not GEMINI_API_KEY:
        return None
    try:
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        headers = {"Content-Type": "application/json"}
        # Increased timeout for long POCs
        res = requests.post(url, json=payload, headers=headers, timeout=45)
        if res.status_code == 200:
            return res.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None
    return None

# --- HELPER: GET SOURCE CODE ---


def get_src(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return f.read()
    except:
        pass
    return ""

# --- FEATURE: ELITE ANALYSIS (The "Best in Market" Prompt - Cyfrin Style) ---


def analyze_issue(issue, source_code, issue_id):
    print(f"🧠 Analyzing Issue {issue_id}: {issue['description'][:50]}...")

    prompt = f"""
    You are an Elite Smart Contract Security Researcher (top ranking on Code4rena/Sherlock/Cyfrin).
    You have found a vulnerability. Your job is to write the Audit Report finding in the EXACT Cyfrin format.

    --- CONTEXT ---
    VULNERABILITY TYPE: {issue['description']}
    FILE: {issue['file']}
    CHECK: {issue['check']}
    SOURCE CODE:
    {source_code}

    --- TASK ---
    Write a rigorous audit finding in the EXACT Cyfrin format below. Be precise and technical.

    --- REQUIRED FORMAT (Follow EXACTLY) ---

    **Description:** (Deep technical explanation of the root cause. Trace the execution flow. Explain WHY it is broken, referencing specific variables, functions, and lines. Be specific about what function in what contract has the issue.)

    **Impact:** (Explain the real-world consequences. What can an attacker do? What funds are at risk? Be specific about severity.)

    **Proof of Concept:**

    <details>
    <summary>Proof Of Code</summary>

    Place the following into the test file.

    ```solidity
    function testExploit() public {{
        // Write a complete, working Foundry test that demonstrates the vulnerability
        // Include setup, attack execution, and assertions proving the exploit worked
    }}
    ```

    </details>

    **Recommended Mitigation:** (Provide the specific fix with a diff code block showing before/after. Use + for additions and - for removals.)

    ```diff
    - // old vulnerable code
    + // new fixed code
    ```
    """

    analysis = query_gemini(prompt)
    if analysis:
        # Remove any main markdown wrappers if Gemini adds them
        clean = analysis.replace("```markdown", "").strip()
        return clean
    return None

# --- STEP 1: SLITHER ---


def step_slither(exclude_paths):
    print("🔍 Running Slither...")
    cmd = ["slither", ".", "--json", "-"]
    stdout = run_command(cmd, TIMEOUT_SLITHER)
    issues = []

    if stdout:
        try:
            start = stdout.find('{')
            end = stdout.rfind('}') + 1
            if start != -1:
                data = json.loads(stdout[start:end])
                for i in data.get("results", {}).get("detectors", []):
                    file_path = i.get("elements", [{}])[0].get(
                        "source_mapping", {}).get("filename_relative", "")
                    if any(x in file_path for x in exclude_paths):
                        continue

                    issues.append({
                        "tool": "Slither",
                        "severity": i.get("impact", "Unknown"),
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("check", "Unknown")
                    })
        except:
            pass
    return issues

# --- STEP 2: ADERYN ---


def step_aderyn(exclude_paths):
    print("🦜 Running Aderyn...")
    cmd = ["aderyn", ".", "-o", "report.json", "-x", ",".join(exclude_paths)]
    run_command(cmd, TIMEOUT_ADERYN)
    issues = []

    if os.path.exists("report.json"):
        try:
            with open("report.json", "r") as f:
                data = json.load(f)
            severity_map = {"critical_issues": "Critical",
                            "high_issues": "High", "medium_issues": "Medium"}
            for key, sev in severity_map.items():
                for i in data.get(key, {}).get("issues", []):
                    if not i.get("instances"):
                        continue
                    file_path = i["instances"][0].get("contract_path", "")
                    if any(x in file_path for x in exclude_paths):
                        continue

                    issues.append({
                        "tool": "Aderyn",
                        "severity": sev,
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("title", "Unknown")
                    })
            os.remove("report.json")
        except:
            pass
    return issues

# --- GENERATE REPORT (Cyfrin Style) ---


def get_report_header():
    """Generate the Cyfrin-style report header with frontmatter and metadata."""
    from datetime import datetime
    today = datetime.now().strftime("%B %d, %Y")

    header = f"""---
title: Protocol Audit Report
author: ThirdGen.io
date: {today}
header-includes:
  - \\usepackage{{titling}}
  - \\usepackage{{graphicx}}
---

\\begin{{titlepage}}
    \\centering
    \\begin{{figure}}[h]
        \\centering
        \\includegraphics[width=0.5\\textwidth]{{logo.pdf}}
    \\end{{figure}}
    \\vspace*{{2cm}}
    {{\\Huge\\bfseries Protocol Audit Report\\par}}
    \\vspace{{1cm}}
    {{\\Large Version 1.0\\par}}
    \\vspace{{2cm}}
    {{\\Large\\itshape ThirdGen.io\\par}}
    \\vfill
    {{\\large \\today\\par}}
\\end{{titlepage}}

\\maketitle

<!-- Your report starts here! -->

Prepared by: [ThirdGen](https://thirdgen.io)
Lead Auditors:
- ThirdGen Security Team

"""
    return header


def get_toc(high_issues, medium_issues, low_issues, info_issues):
    """Generate dynamic Table of Contents based on findings."""
    toc = ["# Table of Contents"]
    toc.append("- [Table of Contents](#table-of-contents)")
    toc.append("- [Protocol Summary](#protocol-summary)")
    toc.append("- [Disclaimer](#disclaimer)")
    toc.append("- [Risk Classification](#risk-classification)")
    toc.append("- [Audit Details](#audit-details)")
    toc.append("  - [Scope](#scope)")
    toc.append("  - [Roles](#roles)")
    toc.append("- [Executive Summary](#executive-summary)")
    toc.append("  - [Issues found](#issues-found)")
    toc.append("- [Findings](#findings)")

    if high_issues:
        toc.append("  - [High](#high)")
        for idx, issue in enumerate(high_issues):
            issue_id = f"H-{idx+1}"
            title = f"`{issue['file'].split('/')[-1].replace('.sol', '')}::{issue['check']}` vulnerability"
            anchor = f"#h-{idx+1}-{issue['check'].lower().replace(' ', '-').replace('_', '-')}"
            toc.append(f"    - [\\[{issue_id}\\] {title}]({anchor})")

    if medium_issues:
        toc.append("  - [Medium](#medium)")
        for idx, issue in enumerate(medium_issues):
            issue_id = f"M-{idx+1}"
            title = f"`{issue['file'].split('/')[-1].replace('.sol', '')}::{issue['check']}`"
            anchor = f"#m-{idx+1}-{issue['check'].lower().replace(' ', '-').replace('_', '-')}"
            toc.append(f"    - [\\[{issue_id}\\] {title}]({anchor})")

    if low_issues:
        toc.append("  - [Low](#low)")

    if info_issues:
        toc.append("  - [Informationals](#informationals)")

    toc.append("")
    return "\n".join(toc)


def get_static_sections():
    """Generate static sections: Protocol Summary, Disclaimer, Risk Classification, Audit Details."""
    sections = """# Protocol Summary

Protocol functionality and description will be added based on the specific audit scope.

# Disclaimer

The ThirdGen team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details

## Scope

Files in scope for this audit:

```
./src/
```

## Roles

Roles will be documented based on the specific protocol being audited.

"""
    return sections


def get_executive_summary(high_count, medium_count, low_count, info_count):
    """Generate Executive Summary with issues table."""
    total = high_count + medium_count + low_count + info_count

    summary = f"""# Executive Summary

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | {high_count}                      |
| Medium   | {medium_count}                      |
| Low      | {low_count}                      |
| Info     | {info_count}                      |
| Total    | {total}                     |

"""
    return summary


def generate_report(all_issues):
    if not all_issues:
        return "✅ No security issues found."

    # Categorize issues by severity
    high_issues = [i for i in all_issues if i['severity'] in ["High", "Critical"]]
    medium_issues = [i for i in all_issues if i['severity'] == "Medium"]
    low_issues = [i for i in all_issues if i['severity'] == "Low"]
    info_issues = [i for i in all_issues if i['severity'] in ["Informational", "Info", "Optimization"]]

    md = []

    # Add header
    md.append(get_report_header())

    # Add Table of Contents
    md.append(get_toc(high_issues, medium_issues, low_issues, info_issues))

    # Add static sections
    md.append(get_static_sections())

    # Add Executive Summary
    md.append(get_executive_summary(len(high_issues), len(medium_issues), len(low_issues), len(info_issues)))

    # Start Findings section
    md.append("# Findings\n")

    # PROCESS HIGH/CRITICAL
    if high_issues:
        md.append("## High\n")

        for idx, issue in enumerate(high_issues):
            issue_id = f"H-{idx+1}"
            contract_name = issue['file'].split('/')[-1].replace('.sol', '')
            title = f"`{contract_name}::{issue['check']}` vulnerability"

            md.append(f"### [{issue_id}] {title}\n")

            # If we have an API Key, use AI to generate the full report
            if GEMINI_API_KEY:
                src = get_src(issue['file'])
                ai_report = analyze_issue(issue, src, issue_id)
                if ai_report:
                    md.append(ai_report)
                    md.append("\n")
                    continue

            # Fallback if no AI or AI failed
            md.append(f"**Description:** {issue['description']}\n")
            md.append(f"**Impact:** This vulnerability could lead to loss of funds or protocol malfunction.\n")
            md.append(f"**Proof of Concept:** Manual testing required.\n")
            md.append(f"**Recommended Mitigation:** Review and fix the identified issue in `{issue['file']}`.\n")

    # PROCESS MEDIUM
    if medium_issues:
        md.append("## Medium\n")

        for idx, issue in enumerate(medium_issues):
            issue_id = f"M-{idx+1}"
            contract_name = issue['file'].split('/')[-1].replace('.sol', '')
            title = f"`{contract_name}::{issue['check']}` issue"

            md.append(f"### [{issue_id}] {title}\n")

            if GEMINI_API_KEY:
                src = get_src(issue['file'])
                ai_report = analyze_issue(issue, src, issue_id)
                if ai_report:
                    md.append(ai_report)
                    md.append("\n")
                    continue

            # Fallback
            md.append(f"**Description:** {issue['description']}\n")
            md.append(f"**Impact:** Medium severity issue that should be addressed.\n")
            md.append(f"**Recommended Mitigation:** Review the issue in `{issue['file']}`.\n")

    # PROCESS LOW
    if low_issues:
        md.append("## Low\n")

        for idx, issue in enumerate(low_issues):
            issue_id = f"L-{idx+1}"
            contract_name = issue['file'].split('/')[-1].replace('.sol', '')

            md.append(f"### [{issue_id}] `{contract_name}::{issue['check']}`\n")
            md.append(f"**Description:** {issue['description']}\n")
            md.append(f"**Recommended Mitigation:** Consider addressing this low severity issue.\n")

    # PROCESS INFORMATIONAL
    if info_issues:
        md.append("## Informationals\n")

        for idx, issue in enumerate(info_issues):
            issue_id = f"I-{idx+1}"
            contract_name = issue['file'].split('/')[-1].replace('.sol', '')

            md.append(f"### [{issue_id}] `{contract_name}::{issue['check']}`\n")
            md.append(f"**Description:** {issue['description']}\n")

    return "\n".join(md)

# --- MAIN ---


def main():
    print("🚀 STARTING AUDIT...")
    config = load_config()

    all_issues = []
    all_issues.extend(step_slither(config["exclude_paths"]))
    all_issues.extend(step_aderyn(config["exclude_paths"]))

    # Generate Report
    report = generate_report(all_issues)

    # Save & Post
    with open("report.md", "w") as f:
        f.write(report)
    print("✅ Audit Complete.")

    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    if token and repo and "pull" in os.getenv("GITHUB_REF", ""):
        try:
            pr_num = os.getenv("GITHUB_REF").split("/")[-2]
            # ✅ CORRECT CODE (Copy this exactly)
            url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
            headers = {"Authorization": f"token {token}",
                       "Accept": "application/vnd.github.v3+json"}

            # Update or Post
            existing = requests.get(url, headers=headers).json()
            if isinstance(existing, list):
                for c in existing:
                    if "ThirdGen Audit Report" in c.get("body", ""):
                        requests.patch(
                            f"{url}/{c['id']}", json={"body": report}, headers=headers)
                        return
            requests.post(url, json={"body": report}, headers=headers)
        except Exception as e:
            print(f"⚠️ Github Comment Error: {e}")


if __name__ == "__main__":
    main()
