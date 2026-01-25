"""
ThirdGen Smart Contract Security Scanner
"""

import subprocess
import json
import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_REF = os.getenv("GITHUB_REF", "")

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
GITHUB_API = "https://api.github.com"

DEFAULT_CONFIG = {
    "solc_version": "0.8.25",
    "exclude_severities": [],
    "exclude_paths": ["lib/", "node_modules/", "test/", "script/", "mock/", "mocks/"],
    "mythril": {
        "targets": [],
        "remappings_file": "remappings.json"
    }
}

TIMEOUTS = {"slither": 300, "aderyn": 120, "gemini": 90, "github": 15}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class Issue:
    tool: str
    severity: str
    file: str
    description: str
    check: str
    lines: tuple[int, int] = field(default=(0, 0))

    @property
    def contract_name(self) -> str:
        return Path(self.file).stem if self.file else "Unknown"

    @property
    def severity_normalized(self) -> str:
        sev = self.severity.lower()
        if sev in ("critical", "high"):
            return "High"
        elif sev == "medium":
            return "Medium"
        elif sev == "low":
            return "Low"
        return "Informational"


@dataclass
class AuditReport:
    issues: list[Issue]
    high: list[Issue] = field(default_factory=list)
    medium: list[Issue] = field(default_factory=list)
    low: list[Issue] = field(default_factory=list)
    info: list[Issue] = field(default_factory=list)

    def __post_init__(self):
        for issue in self.issues:
            category = issue.severity_normalized.lower()
            if category == "high":
                self.high.append(issue)
            elif category == "medium":
                self.medium.append(issue)
            elif category == "low":
                self.low.append(issue)
            else:
                self.info.append(issue)

    @property
    def total(self) -> int:
        return len(self.issues)


def load_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    config["mythril"] = DEFAULT_CONFIG["mythril"].copy()
    config_path = Path("thirdgen.config.json")

    if config_path.exists():
        try:
            user_config = json.loads(config_path.read_text())

            if "solc_version" in user_config:
                config["solc_version"] = user_config["solc_version"]

            if "exclude_severities" in user_config:
                config["exclude_severities"] = user_config["exclude_severities"]

            if "exclude_paths" in user_config:
                config["exclude_paths"] = user_config["exclude_paths"]

            if "mythril" in user_config:
                if "targets" in user_config["mythril"]:
                    config["mythril"]["targets"] = user_config["mythril"]["targets"]
                if "remappings_file" in user_config["mythril"]:
                    config["mythril"]["remappings_file"] = user_config["mythril"]["remappings_file"]

            log.info(f"Loaded config from {config_path}")
        except (json.JSONDecodeError, IOError) as e:
            log.warning(f"Failed to load config: {e}")

    return config


def run_command(cmd: list[str], timeout: int = 120) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        log.error(f"Command timed out: {cmd[0]}")
    except FileNotFoundError:
        log.error(f"Command not found: {cmd[0]}")
    return None


def read_source_file(path: str) -> str:
    try:
        file_path = Path(path)
        if file_path.exists() and file_path.is_file():
            return file_path.read_text(encoding="utf-8")
    except (IOError, UnicodeDecodeError):
        pass
    return ""


def get_code_snippet(file_path: str, start_line: int, end_line: int, context: int = 3) -> str:
    source = read_source_file(file_path)
    if not source or start_line == 0:
        return ""

    lines = source.splitlines()
    total_lines = len(lines)

    snippet_start = max(0, start_line - context - 1)
    snippet_end = min(total_lines, end_line + context)
    snippet_lines = lines[snippet_start:snippet_end]

    numbered_lines = []
    for i, line in enumerate(snippet_lines, start=snippet_start + 1):
        numbered_lines.append(f"{i:4d} | {line}")

    return "\n".join(numbered_lines)


def run_slither(exclude_paths: list[str]) -> list[Issue]:
    log.info("Running Slither...")
    stdout = run_command(["slither", ".", "--json", "-"], timeout=TIMEOUTS["slither"])

    if not stdout:
        return []

    issues = []
    try:
        json_start = stdout.find("{")
        json_end = stdout.rfind("}") + 1

        if json_start == -1 or json_end == 0:
            return []

        data = json.loads(stdout[json_start:json_end])
        detectors = data.get("results", {}).get("detectors", [])

        for detector in detectors:
            elements = detector.get("elements", [])
            if not elements:
                continue

            source_mapping = elements[0].get("source_mapping", {})
            file_path = source_mapping.get("filename_relative", "")

            if any(exc in file_path for exc in exclude_paths):
                continue

            lines_list = source_mapping.get("lines", [0])
            start_line = lines_list[0] if lines_list else 0
            end_line = lines_list[-1] if lines_list else start_line

            issues.append(Issue(
                tool="Slither",
                severity=detector.get("impact", "Unknown"),
                file=file_path,
                description=detector.get("description", "").strip(),
                check=detector.get("check", "unknown"),
                lines=(start_line, end_line)
            ))

        log.info(f"Slither found {len(issues)} issues")

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse Slither JSON: {e}")

    return issues


def run_aderyn(exclude_paths: list[str]) -> list[Issue]:
    log.info("Running Aderyn...")
    report_path = Path("aderyn_temp_report.json")

    if report_path.exists():
        report_path.unlink()

    run_command(["aderyn", ".", "-o", str(report_path), "-x", ",".join(exclude_paths)], timeout=TIMEOUTS["aderyn"])

    if not report_path.exists():
        return []

    issues = []
    try:
        data = json.loads(report_path.read_text())

        severity_mapping = {
            "critical_issues": "Critical",
            "high_issues": "High",
            "medium_issues": "Medium",
            "low_issues": "Low",
        }

        for key, severity in severity_mapping.items():
            section = data.get(key, {})
            items = section.get("issues", []) if isinstance(section, dict) else []

            for item in items:
                instances = item.get("instances", [])
                if not instances:
                    continue

                first_instance = instances[0]
                file_path = first_instance.get("contract_path", "")

                if any(exc in file_path for exc in exclude_paths):
                    continue

                line_num = first_instance.get("line_no", 0)

                issues.append(Issue(
                    tool="Aderyn",
                    severity=severity,
                    file=file_path,
                    description=item.get("description", "").strip(),
                    check=item.get("title", "unknown"),
                    lines=(line_num, line_num)
                ))

        log.info(f"Aderyn found {len(issues)} issues")

    except json.JSONDecodeError as e:
        log.error(f"Failed to parse Aderyn JSON: {e}")
    finally:
        if report_path.exists():
            report_path.unlink()

    return issues


def run_mythril(config: dict) -> list[Issue]:
    targets = config["mythril"]["targets"]
    remappings_file = config["mythril"]["remappings_file"]

    if not targets:
        log.info("Mythril: No targets specified in config, skipping")
        return []

    log.info(f"Running Mythril on {len(targets)} targets (no timeout)...")

    issues = []

    for target in targets:
        if not Path(target).exists():
            log.warning(f"Mythril target not found: {target}")
            continue

        log.info(f"  Analyzing {target}...")

        cmd = ["myth", "analyze", target, "-o", "json"]

        if Path(remappings_file).exists():
            cmd.extend(["--solc-json", remappings_file])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            stdout = result.stdout

            if not stdout:
                continue

            json_start = stdout.find("{")
            json_end = stdout.rfind("}") + 1

            if json_start == -1 or json_end == 0:
                json_start = stdout.find("[")
                json_end = stdout.rfind("]") + 1

            if json_start == -1 or json_end == 0:
                continue

            data = json.loads(stdout[json_start:json_end])

            if isinstance(data, dict):
                if "issues" in data:
                    myth_issues = data["issues"]
                elif "success" in data and data.get("issues"):
                    myth_issues = data["issues"]
                else:
                    myth_issues = []
            elif isinstance(data, list):
                myth_issues = data
            else:
                continue

            for item in myth_issues:
                severity = item.get("severity", "Medium")
                if severity.lower() == "low":
                    severity = "Low"
                elif severity.lower() == "medium":
                    severity = "Medium"
                elif severity.lower() in ("high", "critical"):
                    severity = "High"

                line_num = item.get("lineno", 0)
                if not line_num:
                    line_num = item.get("sourceMap", {}).get("line", 0) if isinstance(item.get("sourceMap"), dict) else 0

                issues.append(Issue(
                    tool="Mythril",
                    severity=severity,
                    file=target,
                    description=item.get("description", "").strip(),
                    check=item.get("title", item.get("swc-id", "unknown")),
                    lines=(line_num, line_num)
                ))

        except json.JSONDecodeError:
            log.warning(f"  Failed to parse Mythril output for {target}")
        except FileNotFoundError:
            log.error("Mythril not found. Install with: pip install mythril")
            return []
        except Exception as e:
            log.warning(f"  Mythril error on {target}: {e}")

    log.info(f"Mythril found {len(issues)} issues")
    return issues


def query_gemini(prompt: str) -> Optional[str]:
    if not GEMINI_API_KEY:
        return None

    try:
        response = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUTS["gemini"]
        )

        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    except (requests.RequestException, KeyError, IndexError):
        pass

    return None


def analyze_issue_with_ai(issue: Issue) -> Optional[str]:
    source_code = read_source_file(issue.file)

    if len(source_code) > 10000:
        source_code = source_code[:10000] + "\n... (truncated)"

    prompt = f"""You are an elite smart contract security auditor. Analyze this vulnerability.

CONTRACT: {issue.contract_name}
FILE: {issue.file}
VULNERABILITY: {issue.check}
SCANNER DESCRIPTION: {issue.description}

SOURCE CODE:
```solidity
{source_code}
```

Write the finding in this EXACT format only:

**Description:** Explain the vulnerability technically. Reference specific function names and line numbers.

**Impact:** What are the real-world consequences? Can funds be stolen?

**Proof of Concept:**

<details>
<summary>PoC</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {{
    function setUp() public {{
    }}

    function testExploit() public {{
    }}
}}
```

</details>

**Recommended Mitigation:**

```diff
- // vulnerable code
+ // fixed code
```
"""

    log.info(f"  AI analyzing: {issue.check}")
    response = query_gemini(prompt)

    if response:
        cleaned = response.strip()
        if cleaned.startswith("```markdown"):
            cleaned = cleaned[11:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return cleaned.strip()

    return None


def get_impact_description(check: str) -> str:
    check_lower = check.lower()

    impacts = {
        "reentrancy": "An attacker can re-enter the contract before state changes complete, potentially draining all funds.",
        "arbitrary-send": "ETH can be sent to arbitrary addresses, allowing an attacker to steal funds.",
        "selfdestruct": "The contract can be destroyed, permanently locking all funds.",
        "delegatecall": "Malicious delegatecall can hijack contract storage and steal funds.",
        "access-control": "Missing access control allows unauthorized users to call privileged functions.",
        "timestamp": "Block timestamp manipulation could be exploited to game time-dependent logic.",
        "loop": "Unbounded loop can cause out-of-gas errors, making the function unusable.",
        "integer": "Integer overflow/underflow can corrupt balances and protocol state.",
        "swc": "Smart contract weakness detected by symbolic execution analysis.",
    }

    for keyword, impact in impacts.items():
        if keyword in check_lower:
            return impact

    return "This vulnerability could lead to loss of funds or protocol malfunction."


def generate_poc_template(issue: Issue) -> str:
    contract = issue.contract_name
    check_lower = issue.check.lower()

    if "reentrancy" in check_lower:
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract}.sol";

contract Attacker {{
    {contract} public target;

    constructor(address _target) {{
        target = {contract}(_target);
    }}

    receive() external payable {{
        if (address(target).balance >= 1 ether) {{
            // Re-enter vulnerable function
        }}
    }}

    function attack() external payable {{
        // Trigger initial call
    }}
}}

contract ReentrancyTest is Test {{
    {contract} public target;
    Attacker public attacker;

    function setUp() public {{
        target = new {contract}();
        attacker = new Attacker(address(target));
        vm.deal(address(target), 10 ether);
    }}

    function testReentrancy() public {{
        vm.deal(address(attacker), 1 ether);
        uint256 balanceBefore = address(target).balance;
        attacker.attack{{value: 1 ether}}();
        assertLt(address(target).balance, balanceBefore);
    }}
}}"""

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract}.sol";

contract ExploitTest is Test {{
    {contract} public target;

    function setUp() public {{
        target = new {contract}();
    }}

    function testExploit() public {{
        // Setup
        // Execute exploit
        // Verify
    }}
}}"""


def get_mitigation_recommendation(check: str) -> str:
    check_lower = check.lower()

    if "reentrancy" in check_lower:
        return """```diff
+ import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

- contract Vulnerable {
+ contract Fixed is ReentrancyGuard {

-     function withdraw() external {
+     function withdraw() external nonReentrant {
+         uint256 amount = balances[msg.sender];
+         balances[msg.sender] = 0;
          (bool success, ) = msg.sender.call{value: amount}("");
          require(success);
-         balances[msg.sender] = 0;
      }
  }
```"""

    elif "arbitrary-send" in check_lower or "eth" in check_lower:
        return """```diff
  function withdraw() external {
+     require(msg.sender == owner, "Not authorized");
-     payable(msg.sender).transfer(address(this).balance);
+     (bool success, ) = payable(owner).call{value: address(this).balance}("");
+     require(success, "Transfer failed");
  }
```"""

    elif "timestamp" in check_lower:
        return """```diff
- if (block.timestamp >= deadline) {
+ if (block.number >= deadlineBlock) {
      // time-sensitive logic
  }
```"""

    elif "loop" in check_lower:
        return """```diff
+ uint256 constant MAX_BATCH = 100;

- function processAll() external {
-     for (uint i = 0; i < items.length; i++) {
+ function processBatch(uint256 start, uint256 count) external {
+     require(count <= MAX_BATCH, "Batch too large");
+     for (uint i = start; i < start + count; i++) {
          process(items[i]);
      }
  }
```"""

    elif "unindexed" in check_lower or "event" in check_lower:
        return """```diff
- event Transfer(address from, address to, uint256 amount);
+ event Transfer(address indexed from, address indexed to, uint256 amount);
```"""

    elif "integer" in check_lower or "overflow" in check_lower:
        return """```diff
- uint256 result = a + b;
+ // Use Solidity 0.8+ built-in overflow checks or SafeMath
+ uint256 result = a + b; // Automatically reverts on overflow in 0.8+
```"""

    return f"Review and fix the vulnerability in `{check}`."


def generate_finding(issue: Issue, issue_id: str, use_ai: bool = True) -> str:
    lines = []
    lines.append(f"### [{issue_id}] `{issue.contract_name}::{issue.check}`")
    lines.append("")

    if use_ai and GEMINI_API_KEY:
        ai_analysis = analyze_issue_with_ai(issue)
        if ai_analysis:
            lines.append(ai_analysis)
            lines.append("")
            return "\n".join(lines)

    lines.append(f"**Description:** {issue.description}")
    lines.append("")

    if issue.lines[0] > 0:
        snippet = get_code_snippet(issue.file, issue.lines[0], issue.lines[1])
        if snippet:
            lines.append("**Vulnerable Code:**")
            lines.append("")
            lines.append("```solidity")
            lines.append(snippet)
            lines.append("```")
            lines.append("")

    impact = get_impact_description(issue.check)
    lines.append(f"**Impact:** {impact}")
    lines.append("")

    poc = generate_poc_template(issue)
    lines.append("**Proof of Concept:**")
    lines.append("")
    lines.append("<details>")
    lines.append("<summary>PoC</summary>")
    lines.append("")
    lines.append("```solidity")
    lines.append(poc)
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    mitigation = get_mitigation_recommendation(issue.check)
    lines.append("**Recommended Mitigation:**")
    lines.append("")
    lines.append(mitigation)
    lines.append("")

    return "\n".join(lines)


def generate_report(report: AuditReport) -> str:
    today = datetime.now().strftime("%B %d, %Y")

    sections = []

    sections.append(f"""---
title: Security Audit Report
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
    {{\\Huge\\bfseries Security Audit Report\\par}}
    \\vspace{{1cm}}
    {{\\Large Version 1.0\\par}}
    \\vspace{{2cm}}
    {{\\Large\\itshape ThirdGen.io\\par}}
    \\vfill
    {{\\large \\today\\par}}
\\end{{titlepage}}

\\maketitle

Prepared by: [ThirdGen](https://thirdgen.io)
Lead Auditors:
- ThirdGen Security Team
""")

    toc_lines = [
        "# Table of Contents",
        "- [Table of Contents](#table-of-contents)",
        "- [Protocol Summary](#protocol-summary)",
        "- [Disclaimer](#disclaimer)",
        "- [Risk Classification](#risk-classification)",
        "- [Audit Details](#audit-details)",
        "  - [Scope](#scope)",
        "  - [Roles](#roles)",
        "- [Executive Summary](#executive-summary)",
        "  - [Issues found](#issues-found)",
        "- [Findings](#findings)",
    ]

    if report.high:
        toc_lines.append("  - [High](#high)")
    if report.medium:
        toc_lines.append("  - [Medium](#medium)")
    if report.low:
        toc_lines.append("  - [Low](#low)")
    if report.info:
        toc_lines.append("  - [Informational](#informational)")

    sections.append("\n".join(toc_lines))

    sections.append("""
# Protocol Summary

Protocol functionality and architecture will be documented based on the specific audit scope.

# Disclaimer

The ThirdGen team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity.

# Audit Details

## Scope

```
./src/
```

## Roles

Roles will be documented based on the specific protocol.
""")

    sections.append(f"""
# Executive Summary

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | {len(report.high)} |
| Medium   | {len(report.medium)} |
| Low      | {len(report.low)} |
| Info     | {len(report.info)} |
| Total    | {report.total} |
""")

    sections.append("\n# Findings\n")

    if report.high:
        sections.append("## High\n")
        for idx, issue in enumerate(report.high, 1):
            sections.append(generate_finding(issue, f"H-{idx}", use_ai=True))

    if report.medium:
        sections.append("## Medium\n")
        for idx, issue in enumerate(report.medium, 1):
            sections.append(generate_finding(issue, f"M-{idx}", use_ai=True))

    if report.low:
        sections.append("## Low\n")
        for idx, issue in enumerate(report.low, 1):
            sections.append(generate_finding(issue, f"L-{idx}", use_ai=False))

    if report.info:
        sections.append("## Informational\n")
        for idx, issue in enumerate(report.info, 1):
            sections.append(f"### [I-{idx}] `{issue.contract_name}::{issue.check}`\n")
            sections.append(f"**Description:** {issue.description}\n")

    return "\n".join(sections)


def post_to_github(report_content: str) -> bool:
    if not all([GITHUB_TOKEN, GITHUB_REPOSITORY]):
        return False

    if "/pull/" not in GITHUB_REF:
        return False

    try:
        pr_number = GITHUB_REF.split("/")[-2]
        comments_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }

        response = requests.get(comments_url, headers=headers, timeout=TIMEOUTS["github"])
        if response.status_code == 200:
            for comment in response.json():
                if "Security Audit Report" in comment.get("body", ""):
                    update_url = f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/issues/comments/{comment['id']}"
                    requests.patch(update_url, json={"body": report_content}, headers=headers, timeout=TIMEOUTS["github"])
                    log.info("Updated existing PR comment")
                    return True

        response = requests.post(comments_url, json={"body": report_content}, headers=headers, timeout=TIMEOUTS["github"])
        if response.status_code == 201:
            log.info("Posted new PR comment")
            return True

    except requests.RequestException as e:
        log.error(f"GitHub API error: {e}")

    return False


def filter_issues_by_severity(issues: list[Issue], exclude_severities: list[str]) -> list[Issue]:
    if not exclude_severities:
        return issues

    exclude_lower = [s.lower() for s in exclude_severities]
    return [i for i in issues if i.severity_normalized.lower() not in exclude_lower]


def main():
    log.info("ThirdGen Security Scanner")

    config = load_config()
    exclude_paths = config["exclude_paths"]
    exclude_severities = config["exclude_severities"]

    all_issues: list[Issue] = []
    all_issues.extend(run_slither(exclude_paths))
    all_issues.extend(run_aderyn(exclude_paths))
    all_issues.extend(run_mythril(config))

    all_issues = filter_issues_by_severity(all_issues, exclude_severities)
    all_issues.sort(key=lambda x: SEVERITY_RANK.get(x.severity, 99))

    report = AuditReport(issues=all_issues)

    log.info(f"Found {report.total} issues: {len(report.high)} High, {len(report.medium)} Medium, {len(report.low)} Low, {len(report.info)} Info")

    if report.total > 0:
        report_content = generate_report(report)
        Path("report.md").write_text(report_content, encoding="utf-8")
        log.info("Report saved to report.md")
        post_to_github(report_content)
    else:
        log.info("No issues found")

    log.info("Scan complete")


if __name__ == "__main__":
    main()
