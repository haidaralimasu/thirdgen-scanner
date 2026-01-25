"""
ThirdGen Security Scanner - Markdown Report Generator
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import AuditReport, Finding


def get_impact_description(check: str) -> str:
    """Get a standard impact description based on vulnerability type"""
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
        "unchecked": "Unchecked return value could lead to silent failures.",
        "tx-origin": "Using tx.origin for authentication is vulnerable to phishing attacks.",
    }

    for keyword, impact in impacts.items():
        if keyword in check_lower:
            return impact

    return "This vulnerability could lead to loss of funds or protocol malfunction."


def get_mitigation_template(check: str) -> str:
    """Get a standard mitigation recommendation based on vulnerability type"""
    check_lower = check.lower()

    if "reentrancy" in check_lower:
        return """```diff
+ import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

- contract Vulnerable {
+ contract Fixed is ReentrancyGuard {

-     function withdraw() external {
+     function withdraw() external nonReentrant {
+         uint256 amount = balances[msg.sender];
+         balances[msg.sender] = 0;  // State change BEFORE external call
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
+     for (uint i = start; i < start + count && i < items.length; i++) {
          process(items[i]);
      }
  }
```"""

    elif "tx-origin" in check_lower:
        return """```diff
- require(tx.origin == owner, "Not owner");
+ require(msg.sender == owner, "Not owner");
```"""

    return f"Review and address the `{check}` vulnerability according to security best practices."


def get_poc_template(finding: Finding) -> str:
    """Generate a Proof of Concept template"""
    contract = finding.contract_name
    check_lower = finding.id.lower()

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
        // Setup initial state

        // Execute exploit

        // Verify exploit succeeded
    }}
}}"""


def get_code_snippet(file_path: str, start_line: int, end_line: int, context: int = 3) -> str:
    """Extract code snippet with line numbers"""
    try:
        path = Path(file_path)
        if not path.exists():
            return ""

        lines = path.read_text(encoding="utf-8").splitlines()
        total = len(lines)

        snippet_start = max(0, start_line - context - 1)
        snippet_end = min(total, end_line + context)

        result = []
        for i in range(snippet_start, snippet_end):
            result.append(f"{i + 1:4d} | {lines[i]}")

        return "\n".join(result)

    except (IOError, UnicodeDecodeError):
        return ""


def format_finding_full(finding: Finding, issue_id: str, config: dict) -> str:
    """Format a finding with full details (for high/critical)"""
    lines = []
    lines.append(f"### [{issue_id}] {finding.title}")
    lines.append("")

    # Use AI analysis if available
    if finding.ai_analyzed and not finding.is_false_positive:
        lines.append(f"**Location:** `{finding.location}`")
        lines.append("")
        lines.append(f"**Tool:** {finding.tool}")
        if finding.swc:
            lines.append(f" | **SWC:** [{finding.swc}](https://swcregistry.io/docs/{finding.swc})")
        lines.append("")

        if finding.description:
            lines.append(f"**Description:** {finding.description}")
            lines.append("")

        if finding.attack_scenario and finding.attack_scenario != "N/A":
            lines.append(f"**Attack Scenario:** {finding.attack_scenario}")
            lines.append("")

        if finding.impact:
            lines.append(f"**Impact:** {finding.impact}")
            lines.append("")

        if finding.suggested_fix:
            lines.append("**Recommended Fix:**")
            lines.append("")
            lines.append("```solidity")
            lines.append(finding.suggested_fix)
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    # Fallback to template-based output
    lines.append(f"**Location:** `{finding.location}`")
    lines.append("")
    lines.append(f"**Tool:** {finding.tool}")
    if finding.swc:
        lines.append(f" | **SWC:** [{finding.swc}](https://swcregistry.io/docs/{finding.swc})")
    lines.append("")

    lines.append(f"**Description:** {finding.description}")
    lines.append("")

    # Code snippet
    if config.get("report", {}).get("include_code_snippets", True) and finding.line > 0:
        snippet = get_code_snippet(finding.file, finding.line, finding.end_line or finding.line)
        if snippet:
            lines.append("**Vulnerable Code:**")
            lines.append("")
            lines.append("```solidity")
            lines.append(snippet)
            lines.append("```")
            lines.append("")

    # Impact
    impact = get_impact_description(finding.id)
    lines.append(f"**Impact:** {impact}")
    lines.append("")

    # PoC
    if config.get("report", {}).get("include_poc", True):
        poc = get_poc_template(finding)
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

    # Mitigation
    if config.get("report", {}).get("include_mitigations", True):
        mitigation = get_mitigation_template(finding.id)
        lines.append("**Recommended Mitigation:**")
        lines.append("")
        lines.append(mitigation)
        lines.append("")

    return "\n".join(lines)


def format_finding_minimal(finding: Finding) -> str:
    """Format a finding minimally (for low/informational)"""
    return f"- **{finding.title}** - `{finding.location}` ({finding.tool})\n"


def generate_report(report: AuditReport, config: dict) -> str:
    """Generate the full markdown report"""
    today = datetime.now().strftime("%B %d, %Y")
    report_config = config.get("report", {})
    collapse_low = report_config.get("collapse_low_severity", True)
    show_raw = report_config.get("include_raw_counts", True)

    sections = []

    # Header
    title = report_config.get("title", "Smart Contract Security Audit Report")
    sections.append(f"# {title}")
    sections.append("")
    sections.append(f"**Generated:** {today}")
    sections.append(f"**Tools:** {', '.join(report.tools_run)}")
    sections.append("")

    # Summary Table
    sections.append("## Summary")
    sections.append("")

    if show_raw and report.false_positive_count > 0:
        sections.append("| Severity | Found | Confirmed |")
        sections.append("|----------|-------|-----------|")
    else:
        sections.append("| Severity | Count |")
        sections.append("|----------|-------|")

    critical_raw = len([f for f in report.findings if f.severity.lower() == "critical"])
    high_raw = len([f for f in report.findings if f.severity.lower() == "high"])

    if show_raw and report.false_positive_count > 0:
        sections.append(f"| 🔴 Critical | {critical_raw} | {len(report.critical)} |")
        sections.append(f"| 🟠 High | {high_raw} | {len(report.high)} |")
        sections.append(f"| 🟡 Medium | {len(report.medium)} | - |")
        sections.append(f"| ⚪ Low | {len(report.low)} | - |")
        sections.append(f"| ℹ️ Info | {len(report.informational)} | - |")
    else:
        sections.append(f"| 🔴 Critical | {len(report.critical)} |")
        sections.append(f"| 🟠 High | {len(report.high)} |")
        sections.append(f"| 🟡 Medium | {len(report.medium)} |")
        sections.append(f"| ⚪ Low | {len(report.low)} |")
        sections.append(f"| ℹ️ Info | {len(report.informational)} |")

    sections.append("")

    # Critical Issues
    if report.critical:
        sections.append("---")
        sections.append("")
        sections.append("## 🔴 Critical Issues")
        sections.append("")
        for idx, finding in enumerate(report.critical, 1):
            sections.append(format_finding_full(finding, f"C-{idx}", config))

    # High Issues
    if report.high:
        sections.append("---")
        sections.append("")
        sections.append("## 🟠 High Severity Issues")
        sections.append("")
        for idx, finding in enumerate(report.high, 1):
            sections.append(format_finding_full(finding, f"H-{idx}", config))

    # Medium Issues
    if report.medium:
        sections.append("---")
        sections.append("")
        sections.append("## 🟡 Medium Severity Issues")
        sections.append("")
        for idx, finding in enumerate(report.medium, 1):
            sections.append(format_finding_full(finding, f"M-{idx}", config))

    # Low & Informational (collapsible)
    if report.low or report.informational:
        sections.append("---")
        sections.append("")

        if collapse_low:
            count = len(report.low) + len(report.informational)
            sections.append(f"<details>")
            sections.append(f"<summary>⚪ Low & Informational ({count} items)</summary>")
            sections.append("")

        if report.low:
            sections.append("### Low Severity")
            sections.append("")
            for finding in report.low:
                sections.append(format_finding_minimal(finding))
            sections.append("")

        if report.informational:
            sections.append("### Informational")
            sections.append("")
            for finding in report.informational:
                sections.append(format_finding_minimal(finding))
            sections.append("")

        if collapse_low:
            sections.append("</details>")
            sections.append("")

    # No issues message
    if report.total == 0:
        sections.append("✅ **No security issues found!**")
        sections.append("")

    # Footer
    sections.append("---")
    sections.append("")
    sections.append("*Generated by [ThirdGen Security Scanner](https://thirdgen.io)*")

    return "\n".join(sections)


def generate_pr_comment(report: AuditReport, config: dict) -> str:
    """Generate a condensed report suitable for PR comments"""
    sections = []

    sections.append("## 🔒 Security Audit Report")
    sections.append("")

    # Quick summary
    if report.has_critical or report.has_high:
        sections.append("⚠️ **Action Required:** Critical/High severity issues found!")
        sections.append("")

    # Summary table
    sections.append("| Severity | Count |")
    sections.append("|----------|-------|")
    sections.append(f"| 🔴 Critical | {len(report.critical)} |")
    sections.append(f"| 🟠 High | {len(report.high)} |")
    sections.append(f"| 🟡 Medium | {len(report.medium)} |")
    sections.append(f"| ⚪ Low/Info | {len(report.low) + len(report.informational)} |")
    sections.append("")

    # Top issues only
    if report.critical:
        sections.append("### 🔴 Critical")
        sections.append("")
        for idx, f in enumerate(report.critical[:5], 1):
            sections.append(f"**[C-{idx}] {f.title}**")
            sections.append(f"- Location: `{f.location}`")
            sections.append(f"- {f.description[:200]}..." if len(f.description) > 200 else f"- {f.description}")
            sections.append("")

    if report.high:
        sections.append("### 🟠 High")
        sections.append("")
        for idx, f in enumerate(report.high[:5], 1):
            sections.append(f"**[H-{idx}] {f.title}**")
            sections.append(f"- Location: `{f.location}`")
            sections.append(f"- {f.description[:200]}..." if len(f.description) > 200 else f"- {f.description}")
            sections.append("")

    if report.total == 0:
        sections.append("✅ **No security issues found!**")
        sections.append("")

    sections.append("---")
    sections.append(f"*Tools: {', '.join(report.tools_run)} | [ThirdGen](https://thirdgen.io)*")

    return "\n".join(sections)
