"""
ThirdGen Security Scanner - AI Enhancement (Gemini)
Analyzes findings to detect false positives and enhance reports
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import requests

from .models import Finding

log = logging.getLogger(__name__)

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def get_code_context(file_path: str, line: int, context_lines: int = 10) -> str:
    """Extract source code around the finding location"""
    try:
        path = Path(file_path)
        if not path.exists():
            return "// Source file not found"

        lines = path.read_text(encoding="utf-8").splitlines()
        total = len(lines)

        start = max(0, line - context_lines - 1)
        end = min(total, line + context_lines)

        result = []
        for i in range(start, end):
            marker = ">>> " if i == line - 1 else "    "
            result.append(f"{marker}{i + 1:4d} | {lines[i]}")

        return "\n".join(result)

    except (IOError, UnicodeDecodeError):
        return "// Could not read source file"


def query_gemini(prompt: str, api_key: str, model: str = "gemini-1.5-flash", timeout: int = 90) -> Optional[str]:
    """Send prompt to Gemini API"""
    if not api_key:
        return None

    try:
        url = GEMINI_URL.format(model=model)
        response = requests.post(
            f"{url}?key={api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            headers={"Content-Type": "application/json"},
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    except (requests.RequestException, KeyError, IndexError) as e:
        log.warning(f"Gemini API error: {e}")

    return None


def parse_ai_response(text: str) -> dict[str, Any]:
    """Parse JSON from AI response, handling markdown code blocks"""
    try:
        # Remove markdown code blocks
        text = re.sub(r'```json\s*', '', text)
        text = re.sub(r'```\s*', '', text)
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return {}


def analyze_finding(finding: Finding, api_key: str, model: str, timeout: int) -> Finding:
    """Use AI to analyze a single finding"""
    code_context = get_code_context(finding.file, finding.line)

    prompt = f"""You are an expert smart contract security auditor. Analyze this finding from an automated scanner.

## Finding Details
- **Tool**: {finding.tool}
- **Type**: {finding.id}
- **Title**: {finding.title}
- **Severity**: {finding.severity}
- **Location**: {finding.file}:{finding.line}
- **Description**: {finding.description}

## Code Context
```solidity
{code_context}
```

Analyze whether this is a real vulnerability or a false positive. Consider:
1. Is the vulnerability actually exploitable in this context?
2. Are there existing protections (modifiers, checks, etc.)?
3. What is the realistic attack scenario?

Respond with ONLY a valid JSON object (no markdown, no explanation):
{{
  "is_false_positive": <true or false>,
  "confidence": "<high|medium|low>",
  "reasoning": "<brief explanation of your analysis>",
  "attack_scenario": "<how an attacker could exploit this, or 'N/A' if false positive>",
  "impact": "<what damage could occur if exploited>",
  "suggested_fix": "<code fix or mitigation recommendation>"
}}"""

    response = query_gemini(prompt, api_key, model, timeout)

    if response:
        result = parse_ai_response(response)
        if result:
            finding.is_false_positive = result.get("is_false_positive", False)
            finding.ai_confidence = result.get("confidence", "low")
            finding.attack_scenario = result.get("attack_scenario", "")
            finding.impact = result.get("impact", "")
            finding.suggested_fix = result.get("suggested_fix", "")
            finding.ai_analyzed = True

    return finding


def enhance_findings(findings: list[Finding], config: dict) -> list[Finding]:
    """
    Enhance findings using AI analysis.
    Only analyzes high-severity findings to save API costs.
    """
    ai_config = config.get("ai", {})

    if not ai_config.get("enabled", False):
        log.info("AI enhancement: disabled")
        return findings

    api_key = os.environ.get(ai_config.get("api_key_env", "GEMINI_API_KEY"))
    if not api_key:
        log.warning("AI enhancement: no API key found in environment")
        return findings

    model = ai_config.get("model", "gemini-1.5-flash")
    timeout = ai_config.get("timeout", 90)
    analyze_severities = ai_config.get("analyze_only", ["critical", "high"])
    max_findings = ai_config.get("max_findings", 20)

    # Filter to findings that should be analyzed
    to_analyze = [
        f for f in findings
        if f.severity.lower() in [s.lower() for s in analyze_severities]
    ][:max_findings]

    if not to_analyze:
        log.info("AI enhancement: no high-severity findings to analyze")
        return findings

    log.info(f"AI analyzing {len(to_analyze)} findings...")

    for i, finding in enumerate(to_analyze):
        log.info(f"  [{i + 1}/{len(to_analyze)}] {finding.title[:50]}...")
        analyze_finding(finding, api_key, model, timeout)

    # Count false positives
    fp_count = sum(1 for f in findings if f.is_false_positive)
    if fp_count > 0:
        log.info(f"AI detected {fp_count} false positives")

    return findings


def generate_detailed_analysis(finding: Finding, api_key: str, model: str = "gemini-1.5-flash") -> Optional[str]:
    """
    Generate a detailed audit-style analysis for a confirmed finding.
    Used for high/critical findings in the final report.
    """
    source_code = ""
    try:
        path = Path(finding.file)
        if path.exists():
            source_code = path.read_text(encoding="utf-8")
            if len(source_code) > 10000:
                source_code = source_code[:10000] + "\n... (truncated)"
    except (IOError, UnicodeDecodeError):
        source_code = "// Could not read source"

    prompt = f"""You are an elite smart contract security auditor. Write a professional audit finding.

CONTRACT: {finding.contract_name}
FILE: {finding.file}
VULNERABILITY: {finding.id}
SCANNER DESCRIPTION: {finding.description}

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

    response = query_gemini(prompt, api_key, model, timeout=90)

    if response:
        # Clean up markdown formatting
        cleaned = response.strip()
        if cleaned.startswith("```markdown"):
            cleaned = cleaned[11:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return cleaned.strip()

    return None
