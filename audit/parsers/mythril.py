"""
Mythril output parser
"""

import json
from typing import Any

from ..models import Finding


def parse_mythril(output: str, severity_map: dict[str, str], target_file: str = "") -> list[Finding]:
    """Parse Mythril JSON output"""
    if not output:
        return []

    findings = []

    try:
        # Find JSON in output
        json_start = output.find("{")
        json_end = output.rfind("}") + 1

        if json_start == -1 or json_end == 0:
            # Try array format
            json_start = output.find("[")
            json_end = output.rfind("]") + 1

        if json_start == -1 or json_end == 0:
            return []

        data = json.loads(output[json_start:json_end])

        # Handle different Mythril output formats
        if isinstance(data, dict):
            if "issues" in data:
                issues = data["issues"]
            elif "success" in data and data.get("issues"):
                issues = data["issues"]
            else:
                issues = []
        elif isinstance(data, list):
            issues = data
        else:
            issues = []

        for item in issues:
            raw_severity = item.get("severity", "Medium").lower()

            # Normalize severity
            if raw_severity in ("high", "critical"):
                normalized_severity = "high"
            elif raw_severity == "medium":
                normalized_severity = "medium"
            else:
                normalized_severity = "low"

            line_num = item.get("lineno", 0)
            if not line_num:
                source_map = item.get("sourceMap", {})
                if isinstance(source_map, dict):
                    line_num = source_map.get("line", 0)

            swc_id = item.get("swc-id", "")

            findings.append(Finding(
                id=swc_id if swc_id else item.get("title", "unknown"),
                title=item.get("title", ""),
                severity=normalized_severity,
                file=item.get("filename", target_file),
                line=line_num,
                end_line=line_num,
                tool="mythril",
                swc=swc_id,
                description=item.get("description", "").strip(),
                raw=item
            ))

    except json.JSONDecodeError:
        pass

    return findings
