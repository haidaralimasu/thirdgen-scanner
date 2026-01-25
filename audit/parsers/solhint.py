"""
Solhint output parser
"""

import json
from typing import Any

from ..models import Finding


def parse_solhint(output: str, severity_map: dict[str, str], exclude_paths: list[str]) -> list[Finding]:
    """Parse Solhint JSON output"""
    if not output:
        return []

    findings = []

    try:
        data = json.loads(output.strip())

        for file_result in data:
            file_path = file_result.get("filePath", "")

            # Skip excluded paths
            if any(exc in file_path for exc in exclude_paths):
                continue

            for msg in file_result.get("messages", []):
                # Solhint severity: 1 = warning, 2 = error
                raw_severity = msg.get("severity", 1)
                if raw_severity == 2:
                    normalized_severity = "medium"
                else:
                    normalized_severity = "low"

                rule_id = msg.get("ruleId", "unknown")

                findings.append(Finding(
                    id=rule_id,
                    title=rule_id.replace("-", " ").title(),
                    severity=normalized_severity,
                    file=file_path,
                    line=msg.get("line", 0),
                    end_line=msg.get("endLine", msg.get("line", 0)),
                    tool="solhint",
                    description=msg.get("message", "").strip(),
                    raw=msg
                ))

    except json.JSONDecodeError:
        pass

    return findings
