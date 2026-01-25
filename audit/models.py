"""
ThirdGen Security Scanner - Data Models
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Finding:
    """Represents a security finding from any tool"""
    id: str
    title: str
    severity: str                       # critical, high, medium, low, informational
    file: str
    line: int
    tool: str
    end_line: int = 0
    swc: str = ""
    description: str = ""
    raw: dict = field(default_factory=dict)
    instances: int = 1

    # AI-enhanced fields
    is_false_positive: bool = False
    ai_confidence: str = ""
    attack_scenario: str = ""
    impact: str = ""
    suggested_fix: str = ""
    ai_analyzed: bool = False

    @property
    def contract_name(self) -> str:
        """Extract contract name from file path"""
        return Path(self.file).stem if self.file else "Unknown"

    @property
    def location(self) -> str:
        """Format file:line location string"""
        if self.line:
            return f"{self.file}:{self.line}"
        return self.file

    @property
    def severity_rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)"""
        ranks = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "informational": 1
        }
        return ranks.get(self.severity.lower(), 0)

    def dedup_key(self) -> str:
        """Generate key for deduplication"""
        return f"{self.file}:{self.line}:{self.id}"


@dataclass
class AuditReport:
    """Aggregated audit report with categorized findings"""
    findings: list[Finding]
    tools_run: list[str] = field(default_factory=list)

    critical: list[Finding] = field(default_factory=list)
    high: list[Finding] = field(default_factory=list)
    medium: list[Finding] = field(default_factory=list)
    low: list[Finding] = field(default_factory=list)
    informational: list[Finding] = field(default_factory=list)

    raw_count: int = 0
    false_positive_count: int = 0

    def __post_init__(self):
        self.raw_count = len(self.findings)
        self._categorize()

    def _categorize(self):
        """Categorize findings by severity"""
        for finding in self.findings:
            if finding.is_false_positive:
                self.false_positive_count += 1
                continue

            sev = finding.severity.lower()
            if sev == "critical":
                self.critical.append(finding)
            elif sev == "high":
                self.high.append(finding)
            elif sev == "medium":
                self.medium.append(finding)
            elif sev == "low":
                self.low.append(finding)
            else:
                self.informational.append(finding)

    @property
    def total(self) -> int:
        """Total confirmed findings (excluding false positives)"""
        return len(self.critical) + len(self.high) + len(self.medium) + len(self.low) + len(self.informational)

    @property
    def has_critical(self) -> bool:
        return len(self.critical) > 0

    @property
    def has_high(self) -> bool:
        return len(self.high) > 0
