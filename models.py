from dataclasses import dataclass
from typing import Optional, List


@dataclass
class VulnResult:
    package: str
    version: str
    cve_id: str
    cvss_score: Optional[float] = None
    severity: str = "UNKNOWN"
    summary: str = ""
    fix_version: str = ""
    url: str = ""
    source: str = ""
    references: Optional[List[str]] = None

    def __post_init__(self):
        if self.cvss_score is not None and self.severity == "UNKNOWN":
            self.severity = self._score_to_severity(self.cvss_score)
        if self.cve_id and not self.url:
            if self.cve_id.startswith("CVE-"):
                self.url = f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
        if self.references is None:
            self.references = []

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "UNKNOWN"

    @property
    def severity_short(self) -> str:
        return self.severity[0] if self.severity != "UNKNOWN" else "?"

    @property
    def cvss_display(self) -> str:
        if self.cvss_score is not None:
            return f"{self.cvss_score} {self.severity_short}"
        return "N/A"
