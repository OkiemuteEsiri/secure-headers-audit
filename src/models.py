from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    headers: Mapping[str, str]
    tls: bool = True
    owner: str = ""

    @classmethod
    def from_dict(cls, row: dict) -> "Target":
        for key in ("name", "url", "headers"):
            if key not in row:
                raise ValueError(f"missing required field: {key}")
        if not isinstance(row["headers"], dict):
            raise ValueError("headers must be an object")
        headers = {str(k).lower(): str(v).strip() for k, v in row["headers"].items()}
        return cls(str(row["name"]), str(row["url"]), headers, bool(row.get("tls", True)), str(row.get("owner", "")))


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    score: int
    target: str
    evidence: str
    rationale: str
    remediation: str
    validation: str
    references: tuple[str, ...]
