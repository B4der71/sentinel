from __future__ import annotations

import hashlib

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)


class Confidence(str, Enum):
    TENTATIVE = "Tentative"
    FIRM = "Firm"
    CONFIRMED = "Confirmed"

    @property
    def score(self) -> float:
        return {
            "Tentative": 0.4,
            "Firm": 0.7,
            "Confirmed": 1.0,
        }[self.value]


@dataclass
class Evidence:
    description: str
    request: str | None = None
    response_excerpt: str | None = None
    screenshot_path: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InputType(str, Enum):
    TEXT = "text"
    HIDDEN = "hidden"
    PASSWORD = "password"
    FILE = "file"
    SUBMIT = "submit"
    OTHER = "other"


@dataclass(frozen=True)
class FormInput:
    name: str
    input_type: InputType = InputType.TEXT
    value: str = ""

    @property
    def is_fuzzable(self) -> bool:
        return self.input_type is not InputType.SUBMIT


@dataclass
class Form:
    url: str
    action: str
    method: str = "GET"
    inputs: list[FormInput] = field(default_factory=list)
    is_upload: bool = False
    source: str = "html"

    @property
    def fuzzable_params(self) -> list[str]:
        return [
            i.name
            for i in self.inputs
            if i.is_fuzzable and i.name
        ]

    def baseline_data(
        self,
        marker: str = "1",
    ) -> dict[str, str]:
        data = {}

        for i in self.inputs:
            data[i.name] = i.value or marker

        return data


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    depth: int = 0


@dataclass
class Finding:
    name: str
    plugin: str
    severity: Severity
    confidence: Confidence
    url: str

    cwe: str | None = None
    parameter: str | None = None
    method: str = "GET"
    payload: str | None = None

    database: str | None = None
    techniques: list[str] = field(default_factory=list)

    cvss: float | None = None

    description: str = ""
    remediation: str = ""

    reproduction: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    discovered_at: str = field(
        default_factory=lambda:
        datetime.now(timezone.utc).isoformat()
    )

    def dedup_key(self) -> str:
        raw = (
            f"{self.plugin}|"
            f"{self.name}|"
            f"{self.method}|"
            f"{self.url}|"
            f"{self.parameter}"
        )

        return hashlib.sha256(
            raw.encode()
        ).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)

        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["confidence_score"] = self.confidence.score
        d["dedup_key"] = self.dedup_key()

        return d
