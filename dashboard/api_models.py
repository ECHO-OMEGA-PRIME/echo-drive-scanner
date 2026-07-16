"""Strict API contracts for the Intelligent Drive Scanner service."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScanProfile = Literal[
    "INTELLIGENCE",
    "INTEL_FAST",
    "INTEL_SECURITY",
    "INTEL_COMPLIANCE",
    "INTEL_OILFIELD",
    "DEDUP",
]


class StrictModel(BaseModel):
    """Reject unknown fields at every mutation boundary."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScanStartRequest(StrictModel):
    """Validated request to start one scanner run."""

    paths: list[str] = Field(min_length=1, max_length=32)
    profile: ScanProfile = "INTEL_FAST"

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in value:
            path = raw.strip()
            if not path:
                raise ValueError("scan paths cannot be empty")
            if len(path) > 1024:
                raise ValueError("scan path exceeds 1024 characters")
            key = path.casefold()
            if key not in seen:
                normalized.append(path)
                seen.add(key)
        if not normalized:
            raise ValueError("at least one unique scan path is required")
        return normalized


class ScanCancelRequest(StrictModel):
    """Auditable cancellation request."""

    reason: str = Field(min_length=20, max_length=500)


class RecommendationExecuteRequest(StrictModel):
    """Explicit confirmation for the disabled-by-default file-action lane."""

    confirm: int


class ScanAcceptedResponse(BaseModel):
    api_version: str = "2.1"
    status: Literal["accepted"] = "accepted"
    scan_id: int
    run_id: str
    profile: ScanProfile
    normalized_roots: list[str]
    status_url: str
    stages_url: str
    accepted_at: str


class ErrorResponse(BaseModel):
    api_version: str = "2.1"
    error: str
    detail: str
    request_id: str | None = None
