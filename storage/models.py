"""Intelligent Drive Scanner v2.0 â€” Pydantic Data Models.

All data models for file records, classifications, scores, relationships,
duplicate clusters, recommendations, scan results, and domain statistics.
Strict validation, typed fields, ISO-8601 timestamps.
"""

from __future__ import annotations

from enum import Enum, StrEnum
from typing import Any

from pydantic import BaseModel, Field

# â”€â”€ Enums â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ConfidenceLevel(StrEnum):
    DEFENSIBLE = "DEFENSIBLE"
    AGGRESSIVE = "AGGRESSIVE"
    DISCLOSURE = "DISCLOSURE"
    HIGH_RISK = "HIGH_RISK"
    UNKNOWN = "UNKNOWN"


class QueryMode(StrEnum):
    FAST = "FAST"
    DEFENSE = "DEFENSE"
    MEMO = "MEMO"


class RelationshipType(StrEnum):
    DUPLICATES = "duplicates"
    NEAR_DUPLICATES = "near_duplicates"
    REFERENCES = "references"
    VERSIONED = "versioned"
    SUPPLEMENTS = "supplements"
    CONTRADICTS = "contradicts"
    SUPERSEDES = "supersedes"
    DEPENDS_ON = "depends_on"
    PARENT_OF = "parent_of"
    CO_CLASSIFIED = "co_classified"


class RecommendationCategory(StrEnum):
    ARCHIVE = "archive"
    DELETE = "delete"
    SECURE = "secure"
    BACKUP = "backup"
    DEDUPLICATE = "deduplicate"
    ORGANIZE = "organize"
    REVIEW = "review"
    ALERT = "alert"
    ENCRYPT = "encrypt"
    UPDATE = "update"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class KeeperStrategy(StrEnum):
    KEEP_NEWEST = "keep_newest"
    KEEP_LARGEST = "keep_largest"
    KEEP_SHALLOWEST = "keep_shallowest"
    KEEP_MOST_ACCESSED = "keep_most_accessed"
    KEEP_HIGHEST_QUALITY = "keep_highest_quality"
    KEEP_IN_DOMAIN_FOLDER = "keep_in_domain_folder"


class ClassificationTier(int, Enum):
    TIER1_FAST = 1
    TIER2_EXPLORE = 2
    TIER3_DEEP = 3


# â”€â”€ File Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class FileSample(BaseModel):
    """Output of content sampling for a single file."""

    path: str
    filename: str
    extension: str
    size_bytes: int
    mime_type: str
    file_signature: str = ""
    content_sample: str | None = None
    keywords: list[str] = Field(default_factory=list)
    detected_domain: str = "UNKNOWN"
    domain_confidence: float = 0.0
    is_binary: bool = False
    sha256: str = ""
    xxhash: str = ""
    extraction_ms: float = 0.0


class FileRecord(BaseModel):
    """Full file record stored in the intelligence database."""

    id: int | None = None
    path: str
    filename: str
    extension: str = ""
    size_bytes: int = 0
    created_at: str | None = None
    modified_at: str | None = None
    accessed_at: str | None = None
    sha256: str | None = None
    xxhash: str | None = None
    mime_type: str | None = None
    drive: str = ""
    parent_dir: str = ""
    depth: int = 0
    is_binary: int = 0
    content_sample: str | None = None
    file_signature: str | None = None
    detected_domain: str = "UNKNOWN"
    domain_confidence: float = 0.0
    keywords: list[str] = Field(default_factory=list)
    scan_id: int = 0
    first_seen_scan_id: int | None = None
    last_modified_scan_id: int | None = None


# â”€â”€ Classification Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class Classification(BaseModel):
    """A single engine classification result for a file."""

    id: int | None = None
    file_id: int = 0
    scan_id: int = 0
    engine_id: str = ""
    domain: str = ""
    domain_label: str | None = None
    topic: str = ""
    conclusion: str | None = None
    confidence: str = ConfidenceLevel.UNKNOWN.value
    authority_weight: int = 0
    score: float = 0.0
    mode: str = QueryMode.FAST.value
    response_ms: int | None = None
    determinism_hash: str | None = None
    classified_at: str = ""


class EngineResult(BaseModel):
    """Response from a single engine query."""

    engine_id: str = ""
    domain: str = ""
    domain_label: str = ""
    topic: str = ""
    conclusion: str = ""
    confidence: str = ConfidenceLevel.UNKNOWN.value
    authority_weight: int = 0
    score: float = 0.0
    mode: str = QueryMode.FAST.value
    determinism_hash: str = ""
    reasoning: str | None = None
    authorities: list[str] = Field(default_factory=list)
    response_ms: int = 0
    cached: bool = False


class DomainResult(BaseModel):
    """Response from a domain-level query (may return multiple engines)."""

    domain: str = ""
    domain_label: str = ""
    results: list[EngineResult] = Field(default_factory=list)
    total_engines: int = 0
    response_ms: int = 0


class CrossDomainResult(BaseModel):
    """Response from a cross-domain query."""

    query: str = ""
    results: list[EngineResult] = Field(default_factory=list)
    domains_searched: int = 0
    response_ms: int = 0


class ClassificationResult(BaseModel):
    """Full classification output for a single file."""

    file_path: str
    tier: ClassificationTier = ClassificationTier.TIER1_FAST
    classifications: list[Classification] = Field(default_factory=list)
    primary_domain: str = "UNKNOWN"
    primary_engine: str = ""
    domain_distribution: dict[str, float] = Field(default_factory=dict)
    total_ms: int = 0


# â”€â”€ Scoring Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class IntelligenceScore(BaseModel):
    """Composite intelligence scores for a single file."""

    id: int | None = None
    file_id: int = 0
    scan_id: int = 0
    overall_score: float = 0.0
    quality_score: float = 0.0
    importance_score: float = 0.0
    sensitivity_score: float = 0.0
    staleness_score: float = 0.0
    uniqueness_score: float = 0.0
    risk_score: float = 0.0
    primary_domain: str | None = None
    primary_engine: str | None = None
    domain_distribution: str | None = None
    classification_count: int = 0
    scored_at: str = ""
    score_version: str = "2.0"


# â”€â”€ Relationship Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class Relationship(BaseModel):
    """A cross-file relationship."""

    id: int | None = None
    source_file_id: int = 0
    target_file_id: int = 0
    relationship_type: str = RelationshipType.REFERENCES.value
    confidence: float = 0.0
    evidence: str | None = None
    detected_at: str = ""
    scan_id: int = 0


# â”€â”€ Deduplication Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class DuplicateCluster(BaseModel):
    """A group of duplicate files."""

    id: int | None = None
    cluster_hash: str = ""
    file_count: int = 0
    total_wasted_bytes: int = 0
    best_file_id: int | None = None
    strategy: str = KeeperStrategy.KEEP_HIGHEST_QUALITY.value
    created_at: str = ""
    members: list[DuplicateMember] = Field(default_factory=list)


class DuplicateMember(BaseModel):
    """A member of a duplicate cluster."""

    cluster_id: int = 0
    file_id: int = 0
    is_keeper: int = 0
    file_path: str = ""
    size_bytes: int = 0


# â”€â”€ Recommendation Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class Recommendation(BaseModel):
    """An actionable recommendation generated from intelligence analysis."""

    id: int | None = None
    scan_id: int = 0
    category: str = RecommendationCategory.REVIEW.value
    severity: str = Severity.MEDIUM.value
    title: str = ""
    description: str = ""
    affected_files: str | None = None
    affected_count: int = 1
    estimated_impact: str | None = None
    action_command: str | None = None
    auto_executable: bool = False
    requires_review: bool = True
    status: str = "pending"
    created_at: str = ""


# â”€â”€ Scan & Stats Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class ScanRecord(BaseModel):
    """A single scan run."""

    id: int | None = None
    started_at: str = ""
    completed_at: str | None = None
    drives: str = "[]"
    profile: str = "INTELLIGENCE"
    total_files: int = 0
    total_size_bytes: int = 0
    files_classified: int = 0
    files_skipped: int = 0
    duration_seconds: float | None = None
    status: str = ScanStatus.RUNNING.value
    config: str | None = None


class DomainStats(BaseModel):
    """Aggregated statistics for a single domain in a scan."""

    id: int | None = None
    scan_id: int = 0
    domain: str = ""
    domain_label: str | None = None
    file_count: int = 0
    total_size_bytes: int = 0
    avg_score: float | None = None
    avg_confidence: str | None = None
    top_topics: str | None = None


class ScanSummary(BaseModel):
    """High-level summary of a completed scan."""

    scan_id: int
    status: str
    total_files: int = 0
    total_size_bytes: int = 0
    files_classified: int = 0
    duration_seconds: float = 0.0
    domain_distribution: dict[str, int] = Field(default_factory=dict)
    top_domains: list[DomainStats] = Field(default_factory=list)
    recommendation_count: int = 0
    duplicate_clusters: int = 0
    wasted_bytes: int = 0
    avg_quality: float = 0.0
    avg_importance: float = 0.0
    high_risk_count: int = 0
    sensitive_count: int = 0


# â”€â”€ Dashboard / API Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class FileDetail(BaseModel):
    """Full file detail with classifications and scores for the API."""

    file: FileRecord
    score: IntelligenceScore | None = None
    classifications: list[Classification] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


class ScanProgress(BaseModel):
    """Real-time scan progress for WebSocket updates."""

    scan_id: int
    phase: str = "discovering"
    total_files: int = 0
    processed_files: int = 0
    classified_files: int = 0
    current_file: str = ""
    elapsed_seconds: float = 0.0
    eta_seconds: float | None = None
    api_calls: int = 0
    cache_hits: int = 0
    errors: int = 0
    throughput_files_per_min: float = 0.0


class ScoreDistribution(BaseModel):
    """Score distribution data for histograms."""

    dimension: str
    buckets: list[dict[str, Any]] = Field(default_factory=list)
    mean: float = 0.0
    median: float = 0.0
    p90: float = 0.0
    p99: float = 0.0


class DomainSunburstNode(BaseModel):
    """Node in the domain sunburst chart."""

    name: str
    value: int = 0
    children: list[DomainSunburstNode] = Field(default_factory=list)
    color: str | None = None
