"""Tests for Pydantic data models."""

from storage.models import (
    Classification,
    ClassificationTier,
    ConfidenceLevel,
    DuplicateCluster,
    DuplicateMember,
    FileRecord,
    FileSample,
    IntelligenceScore,
    KeeperStrategy,
    QueryMode,
    RecommendationCategory,
    RelationshipType,
    ScanProgress,
    ScanStatus,
)


def test_file_record_defaults():
    """FileRecord should have sensible defaults."""
    f = FileRecord(path="/tmp/test.txt", filename="test.txt")
    assert f.extension == ""
    assert f.size_bytes == 0
    assert f.depth == 0
    assert f.is_binary == 0
    assert f.id is None


def test_file_record_full():
    """FileRecord with all fields populated."""
    f = FileRecord(
        id=42,
        path="O:\\ECHO\\test.py",
        filename="test.py",
        extension=".py",
        size_bytes=1024,
        created_at="2026-01-01T00:00:00Z",
        modified_at="2026-02-01T00:00:00Z",
        accessed_at="2026-02-27T00:00:00Z",
        sha256="abc123",
        mime_type="text/x-python",
        drive="O:",
        parent_dir="O:\\ECHO",
        depth=2,
        is_binary=0,
        content_sample="import os\n",
        scan_id=1,
    )
    assert f.id == 42
    assert f.extension == ".py"
    assert f.size_bytes == 1024


def test_classification_defaults():
    """Classification has correct defaults."""
    c = Classification()
    assert c.confidence == ConfidenceLevel.UNKNOWN.value
    assert c.mode == QueryMode.FAST.value
    assert c.score == 0.0


def test_intelligence_score_defaults():
    """IntelligenceScore starts at zero."""
    s = IntelligenceScore()
    assert s.overall_score == 0.0
    assert s.quality_score == 0.0
    assert s.risk_score == 0.0
    assert s.score_version == "2.0"


def test_relationship_type_enum():
    """RelationshipType enum values match expected strings."""
    assert RelationshipType.DUPLICATES.value == "duplicates"
    assert RelationshipType.DEPENDS_ON.value == "depends_on"
    assert RelationshipType.CO_CLASSIFIED.value == "co_classified"
    assert RelationshipType.SUPERSEDES.value == "supersedes"


def test_recommendation_categories():
    """All recommendation categories are defined."""
    cats = [e.value for e in RecommendationCategory]
    assert "archive" in cats
    assert "delete" in cats
    assert "secure" in cats
    assert "encrypt" in cats
    assert "alert" in cats
    assert "organize" in cats


def test_scan_status_enum():
    """ScanStatus enum covers all states."""
    assert ScanStatus.RUNNING.value == "running"
    assert ScanStatus.COMPLETED.value == "completed"
    assert ScanStatus.FAILED.value == "failed"
    assert ScanStatus.CANCELLED.value == "cancelled"


def test_duplicate_cluster_with_members():
    """DuplicateCluster contains members."""
    cluster = DuplicateCluster(
        cluster_hash="abc123",
        file_count=3,
        total_wasted_bytes=2048,
        best_file_id=1,
        strategy=KeeperStrategy.KEEP_HIGHEST_QUALITY.value,
        created_at="2026-02-27T00:00:00Z",
        members=[
            DuplicateMember(file_id=1, is_keeper=1, file_path="/a.txt", size_bytes=1024),
            DuplicateMember(file_id=2, is_keeper=0, file_path="/b.txt", size_bytes=1024),
            DuplicateMember(file_id=3, is_keeper=0, file_path="/c.txt", size_bytes=1024),
        ],
    )
    assert len(cluster.members) == 3
    assert cluster.members[0].is_keeper == 1


def test_scan_progress():
    """ScanProgress model."""
    p = ScanProgress(scan_id=1, phase="classifying", total_files=1000, processed_files=500)
    assert p.scan_id == 1
    assert p.phase == "classifying"


def test_classification_tier():
    """Classification tiers are integers."""
    assert ClassificationTier.TIER1_FAST.value == 1
    assert ClassificationTier.TIER2_EXPLORE.value == 2
    assert ClassificationTier.TIER3_DEEP.value == 3


def test_file_sample():
    """FileSample model with content."""
    sample = FileSample(
        path="/tmp/test.md",
        filename="test.md",
        extension=".md",
        size_bytes=512,
        mime_type="text/markdown",
        content_sample="# Hello World\n\nThis is a test.",
        keywords=["hello", "world", "test"],
        detected_domain="PROG",
        domain_confidence=0.7,
    )
    assert sample.detected_domain == "PROG"
    assert len(sample.keywords) == 3
