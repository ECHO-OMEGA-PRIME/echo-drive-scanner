"""Tests for intelligence scoring module."""

from datetime import datetime, timedelta, timezone

from intelligence.scorer import (
    IntelligenceScorer,
    calculate_importance,
    calculate_overall,
    calculate_quality,
    calculate_risk,
    calculate_sensitivity,
    calculate_staleness,
    calculate_uniqueness,
)
from storage.models import Classification, DuplicateCluster, FileRecord


def _days_ago(days: int) -> str:
    """ISO-8601 UTC timestamp `days` days before now."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _make_file(**kwargs) -> FileRecord:
    """Create a test FileRecord with defaults."""
    defaults = {
        "id": 1,
        "path": "O:\\test\\file.txt",
        "filename": "file.txt",
        "extension": ".txt",
        "size_bytes": 1024,
        "modified_at": _days_ago(1),
        "accessed_at": _days_ago(1),
        "depth": 3,
    }
    defaults.update(kwargs)
    return FileRecord(**defaults)


def _make_classification(**kwargs) -> Classification:
    """Create a test Classification with defaults."""
    defaults = {
        "domain": "PROG",
        "topic": "python",
        "score": 75.0,
        "authority_weight": 80,
        "engine_id": "PROG01",
    }
    defaults.update(kwargs)
    return Classification(**defaults)


def test_quality_empty_file():
    """Empty file should have low quality."""
    f = _make_file(size_bytes=0, content_sample=None)
    score = calculate_quality(f, [])
    assert score >= 0.0
    assert score <= 30.0


def test_quality_rich_file():
    """Rich file with content and classifications should score high."""
    f = _make_file(
        size_bytes=50000,
        content_sample="# Header\n\nThis is a document.\n\n## Section\n\n- Item 1\n- Item 2\n\ndef hello():\n    pass\n" * 10,
        sha256="abc123",
        mime_type="text/plain",
    )
    clss = [_make_classification(score=85.0), _make_classification(score=70.0)]
    score = calculate_quality(f, clss)
    assert score >= 40.0


def test_staleness_fresh():
    """Recently modified file should have low staleness."""
    f = _make_file(modified_at=_days_ago(1), accessed_at=_days_ago(1))
    score = calculate_staleness(f)
    assert score <= 10.0


def test_staleness_ancient():
    """Very old file should have high staleness."""
    f = _make_file(modified_at=_days_ago(6 * 365), accessed_at=_days_ago(6 * 365))
    score = calculate_staleness(f)
    assert score >= 75.0


def test_uniqueness_unique():
    """File with no duplicates should score 100."""
    f = _make_file()
    score = calculate_uniqueness(f, cluster=None, duplicate_count=0)
    assert score == 100.0


def test_uniqueness_many_copies():
    """File with many copies should score low."""
    f = _make_file()
    cluster = DuplicateCluster(file_count=10, cluster_hash="abc")
    score = calculate_uniqueness(f, cluster=cluster, duplicate_count=10)
    assert score <= 15.0


def test_sensitivity_ssn_pattern():
    """File containing SSN pattern should be sensitive."""
    f = _make_file(content_sample="SSN: 123-45-6789")
    score = calculate_sensitivity(f, [])
    assert score >= 80.0


def test_sensitivity_api_key():
    """File with API key pattern should be sensitive."""
    f = _make_file(content_sample="api_key=secret_abc123def456ghi789jkl012mno")
    score = calculate_sensitivity(f, [])
    assert score >= 70.0


def test_sensitivity_clean():
    """File with no sensitive content should score low."""
    f = _make_file(content_sample="Hello world, this is a normal document about cooking.")
    score = calculate_sensitivity(f, [])
    assert score <= 30.0


def test_risk_executable_in_temp():
    """Executable in temp should be high risk."""
    f = _make_file(
        path="C:\\Users\\test\\AppData\\Local\\Temp\\malware.exe",
        extension=".exe",
    )
    score = calculate_risk(f, [], sensitivity=0.0)
    assert score >= 50.0


def test_risk_sensitive_in_shared():
    """Sensitive file in shared folder should be risky."""
    f = _make_file(path="\\\\server\\public\\salaries.xlsx")
    score = calculate_risk(f, [], sensitivity=80.0)
    assert score >= 50.0


def test_overall_score_bounds():
    """Overall score should be between 0 and 100."""
    score = calculate_overall(80, 70, 60, 20, 90, 10)
    assert 0 <= score <= 100


def test_overall_staleness_reduces():
    """Higher staleness should reduce overall score."""
    fresh = calculate_overall(80, 70, 60, 0, 90, 10)
    stale = calculate_overall(80, 70, 60, 90, 90, 10)
    assert fresh > stale


def test_overall_risk_reduces():
    """Higher risk should reduce overall score."""
    safe = calculate_overall(80, 70, 60, 20, 90, 0)
    risky = calculate_overall(80, 70, 60, 20, 90, 90)
    assert safe > risky


def test_scorer_class():
    """IntelligenceScorer produces valid scores."""
    scorer = IntelligenceScorer()
    f = _make_file(content_sample="import os\nprint('hello')")
    clss = [_make_classification()]
    score = scorer.score_file(f, clss, scan_id=1)
    assert 0 <= score.overall_score <= 100
    assert 0 <= score.quality_score <= 100
    assert score.primary_domain == "PROG"
    assert scorer.scored_count == 1
