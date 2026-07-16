"""Tests for recommendation engine."""

from intelligence.recommender import RecommendationEngine
from storage.models import (
    Classification,
    DuplicateCluster,
    DuplicateMember,
    FileRecord,
    IntelligenceScore,
)


def _make_file(id: int, **kwargs) -> FileRecord:
    defaults = {
        "path": f"O:\\test\\file_{id}.txt",
        "filename": f"file_{id}.txt",
        "extension": ".txt",
        "size_bytes": 1024,
        "depth": 3,
    }
    defaults.update(kwargs)
    return FileRecord(id=id, **defaults)


def _make_score(file_id: int, **kwargs) -> IntelligenceScore:
    defaults = {
        "file_id": file_id,
        "scan_id": 1,
        "overall_score": 50.0,
        "quality_score": 50.0,
        "importance_score": 50.0,
        "sensitivity_score": 20.0,
        "staleness_score": 30.0,
        "uniqueness_score": 80.0,
        "risk_score": 20.0,
        "primary_domain": "PROG",
    }
    defaults.update(kwargs)
    return IntelligenceScore(**defaults)


def test_archive_recommendation():
    """Stale + low importance files trigger archive recommendation."""
    files = [_make_file(1), _make_file(2), _make_file(3)]
    scores = {
        1: _make_score(1, staleness_score=90, importance_score=10),
        2: _make_score(2, staleness_score=85, importance_score=15),
        3: _make_score(3, staleness_score=20, importance_score=80),
    }
    engine = RecommendationEngine()
    recs = engine.generate_all(files, scores, {}, [], [], scan_id=1)
    archive_recs = [r for r in recs if r.category == "archive"]
    assert len(archive_recs) >= 1
    assert archive_recs[0].affected_count == 2


def test_secure_recommendation():
    """Sensitive files outside secure locations trigger secure recommendation."""
    files = [
        _make_file(1, path="C:\\Users\\test\\Downloads\\taxes.xlsx"),
        _make_file(2, path="O:\\vault\\secure\\taxes.xlsx"),
    ]
    scores = {
        1: _make_score(1, sensitivity_score=85),
        2: _make_score(2, sensitivity_score=85),
    }
    engine = RecommendationEngine()
    recs = engine.generate_all(files, scores, {}, [], [], scan_id=1)
    secure_recs = [r for r in recs if r.category == "secure"]
    assert len(secure_recs) >= 1
    # Only file 1 (in Downloads) should be flagged, not file 2 (in vault)
    assert secure_recs[0].affected_count == 1


def test_review_high_risk():
    """High risk files trigger review recommendation."""
    files = [_make_file(1)]
    scores = {1: _make_score(1, risk_score=80)}
    engine = RecommendationEngine()
    recs = engine.generate_all(files, scores, {}, [], [], scan_id=1)
    review_recs = [r for r in recs if r.category == "review"]
    assert len(review_recs) >= 1


def test_alert_cyber():
    """CYBER-classified files trigger alert."""
    files = [_make_file(1)]
    classifications = {
        1: [Classification(domain="CYBER", topic="malware", score=85.0)],
    }
    engine = RecommendationEngine()
    recs = engine.generate_all(files, {}, classifications, [], [], scan_id=1)
    alert_recs = [r for r in recs if r.category == "alert"]
    assert len(alert_recs) >= 1
    assert alert_recs[0].severity == "critical"


def test_delete_duplicates():
    """Duplicate clusters trigger delete recommendation."""
    files = [_make_file(1), _make_file(2)]
    clusters = [
        DuplicateCluster(
            id=1,
            cluster_hash="abc",
            file_count=3,
            total_wasted_bytes=2048,
            best_file_id=1,
            members=[
                DuplicateMember(file_id=1, is_keeper=1, file_path="/a.txt", size_bytes=1024),
                DuplicateMember(file_id=2, is_keeper=0, file_path="/b.txt", size_bytes=1024),
                DuplicateMember(file_id=3, is_keeper=0, file_path="/c.txt", size_bytes=1024),
            ],
        ),
    ]
    engine = RecommendationEngine()
    recs = engine.generate_all(files, {}, {}, [], clusters, scan_id=1)
    delete_recs = [r for r in recs if r.category == "delete"]
    assert len(delete_recs) >= 1


def test_severity_ordering():
    """Recommendations should be sorted by severity (critical first)."""
    files = [_make_file(1), _make_file(2)]
    scores = {
        1: _make_score(1, risk_score=80, staleness_score=90, importance_score=10),
        2: _make_score(2, risk_score=80, staleness_score=90, importance_score=10),
    }
    classifications = {
        1: [Classification(domain="CYBER", topic="malware", score=85.0)],
    }
    engine = RecommendationEngine()
    recs = engine.generate_all(files, scores, classifications, [], [], scan_id=1)
    if len(recs) >= 2:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(recs) - 1):
            assert severity_order.get(recs[i].severity, 5) <= severity_order.get(
                recs[i + 1].severity, 5
            )


def test_stats():
    """Engine stats are calculated correctly."""
    engine = RecommendationEngine()
    engine.generate_all([], {}, {}, [], [], scan_id=1)
    stats = engine.get_stats()
    assert stats["total_recommendations"] == 0
    assert stats["total_affected_files"] == 0
