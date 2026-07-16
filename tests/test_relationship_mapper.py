"""Tests for relationship mapping module."""

from intelligence.relationship_mapper import VERSION_PATTERNS, RelationshipMapper
from storage.models import Classification, FileRecord, RelationshipType


def _make_file(id: int, filename: str, **kwargs) -> FileRecord:
    defaults = {
        "path": f"O:\\test\\{filename}",
        "filename": filename,
        "size_bytes": 1024,
        "modified_at": "2026-02-27T00:00:00Z",
        "parent_dir": "O:\\test",
        "depth": 2,
    }
    defaults.update(kwargs)
    return FileRecord(id=id, **defaults)


def test_hash_duplicates():
    """Files with same SHA-256 detected as duplicates."""
    files = [
        _make_file(1, "a.txt", sha256="abc123"),
        _make_file(2, "b.txt", sha256="abc123"),
    ]
    mapper = RelationshipMapper()
    rels = mapper.detect_all(files, {}, scan_id=1)
    dup_rels = [r for r in rels if r.relationship_type == RelationshipType.DUPLICATES.value]
    assert len(dup_rels) == 1
    assert dup_rels[0].confidence == 1.0


def test_version_detection():
    """Versioned files detected from naming pattern."""
    files = [
        _make_file(1, "report_v1.docx", modified_at="2025-01-01T00:00:00Z"),
        _make_file(2, "report_v2.docx", modified_at="2026-01-01T00:00:00Z"),
    ]
    mapper = RelationshipMapper()
    rels = mapper.detect_all(files, {}, scan_id=1)
    ver_rels = [r for r in rels if r.relationship_type == RelationshipType.VERSIONED.value]
    assert len(ver_rels) >= 1


def test_content_references():
    """File referencing another by name detected."""
    files = [
        _make_file(1, "readme.txt", content_sample="See contract_final.pdf for details"),
        _make_file(2, "contract_final.pdf"),
    ]
    mapper = RelationshipMapper()
    rels = mapper.detect_all(files, {}, scan_id=1)
    ref_rels = [r for r in rels if r.relationship_type == RelationshipType.REFERENCES.value]
    assert len(ref_rels) >= 1


def test_code_dependencies():
    """Python import detected as dependency."""
    files = [
        _make_file(1, "main.py", extension=".py", content_sample="from utils import helper"),
        _make_file(2, "utils.py", extension=".py"),
    ]
    mapper = RelationshipMapper()
    rels = mapper.detect_all(files, {}, scan_id=1)
    dep_rels = [r for r in rels if r.relationship_type == RelationshipType.DEPENDS_ON.value]
    assert len(dep_rels) >= 1


def test_co_classified():
    """Files sharing 3+ classification topics detected as co-classified."""
    files = [
        _make_file(1, "a.py"),
        _make_file(2, "b.py"),
    ]
    classifications = {
        1: [
            Classification(domain="PROG", topic="python", score=80),
            Classification(domain="PROG", topic="testing", score=70),
            Classification(domain="CYBER", topic="security", score=60),
        ],
        2: [
            Classification(domain="PROG", topic="python", score=75),
            Classification(domain="PROG", topic="testing", score=65),
            Classification(domain="CYBER", topic="security", score=55),
        ],
    }
    mapper = RelationshipMapper()
    rels = mapper.detect_all(files, classifications, scan_id=1)
    cc_rels = [r for r in rels if r.relationship_type == RelationshipType.CO_CLASSIFIED.value]
    assert len(cc_rels) >= 1


def test_version_patterns():
    """VERSION_PATTERNS match expected filenames."""
    test_cases = [
        ("report_v1.0.docx", True),
        ("data_v2.docx", True),
        ("backup_20260227.csv", True),
        ("notes_copy.txt", True),
        ("file (1).txt", True),
        ("readme_rev3.md", True),
        ("normal.txt", False),
    ]
    for filename, should_match in test_cases:
        matched = any(p.match(filename) for p in VERSION_PATTERNS)
        assert matched == should_match, (
            f"Pattern match failed for {filename}: expected {should_match}"
        )


def test_stats():
    """Stats are correctly accumulated."""
    files = [
        _make_file(1, "a.txt", sha256="same"),
        _make_file(2, "b.txt", sha256="same"),
    ]
    mapper = RelationshipMapper()
    mapper.detect_all(files, {}, scan_id=1)
    stats = mapper.get_stats()
    assert stats["total_relationships"] >= 1
    assert stats["duplicates"] >= 1
