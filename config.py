"""Intelligent Drive Scanner v2.0 — Configuration & Constants."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
# DRIVESCAN_DB_PATH lets deploy/smoke environments point at an alternate db.
DB_PATH = Path(os.environ.get("DRIVESCAN_DB_PATH") or (PROJECT_ROOT / "intelligence.db"))
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

EXISTING_SCANNER = Path(r"O:\ECHO_OMEGA_PRIME\CORE\system_scanner.py")

# ── Cloud Endpoints ──────────────────────────────────────────────────────────
# All external endpoints and credentials come from the environment. An empty
# value means "not configured": callers must skip the network call entirely
# (log a single INFO line) rather than error.

ENGINE_API_KEY: str = os.environ.get("DRIVESCAN_ENGINE_API_KEY", "")
ENGINE_RUNTIME_URL = os.environ.get("DRIVESCAN_ENGINE_URL", "")
SHARED_BRAIN_URL = os.environ.get("DRIVESCAN_SHARED_BRAIN_URL", "")
GRAPH_RAG_URL = os.environ.get("DRIVESCAN_GRAPH_RAG_URL", "")
KNOWLEDGE_FORGE_URL = os.environ.get("DRIVESCAN_KNOWLEDGE_FORGE_URL", "")
AI_ORCHESTRATOR_URL = os.environ.get("DRIVESCAN_AI_ORCHESTRATOR_URL", "")
DRIVE_INTELLIGENCE_URL = os.environ.get("DRIVESCAN_WORKER_URL", "")

# ── Engine Runtime API ───────────────────────────────────────────────────────

RUNTIME_ENDPOINTS = {
    "engine_query": "/engine/{engine_id}/query",
    "query_engine": "/engine/{engine_id}/query",
    "domain_query": "/domain/{domain}/query",
    "query_domain": "/domain/{domain}/query",
    "cross_domain": "/cross-domain/query",
    "global_search": "/search",
    "search": "/search",
    "list_domains": "/domains",
    "domains": "/domains",
    "health": "/health",
    "stats": "/stats",
}

MAX_CONCURRENT_REQUESTS = 20
MAX_REQUESTS_PER_MINUTE = 500
CACHE_TTL_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 3
# Number of attempts per engine request. Must be >= 1 or the request loop
# never executes (range(0)). Overridable via DRIVESCAN_ENGINE_RETRIES.
MAX_RETRIES = int(os.environ.get("DRIVESCAN_ENGINE_RETRIES", "2"))
RETRY_BACKOFF_BASE = 0.5

# ── Content Sampling ─────────────────────────────────────────────────────────

SAMPLE_SIZE = 2048
SIGNATURE_SIZE = 16
KEYWORD_LIMIT = 50

# ── Classification ───────────────────────────────────────────────────────────

BATCH_SIZE = 100
CONCURRENT_BATCHES = 5
TIER1_CONCURRENCY = 20
TIER2_CONCURRENCY = 10
TIER3_CONCURRENCY = 3
TIER2_CONFIDENCE_THRESHOLD = 0.5
TIER3_SIZE_THRESHOLD = 51200  # 50KB

# ── Scoring Weights ──────────────────────────────────────────────────────────

QUALITY_WEIGHTS = {
    "content_length": 0.15,
    "keyword_density": 0.15,
    "structure_score": 0.15,
    "engine_match_count": 0.20,
    "engine_match_score": 0.20,
    "completeness": 0.15,
}

IMPORTANCE_WEIGHTS = {
    "domain_criticality": 0.25,
    "authority_weight": 0.20,
    "access_recency": 0.15,
    "reference_count": 0.15,
    "uniqueness": 0.15,
    "path_depth": 0.10,
}

OVERALL_WEIGHTS = {
    "quality": 0.20,
    "importance": 0.25,
    "sensitivity": 0.15,
    "staleness": -0.10,
    "uniqueness": 0.15,
    "risk": -0.15,
}

DOMAIN_CRITICALITY = {
    "CYBER": 90,
    "FIN": 85,
    "LG": 80,
    "TAX": 80,
    "MED": 85,
    "CRYPTO": 70,
    "FOREN": 75,
    "LM": 70,
    "DRL": 65,
    "FRAC": 65,
    "PROD": 60,
    "OFE": 55,
    "ENV": 65,
    "NUC": 90,
    "AERO": 75,
    "MARINE": 60,
    "EE": 55,
    "MECH": 50,
    "CONST": 50,
    "AUTO": 50,
    "CHEM": 60,
    "INS": 60,
    "RE": 55,
    "ACCT": 70,
    "FOOD": 40,
    "PROG": 45,
}

DOMAIN_SENSITIVITY = {
    "MED": 40,
    "FIN": 35,
    "TAX": 35,
    "LG": 30,
    "CYBER": 25,
    "CRYPTO": 30,
    "FOREN": 25,
    "INS": 20,
}

# ── Deduplication ────────────────────────────────────────────────────────────

DEFAULT_KEEPER_STRATEGY = "keep_highest_quality"
FALLBACK_KEEPER_STRATEGIES = ["keep_newest", "keep_shallowest"]

# ── Dashboard ────────────────────────────────────────────────────────────────

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8460

# ── Scan Profiles ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "INTELLIGENCE": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": True,
        "relationships": True,
        "recommendations": True,
    },
    "INTEL_FAST": {
        "intelligence": True,
        "tier1": True,
        "tier2": False,
        "tier3": False,
        "dedup": True,
        "relationships": False,
        "recommendations": True,
    },
    "INTEL_SECURITY": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": False,
        "recommendations": True,
        "domains": ["CYBER", "FOREN"],
    },
    "INTEL_COMPLIANCE": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": True,
        "recommendations": True,
        "domains": ["FIN", "LG", "MED", "TAX", "ACCT", "INS"],
    },
    "INTEL_OILFIELD": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": True,
        "recommendations": True,
        "domains": ["DRL", "FRAC", "PROD", "OFE", "LM", "ENV"],
    },
    "DEDUP": {
        "intelligence": False,
        "tier1": False,
        "tier2": False,
        "tier3": False,
        "dedup": True,
        "relationships": False,
        "recommendations": True,
    },
}

# ── File Signatures (Magic Bytes) ────────────────────────────────────────────

FILE_SIGNATURES: dict[str, str] = {
    "25504446": "application/pdf",
    "504b0304": "application/zip",
    "d0cf11e0": "application/msword",
    "89504e47": "image/png",
    "ffd8ff": "image/jpeg",
    "7f454c46": "application/x-elf",
    "4d5a": "application/x-dosexec",
    "53514c69": "application/x-sqlite3",
    "47494638": "image/gif",
    "424d": "image/bmp",
    "52494646": "audio/wav",
    "494433": "audio/mpeg",
    "fffb": "audio/mpeg",
    "1a45dfa3": "video/webm",
    "0000001866747970": "video/mp4",
    "000001ba": "video/mpeg",
    "000001b3": "video/mpeg",
    "1f8b": "application/gzip",
    "425a68": "application/x-bzip2",
    "fd377a585a00": "application/x-xz",
    "377abcaf271c": "application/x-7z-compressed",
    "52617221": "application/x-rar",
    "4f676753": "audio/ogg",
    "664c6143": "audio/flac",
    "7b": "application/json",
    "efbbbf": "text/plain",
    "fffe": "text/plain",
    "feff": "text/plain",
}

# ── MIME to Extension Mapping ────────────────────────────────────────────────

EXTENSION_MIME: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".log": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".ts": "application/typescript",
    ".py": "text/x-python",
    ".go": "text/x-go",
    ".rs": "text/x-rust",
    ".java": "text/x-java",
    ".cpp": "text/x-c++",
    ".c": "text/x-c",
    ".h": "text/x-c",
    ".cs": "text/x-csharp",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".sh": "text/x-shellscript",
    ".ps1": "text/x-powershell",
    ".bat": "text/x-batch",
    ".cmd": "text/x-batch",
    ".sql": "text/x-sql",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".toml": "text/toml",
    ".ini": "text/plain",
    ".cfg": "text/plain",
    ".env": "text/plain",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".7z": "application/x-7z-compressed",
    ".rar": "application/x-rar",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".ogg": "audio/ogg",
    ".mp4": "video/mp4",
    ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".exe": "application/x-dosexec",
    ".dll": "application/x-dosexec",
    ".so": "application/x-sharedlib",
    ".msi": "application/x-msi",
    ".db": "application/x-sqlite3",
    ".sqlite": "application/x-sqlite3",
    ".sqlite3": "application/x-sqlite3",
    ".sol": "text/x-solidity",
    ".asm": "text/x-asm",
    ".wasm": "application/wasm",
}

TEXT_EXTENSIONS = {
    ".txt", ".md", ".log", ".csv", ".json", ".xml", ".html", ".htm",
    ".css", ".js", ".ts", ".tsx", ".jsx", ".py", ".go", ".rs", ".java",
    ".cpp", ".c", ".h", ".cs", ".rb", ".php", ".sh", ".ps1", ".bat",
    ".cmd", ".sql", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env",
    ".r", ".m", ".swift", ".kt", ".lua", ".pl", ".pm", ".tcl", ".awk",
    ".sed", ".makefile", ".cmake", ".gradle", ".sbt", ".cabal",
    ".nix", ".tf", ".hcl", ".dockerfile", ".gitignore", ".editorconfig",
    ".eslintrc", ".prettierrc", ".babelrc", ".svg", ".mdx", ".rst",
    ".tex", ".bib", ".properties", ".conf", ".reg", ".vbs",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".msi",
    ".com", ".scr", ".pif", ".hta", ".cpl", ".jar", ".sh",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a",
    ".mp4", ".avi", ".mkv", ".webm", ".mov", ".wmv", ".flv",
    ".exe", ".dll", ".so", ".msi", ".bin", ".dat", ".iso",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
    ".psd", ".ai", ".sketch", ".fig",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".class", ".o", ".obj", ".lib", ".a",
    ".wasm",
}

# ── Domain Auto-Detection Rules ──────────────────────────────────────────────

EXTENSION_DOMAIN: dict[str, str] = {
    ".py": "PROG",
    ".js": "PROG",
    ".ts": "PROG",
    ".tsx": "PROG",
    ".jsx": "PROG",
    ".go": "PROG",
    ".rs": "PROG",
    ".java": "PROG",
    ".cpp": "PROG",
    ".c": "PROG",
    ".cs": "PROG",
    ".rb": "PROG",
    ".php": "PROG",
    ".swift": "PROG",
    ".kt": "PROG",
    ".sol": "CRYPTO",
    ".asm": "CYBER",
}

CONTENT_DOMAIN_RULES: list[tuple[str, str]] = [
    (r"contract|agreement|clause|indemnif", "LG"),
    (r"invoice|revenue|balance|ledger|audit", "FIN"),
    (r"deed|mineral|royalty|lease|convey", "LM"),
    (r"patient|diagnosis|prescription|HIPAA", "MED"),
    (r"well|drilling|casing|completion|BOP", "DRL"),
    (r"fracture|proppant|slurry|perforat", "FRAC"),
    (r"revenue|expense|balance|depreciat", "ACCT"),
    (r"production|BOE|MCF|barrel", "PROD"),
    (r"premium|claim|loss|reserve|actuari", "INS"),
    (r"specification|tolerance|material", "MECH"),
    (r"recipe|ingredient|HACCP|allergen", "FOOD"),
]

PATH_DOMAIN_RULES: list[tuple[str, str]] = [
    (r"tax|irs|1040|w2|1099", "TAX"),
    (r"legal|law|contract|litigation", "LG"),
    (r"landman|title|deed|mineral|lease", "LM"),
    (r"security|cyber|malware|threat|vuln", "CYBER"),
    (r"finance|accounting|audit|ledger", "FIN"),
    (r"medical|patient|clinical|pharma", "MED"),
    (r"drilling|wellbore|BHA|MWD", "DRL"),
    (r"frac|completion|stimulat|proppant", "FRAC"),
    (r"production|artificial.lift|ESP|rod.pump", "PROD"),
    (r"oilfield|equipment|BOP|separator", "OFE"),
    (r"crypto|blockchain|defi|wallet|token", "CRYPTO"),
    (r"insurance|actuari|claim|underwrit", "INS"),
    (r"real.estate|property|apprais|mortgage", "RE"),
    (r"aerospace|aviation|FAA|airframe", "AERO"),
    (r"automotive|vehicle|ADAS|OBD", "AUTO"),
    (r"chemistry|chemical|reaction|catalyst", "CHEM"),
    (r"nuclear|reactor|neutron|fission", "NUC"),
    (r"marine|offshore|subsea|vessel", "MARINE"),
    (r"construction|concrete|steel|ACI", "CONST"),
    (r"electrical|power|relay|transformer", "EE"),
    (r"food|HACCP|sanitation|ingredient", "FOOD"),
    (r"forensic|evidence|crime|investig", "FOREN"),
    (r"environment|emission|EPA|pollut", "ENV"),
]

# ── Sensitivity Patterns ─────────────────────────────────────────────────────

SENSITIVITY_PATTERNS: dict[str, tuple[str, int]] = {
    "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", 90),
    "credit_card": (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", 95),
    "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 30),
    "phone": (r"\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b", 25),
    "api_key": (r"\b(?:sk|pk|api|key|token|secret)[_-]?[A-Za-z0-9]{20,}\b", 85),
    "password": (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", 90),
    "medical_record": (r"(?i)(?:patient|diagnosis|prescription|ICD-10)", 80),
    "financial": (r"(?i)(?:account\s*number|routing\s*number|bank|SWIFT)", 75),
    "legal_privileged": (r"(?i)(?:attorney.client|privileged|confidential|under\s*seal)", 70),
    "classified": (r"(?i)(?:top\s*secret|classified|restricted|FOUO)", 95),
}

# ── Recommendation Thresholds ────────────────────────────────────────────────

REC_ARCHIVE_STALENESS = 80
REC_ARCHIVE_IMPORTANCE = 30
REC_DELETE_STALENESS = 90
REC_DELETE_IMPORTANCE = 10
REC_SECURE_SENSITIVITY = 70
REC_BACKUP_IMPORTANCE = 80
REC_DEDUP_MIN_COPIES = 5
REC_REVIEW_RISK = 70
REC_UPDATE_STALENESS = 50
REC_UPDATE_IMPORTANCE = 60


class ScanConfig(BaseModel):
    """Configuration for a single scan run."""

    drives: list[str] = Field(default_factory=lambda: ["O:"])
    paths: list[str] = Field(default_factory=list)
    profile: str = "INTELLIGENCE"
    domains: list[str] | None = None
    intelligence: bool = True
    dashboard: bool = False
    upload_cloud: bool = False
    max_files: int | None = None
    max_depth: int | None = None
    max_file_size: int | None = None
    include_extensions: set[str] | None = None
    exclude_extensions: set[str] | None = None
    skip_binary: bool = False
    skip_large_mb: int | None = None
    incremental: bool = True
    deep_analyze_paths: list[str] = Field(default_factory=list)


# ── Recommendation Thresholds ────────────────────────────────────────────────

RECOMMENDATION_THRESHOLDS: dict[str, float] = {
    # Archive: stale + low importance
    "archive_staleness_min": 80.0,
    "archive_importance_max": 30.0,
    # Secure: sensitive files in insecure locations
    "secure_sensitivity_min": 70.0,
    # Encrypt: highly sensitive unencrypted
    "encrypt_sensitivity_min": 80.0,
    # Review: high-risk files
    "review_risk_min": 70.0,
    # Alert: cyber-classified files
    "alert_cyber_score_min": 70.0,
    # Backup: important + unique files not backed up
    "backup_importance_min": 80.0,
    # Update: stale but important (needs refresh)
    "update_staleness_min": 50.0,
    "update_importance_min": 60.0,
}

# ── Performance Tuning ─────────────────────────────────────────────────────
STREAMING_BATCH_SIZE = 2000         # Files per streaming batch (memory vs speed)
PARALLEL_SAMPLE_WORKERS = 32       # ThreadPool workers for parallel file sampling
MIN_DISK_SPACE_GB = 5.0            # Minimum free GB on DB drive before aborting
CHANGE_DETECTION_ENABLED = True    # Skip re-scanning unchanged files
PRIORITY_DIRS = [                  # Scan these dirs first for fast intelligence
    "ECHO_OMEGA_PRIME", "SYSTEMS", "WORKERS", "CORE", "_CLAUDE",
    "ECHO_X", "ECHO_PRIME", "SPI_GODCORE",
]

# ── Library Extraction ─────────────────────────────────────────────────────
LIBRARY_EXTRACTION_ENABLED = True  # Extract function/pattern/schema libraries
LIBRARY_CODE_EXTENSIONS = {        # Extensions to extract libraries from
    ".py", ".js", ".ts", ".jsx", ".tsx"
}
SENSITIVE_SCAN_ENABLED = True      # Scan for secrets/credentials in all files
SECRET_ALERT_THRESHOLD = 1         # Alert immediately on any secret found

# ── Worker Sync ────────────────────────────────────────────────────────────
# Off by default: opt in with DRIVESCAN_WORKER_SYNC=1 (also requires
# DRIVESCAN_WORKER_URL and an API key, or the push is skipped).
WORKER_SYNC_ENABLED = os.environ.get("DRIVESCAN_WORKER_SYNC", "0") == "1"
WORKER_PUSH_BATCH_SIZE = 500       # Files per push batch to worker

# ── DB Maintenance ─────────────────────────────────────────────────────────
DB_MAX_SIZE_GB = 10.0              # Warn when DB exceeds this size
DB_KEEP_SCANS = 3                  # Keep N most recent scans per drive, archive rest


# ── Path Scope Controls (SAFETY-CRITICAL) ──────────────────────────────────
# The scanner walks arbitrary filesystem paths and the dashboard can trigger
# file actions. These lists bound where it is allowed to operate.


def _env_path_list(name: str) -> list[str]:
    """Parse an os.pathsep-separated env var into a list of path entries."""
    return [p.strip() for p in os.environ.get(name, "").split(os.pathsep) if p.strip()]


# Paths the scanner must NEVER traverse or act on. Absolute entries are
# treated as protected subtrees; bare entries match as substrings of the
# resolved path. Extend via env DRIVESCAN_PROTECTED_PATHS (os.pathsep-separated).
PROTECTED_PATHS: list[str] = [
    # Windows system locations
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    "$Recycle.Bin",
    "System Volume Information",
    # POSIX system locations
    "/etc", "/sys", "/proc", "/dev", "/boot", "/usr/lib", "/var/lib",
    # Placeholder: replace with the root of your personal-data tree(s),
    # e.g. r"C:\Users\you\PersonalData". Kept inert until edited.
    "__PERSONAL_DATA_TREE_PLACEHOLDER__",
] + _env_path_list("DRIVESCAN_PROTECTED_PATHS")

# If non-empty, every scan root must live inside one of these prefixes.
# Empty (default) = allow anywhere, but PROTECTED_PATHS always applies.
# Set via env DRIVESCAN_ALLOWLIST (os.pathsep-separated).
SCAN_ALLOWLIST: list[str] = _env_path_list("DRIVESCAN_ALLOWLIST")


def _norm(p: str | Path) -> str:
    """Normalize a path string for case-insensitive prefix comparison."""
    return os.path.normcase(os.path.normpath(str(p)))


def _is_within(path_norm: str, prefix: str | Path) -> bool:
    """True if an already-normalized path equals or lives under prefix."""
    prefix_norm = _norm(prefix)
    return path_norm == prefix_norm or path_norm.startswith(prefix_norm + os.sep)


def validate_scan_path(
    path: str | Path,
    protected: list[str] | None = None,
    allowlist: list[str] | None = None,
) -> tuple[bool, str]:
    """Check whether a path may be scanned / acted upon.

    Returns (ok, reason). A path is rejected if it resolves inside any
    PROTECTED_PATHS entry, or — when SCAN_ALLOWLIST is non-empty — outside
    every allowlist prefix. The optional arguments exist for tests; callers
    normally rely on the module-level lists.
    """
    protected = PROTECTED_PATHS if protected is None else protected
    allowlist = SCAN_ALLOWLIST if allowlist is None else allowlist

    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError) as e:
        return False, f"cannot resolve path: {e}"
    norm = _norm(resolved)

    for entry in protected:
        entry = entry.strip()
        if not entry:
            continue
        if os.path.isabs(entry) or (len(entry) > 1 and entry[1] == ":"):
            if _is_within(norm, entry):
                return False, f"path is inside protected location '{entry}'"
        elif os.path.normcase(entry) in norm:
            return False, f"path matches protected pattern '{entry}'"

    if allowlist:
        if not any(_is_within(norm, entry) for entry in allowlist if entry.strip()):
            return False, "path is outside the configured scan allowlist"

    return True, "ok"


def is_protected_path(path: str | Path) -> bool:
    """Protected-paths-only check (ignores the allowlist) for directory pruning."""
    ok, _ = validate_scan_path(path, allowlist=[])
    return not ok
