"""
Echo Function Library — Scanner Intelligence Module
Extracts every function/class/method from every code file and stores
in a queryable library for reuse across all Echo programs.

Extracts: name, signature, docstring, body, language, file path,
          quality score, how many copies exist system-wide, tags.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any

SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
}

SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{32,}", "openai_key"),
    (r"sk-ant-[a-zA-Z0-9\-_]{32,}", "anthropic_key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_key"),
    (r"ghp_[a-zA-Z0-9]{36}", "github_token"),
    (r"xai-[a-zA-Z0-9]{32,}", "xai_key"),
    (r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "jwt_token"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "private_key"),
    (r'[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[=:]\s*["\'][a-zA-Z0-9\-_]{16,}', "api_key_generic"),
    (r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[=:]\s*["\'][^"\']{8,}', "password"),
    (r'[Ss][Ee][Cc][Rr][Ee][Tt]\s*[=:]\s*["\'][a-zA-Z0-9\-_]{12,}', "secret"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"r2_[a-zA-Z0-9]{32,}", "cloudflare_r2"),
]

DESIGN_PATTERNS = {
    "circuit_breaker": [r"circuit.?break", r"CircuitBreak", r"OPEN.*CLOSED.*HALF"],
    "rate_limiter": [r"rate.?limit", r"RateLimi", r"requests_per", r"throttl"],
    "retry_backoff": [r"retry.*backoff", r"exponential.*back", r"MAX_RETRIES.*attempt"],
    "singleton": [r"_instance\s*=\s*None", r"__instance", r"getInstance"],
    "factory": [r"def create_", r"Factory", r"def make_"],
    "observer": [r"subscribe|unsubscribe", r"on_event", r"EventEmitter"],
    "pub_sub": [r"publish|subscribe", r"PubSub", r"message_bus"],
    "pipeline": [r"pipeline|Pipeline", r"stage.*next", r"chain.*filter"],
    "pool": [r"ThreadPool|ProcessPool|ConnectionPool", r"pool\.submit", r"pool\.map"],
}


def _body_hash(body: str) -> str:
    """Stable hash of function body for dedup detection."""
    normalized = re.sub(r"\s+", " ", body.strip())
    return hashlib.md5(normalized.encode()).hexdigest()[:16]


def _quality_score(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Score 0-100 based on docstring, type hints, length, complexity."""
    score = 0
    # Has docstring
    if ast.get_docstring(node) or "":
        score += 25
    # Has return annotation
    if node.returns:
        score += 15
    # Args have type hints
    typed_args = sum(1 for a in node.args.args if a.annotation)
    total_args = len(node.args.args)
    if total_args > 0:
        score += int((typed_args / total_args) * 20)
    # Reasonable length (5-50 lines = good)
    lines = (node.end_lineno or 0) - node.lineno
    if 5 <= lines <= 50:
        score += 20
    elif lines < 5:
        score += 5
    # Has error handling
    for child in ast.walk(node):
        if isinstance(child, ast.Try):
            score += 10
            break
    # Is async (modern pattern)
    if isinstance(node, ast.AsyncFunctionDef):
        score += 10
    return min(score, 100)


def extract_python_functions(path: Path, content: str) -> list[dict]:
    """AST-parse Python file and extract all functions/methods."""
    results: list[dict[str, Any]] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return results

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Build a complete signature string across positional-only, regular,
        # variadic, keyword-only, and variadic-keyword arguments. ast.arg uses
        # the `.arg` attribute (not `.name`).
        args: list[str] = []
        positional = [*node.args.posonlyargs, *node.args.args]
        posonly_count = len(node.args.posonlyargs)
        for index, arg in enumerate(positional):
            ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
            args.append(f"{arg.arg}{ann}")
            if posonly_count and index + 1 == posonly_count:
                args.append("/")
        if node.args.vararg:
            ann = (
                f": {ast.unparse(node.args.vararg.annotation)}"
                if node.args.vararg.annotation
                else ""
            )
            args.append(f"*{node.args.vararg.arg}{ann}")
        elif node.args.kwonlyargs:
            args.append("*")
        for arg in node.args.kwonlyargs:
            ann = f": {ast.unparse(arg.annotation)}" if arg.annotation else ""
            args.append(f"{arg.arg}{ann}")
        if node.args.kwarg:
            ann = (
                f": {ast.unparse(node.args.kwarg.annotation)}" if node.args.kwarg.annotation else ""
            )
            args.append(f"**{node.args.kwarg.arg}{ann}")
        ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
        is_async = isinstance(node, ast.AsyncFunctionDef)
        prefix = "async def" if is_async else "def"
        signature = f"{prefix} {node.name}({', '.join(args)}){ret}"

        # Extract body
        try:
            lines = content.splitlines()
            body_lines = lines[node.lineno - 1 : node.end_lineno]
            body = "\n".join(body_lines)
        except Exception:
            body = ""

        docstring = ast.get_docstring(node) or ""
        quality = _quality_score(node)

        # Detect patterns in body
        patterns_found = []
        for pattern_name, regexes in DESIGN_PATTERNS.items():
            if any(re.search(rx, body, re.I) for rx in regexes):
                patterns_found.append(pattern_name)

        results.append(
            {
                "name": node.name,
                "language": "python",
                "signature": signature,
                "docstring": docstring[:500],
                "body": body[:4000],
                "body_hash": _body_hash(body),
                "file_path": str(path),
                "line_number": node.lineno,
                "is_async": is_async,
                "quality_score": quality,
                "patterns": patterns_found,
                "arg_count": len(node.args.posonlyargs)
                + len(node.args.args)
                + len(node.args.kwonlyargs)
                + int(node.args.vararg is not None)
                + int(node.args.kwarg is not None),
            }
        )

    return results


def extract_js_functions(path: Path, content: str) -> list[dict]:
    """Regex-based JS/TS function extraction."""
    results: list[dict[str, Any]] = []
    lang = SUPPORTED_LANGUAGES.get(path.suffix.lower(), "javascript")

    patterns = [
        # async function name(args)
        r"(?P<async>async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)",
        # const name = async (args) =>
        r"(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?P<async>async\s*)?\(?(?P<args>[^)=]*)\)?\s*=>",
        # name(args) { — method
        r"(?:^\s*)(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*\{",
    ]

    for i, line in enumerate(content.splitlines(), 1):
        for pat in patterns:
            m = re.search(pat, line)
            if m:
                name = m.group("name") if "name" in m.groupdict() else ""
                if not name or name in ("if", "for", "while", "switch", "catch"):
                    continue
                is_async = bool(m.group("async")) if "async" in m.groupdict() else False
                args = m.group("args").strip() if "args" in m.groupdict() else ""
                signature = f"{'async ' if is_async else ''}function {name}({args})"

                # Grab ~20 lines of body
                body_lines = content.splitlines()[i - 1 : i + 20]
                body = "\n".join(body_lines)

                results.append(
                    {
                        "name": name,
                        "language": lang,
                        "signature": signature,
                        "docstring": "",
                        "body": body[:2000],
                        "body_hash": _body_hash(body),
                        "file_path": str(path),
                        "line_number": i,
                        "is_async": is_async,
                        "quality_score": 40,
                        "patterns": [],
                        "arg_count": len([a for a in args.split(",") if a.strip()]),
                    }
                )
                break  # one match per line

    return results


def _mask_secret(value: str) -> str:
    """Mask a matched secret value. The raw match must never be stored or
    logged anywhere — at most the first 2 + last 2 chars survive."""
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}…{value[-2:]} (len={len(value)})"


def scan_secrets(content: str, path: Path) -> list[dict]:
    """Scan content for secret patterns. Returns findings with MASKED previews."""
    findings = []
    for pattern, secret_type in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            findings.append(
                {
                    "file_path": str(path),
                    "secret_type": secret_type,
                    "line_number": content[: m.start()].count("\n") + 1,
                    "match_preview": _mask_secret(m.group()),
                }
            )
    return findings


def detect_patterns(content: str, path: Path) -> list[dict]:
    """Detect design patterns in file content."""
    found = []
    for pattern_name, regexes in DESIGN_PATTERNS.items():
        for rx in regexes:
            if re.search(rx, content, re.I):
                found.append(
                    {
                        "file_path": str(path),
                        "pattern": pattern_name,
                        "language": SUPPORTED_LANGUAGES.get(path.suffix.lower(), "unknown"),
                    }
                )
                break
    return found


def extract_schemas(content: str, path: Path, lang: str) -> list[dict]:
    """Extract data models, interfaces, Pydantic models, DB tables."""
    results = []
    if lang == "python":
        # Pydantic models / dataclasses
        for m in re.finditer(
            r"class\s+(\w+)\s*\(\s*(BaseModel|TypedDict|dataclass)[^)]*\)", content
        ):
            results.append(
                {
                    "file_path": str(path),
                    "schema_type": "pydantic" if "BaseModel" in m.group() else "typed_dict",
                    "name": m.group(1),
                }
            )
        # SQLite CREATE TABLE
        for m in re.finditer(r"CREATE TABLE[^;]+;", content, re.DOTALL | re.I):
            name_m = re.search(r"CREATE TABLE (?:IF NOT EXISTS\s+)?(\w+)", m.group(), re.I)
            if name_m:
                results.append(
                    {
                        "file_path": str(path),
                        "schema_type": "sqlite_table",
                        "name": name_m.group(1),
                        "definition": m.group()[:500],
                    }
                )
    elif lang in ("javascript", "typescript"):
        # TS interfaces
        for m in re.finditer(r"interface\s+(\w+)\s*\{[^}]+\}", content, re.DOTALL):
            results.append(
                {
                    "file_path": str(path),
                    "schema_type": "ts_interface",
                    "name": m.group(1),
                }
            )
    return results


def extract_api_endpoints(content: str, path: Path, lang: str) -> list[dict]:
    """Extract REST API endpoint definitions."""
    results = []
    # Express / Hono routes
    for m in re.finditer(
        r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", content, re.I
    ):
        results.append(
            {
                "file_path": str(path),
                "method": m.group(1).upper(),
                "path": m.group(2),
                "language": lang,
            }
        )
    # FastAPI / Flask
    for m in re.finditer(
        r"""@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
        content,
        re.I,
    ):
        results.append(
            {
                "file_path": str(path),
                "method": m.group(1).upper(),
                "path": m.group(2),
                "language": lang,
            }
        )
    return results


def extract_prompts(content: str, path: Path) -> list[dict]:
    """Extract system prompts, instruction blocks, few-shot examples."""
    results = []
    # system_prompt = "..." blocks
    for m in re.finditer(
        r'(?:system_prompt|SYSTEM_PROMPT|system_message|instructions)\s*[=:]\s*[f]?["\'\`]{1,3}(.*?)["\'\`]{1,3}',
        content,
        re.DOTALL,
    ):
        body = m.group(1).strip()
        if len(body) > 50:
            results.append(
                {
                    "file_path": str(path),
                    "prompt_type": "system_prompt",
                    "content": body[:1000],
                    "length": len(body),
                }
            )
    # {"role": "system", "content": "..."}
    for m in re.finditer(
        r'"role"\s*:\s*"system"[^}]*"content"\s*:\s*"([^"]{50,})"', content, re.DOTALL
    ):
        results.append(
            {
                "file_path": str(path),
                "prompt_type": "chat_system",
                "content": m.group(1)[:1000],
                "length": len(m.group(1)),
            }
        )
    return results


def extract_configs(content: str, path: Path, lang: str) -> list[dict]:
    """Extract constants, env vars, config keys."""
    results = []
    if lang == "python":
        # ALL_CAPS = value
        for m in re.finditer(
            r"^([A-Z][A-Z0-9_]{3,})\s*(?::\s*\w+\s*)?=\s*(.{1,100})$", content, re.MULTILINE
        ):
            results.append(
                {
                    "file_path": str(path),
                    "key": m.group(1),
                    "value_preview": m.group(2).strip()[:80],
                    "language": lang,
                }
            )
    # os.environ / process.env references
    for m in re.finditer(
        r'(?:os\.environ|process\.env)\[?\s*["\']?([A-Z][A-Z0-9_]{3,})["\']?\s*\]?', content
    ):
        results.append(
            {
                "file_path": str(path),
                "key": m.group(1),
                "value_preview": "env_var",
                "language": lang,
            }
        )
    return results


def extract_errors(content: str, path: Path, lang: str) -> list[dict]:
    """Extract error handlers and exception patterns."""
    results = []
    if lang == "python":
        for m in re.finditer(r"except\s+([^:]+):\s*\n((?:\s+.+\n?){1,10})", content):
            results.append(
                {
                    "file_path": str(path),
                    "exception_type": m.group(1).strip(),
                    "handler_body": m.group(2).strip()[:300],
                    "language": lang,
                }
            )
    else:
        for m in re.finditer(r"catch\s*\(([^)]*)\)\s*\{([^}]{0,300})\}", content, re.DOTALL):
            results.append(
                {
                    "file_path": str(path),
                    "exception_type": m.group(1).strip(),
                    "handler_body": m.group(2).strip()[:300],
                    "language": lang,
                }
            )
    return results


def extract_credential_refs(content: str, path: Path) -> list[dict]:
    """Find credential references without storing values."""
    results = []
    cred_patterns = [
        r'(?:vault|secret|key|token|password|credential)[_\s]*(?:get|fetch|load|read)\s*\(\s*["\']([^"\']+)["\']',
        r"env\s*\.\s*([A-Z][A-Z0-9_]{3,})",
        r'process\.env\.["\']?([A-Z][A-Z0-9_]{3,})',
        r'os\.environ\.get\s*\(\s*["\']([A-Z0-9_]+)["\']',
        r'Deno\.env\.get\s*\(\s*["\']([A-Z0-9_]+)["\']',
    ]
    for pat in cred_patterns:
        for m in re.finditer(pat, content, re.I):
            results.append(
                {
                    "file_path": str(path),
                    "credential_key": m.group(1),
                }
            )
    return results


def extract_all(path: Path, content: str) -> dict:
    """Run all extractors on a file. Returns dict of all library contributions."""
    lang = SUPPORTED_LANGUAGES.get(path.suffix.lower(), "unknown")

    if lang == "unknown":
        # Still scan for secrets in any file type
        return {
            "functions": [],
            "patterns": [],
            "schemas": [],
            "endpoints": [],
            "prompts": extract_prompts(content, path),
            "configs": [],
            "errors": [],
            "credentials": extract_credential_refs(content, path),
            "secrets": scan_secrets(content, path),
        }

    funcs = []
    if lang == "python":
        funcs = extract_python_functions(path, content)
    elif lang in ("javascript", "typescript"):
        funcs = extract_js_functions(path, content)

    return {
        "functions": funcs,
        "patterns": detect_patterns(content, path),
        "schemas": extract_schemas(content, path, lang),
        "endpoints": extract_api_endpoints(content, path, lang),
        "prompts": extract_prompts(content, path),
        "configs": extract_configs(content, path, lang),
        "errors": extract_errors(content, path, lang),
        "credentials": extract_credential_refs(content, path),
        "secrets": scan_secrets(content, path),
    }
