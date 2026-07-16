"""
Assimilator — Extract templates, patterns, and knowledge from scanned files.
=============================================================================
Analyzes code files for function signatures, class hierarchies, import graphs.
Analyzes config files for reusable patterns. Analyzes docs for key facts.
Stores templates and pushes extracted knowledge to Shared Brain.
"""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from loguru import logger
from pydantic import BaseModel, Field

# ─── Config ──────────────────────────────────────────────────────────────────
# Endpoints come from env; empty means "not configured" → pushes are skipped.

import os

SHARED_BRAIN_URL = os.environ.get("DRIVESCAN_SHARED_BRAIN_URL", "")
KNOWLEDGE_FORGE_URL = os.environ.get("DRIVESCAN_KNOWLEDGE_FORGE_URL", "")
MEMORY_PRIME_URL = os.environ.get("DRIVESCAN_MEMORY_PRIME_URL", "")
TEMPLATE_DIR = Path(__file__).parent.parent / "data" / "templates"
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_FILES_PER_RUN = 500

CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".cpp", ".c", ".cs"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".conf"}
DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc"}


# ─── Models ──────────────────────────────────────────────────────────────────

class ExtractedFunction(BaseModel):
    name: str
    args: list[str] = Field(default_factory=list)
    returns: str = ""
    decorators: list[str] = Field(default_factory=list)
    docstring: str = ""
    line_number: int = 0
    is_async: bool = False


class ExtractedClass(BaseModel):
    name: str
    bases: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    docstring: str = ""
    line_number: int = 0


class ExtractedImport(BaseModel):
    module: str
    names: list[str] = Field(default_factory=list)
    is_from: bool = False


class CodeAnalysis(BaseModel):
    path: str
    language: str = "python"
    functions: list[ExtractedFunction] = Field(default_factory=list)
    classes: list[ExtractedClass] = Field(default_factory=list)
    imports: list[ExtractedImport] = Field(default_factory=list)
    total_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0


class ConfigPattern(BaseModel):
    path: str
    format: str
    keys: list[str] = Field(default_factory=list)
    nested_depth: int = 0
    has_env_vars: bool = False
    template_name: str = ""


class DocSummary(BaseModel):
    path: str
    title: str = ""
    headings: list[str] = Field(default_factory=list)
    key_facts: list[str] = Field(default_factory=list)
    word_count: int = 0
    links: list[str] = Field(default_factory=list)


class GradedTemplate(BaseModel):
    name: str
    category: str  # "framework", "config", "pattern"
    grade: str = "C"  # A/B/C/D/F
    score: float = 0.0  # 0.0-1.0
    occurrences: int = 0
    key_count: int = 0
    depth: int = 0
    uniqueness: float = 0.0
    maturity: str = "emerging"  # emerging/established/mature
    content: dict[str, Any] = Field(default_factory=dict)
    path: str = ""


class AssimilationResult(BaseModel):
    code_analyses: list[CodeAnalysis] = Field(default_factory=list)
    config_patterns: list[ConfigPattern] = Field(default_factory=list)
    doc_summaries: list[DocSummary] = Field(default_factory=list)
    templates_created: int = 0
    templates_graded: list[GradedTemplate] = Field(default_factory=list)
    knowledge_pushed: int = 0
    files_processed: int = 0
    errors: list[str] = Field(default_factory=list)


# ─── Assimilator ─────────────────────────────────────────────────────────────

class Assimilator:
    """Extract templates and patterns from scanned files."""

    def __init__(self, db: Any) -> None:
        self.db = db

    async def assimilate(self, scan_id: int, max_files: int = MAX_FILES_PER_RUN) -> AssimilationResult:
        """Run full assimilation pipeline on scan results."""
        result = AssimilationResult()

        files = self.db.list_files(scan_id=scan_id, limit=max_files)
        logger.info(f"Assimilating {len(files)} files from scan {scan_id}")

        for f in files:
            fpath = f.path if hasattr(f, "path") else f.get("path", "")
            ext = Path(fpath).suffix.lower()
            size = f.size_bytes if hasattr(f, "size_bytes") else f.get("size_bytes", 0)

            if size > MAX_FILE_SIZE or size == 0:
                continue

            try:
                if ext in CODE_EXTENSIONS:
                    analysis = self._analyze_code(fpath, ext)
                    if analysis and (analysis.functions or analysis.classes):
                        result.code_analyses.append(analysis)
                elif ext in CONFIG_EXTENSIONS:
                    pattern = self._analyze_config(fpath, ext)
                    if pattern and pattern.keys:
                        result.config_patterns.append(pattern)
                elif ext in DOC_EXTENSIONS:
                    summary = self._analyze_doc(fpath)
                    if summary and summary.word_count > 20:
                        result.doc_summaries.append(summary)

                result.files_processed += 1
            except Exception as e:
                result.errors.append(f"{fpath}: {e}")

        # Generate templates from patterns
        result.templates_created = self._generate_templates(result)

        # Push knowledge to cloud
        result.knowledge_pushed = await self._push_knowledge(result)

        logger.info(
            f"Assimilation complete: {result.files_processed} files, "
            f"{len(result.code_analyses)} code, {len(result.config_patterns)} configs, "
            f"{len(result.doc_summaries)} docs, {result.templates_created} templates"
        )
        return result

    def _analyze_code(self, path: str, ext: str) -> CodeAnalysis | None:
        """Analyze a code file for structure."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

        lines = content.split("\n")
        total = len(lines)
        blank = sum(1 for line in lines if not line.strip())
        comments = sum(1 for line in lines if line.strip().startswith("#") or line.strip().startswith("//"))

        analysis = CodeAnalysis(
            path=path,
            language=self._ext_to_lang(ext),
            total_lines=total,
            blank_lines=blank,
            comment_lines=comments,
        )

        if ext == ".py":
            self._analyze_python(content, analysis)
        else:
            self._analyze_generic(content, analysis, ext)

        return analysis

    def _analyze_python(self, content: str, analysis: CodeAnalysis) -> None:
        """Parse Python AST for detailed analysis."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            self._analyze_generic(content, analysis, ".py")
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = []
                for arg in node.args.args:
                    annotation = ""
                    if arg.annotation:
                        try:
                            annotation = ast.unparse(arg.annotation)
                        except Exception:
                            pass
                    args.append(f"{arg.arg}: {annotation}" if annotation else arg.arg)

                returns = ""
                if node.returns:
                    try:
                        returns = ast.unparse(node.returns)
                    except Exception:
                        pass

                decorators = []
                for dec in node.decorator_list:
                    try:
                        decorators.append(ast.unparse(dec))
                    except Exception:
                        pass

                docstring = ast.get_docstring(node) or ""

                analysis.functions.append(ExtractedFunction(
                    name=node.name,
                    args=args,
                    returns=returns,
                    decorators=decorators,
                    docstring=docstring[:200],
                    line_number=node.lineno,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                ))

            elif isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    try:
                        bases.append(ast.unparse(base))
                    except Exception:
                        pass

                methods = [
                    n.name for n in ast.walk(node)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]

                analysis.classes.append(ExtractedClass(
                    name=node.name,
                    bases=bases,
                    methods=methods,
                    docstring=ast.get_docstring(node) or "",
                    line_number=node.lineno,
                ))

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    analysis.imports.append(ExtractedImport(module=alias.name, is_from=False))

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names = [alias.name for alias in node.names]
                    analysis.imports.append(ExtractedImport(module=node.module, names=names, is_from=True))

    def _analyze_generic(self, content: str, analysis: CodeAnalysis, ext: str) -> None:
        """Regex-based analysis for non-Python files."""
        # Functions
        func_patterns = {
            ".js": r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>)",
            ".ts": r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>)",
            ".tsx": r"(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[\w]+)\s*=>)",
            ".go": r"func\s+(?:\([^)]+\)\s+)?(\w+)",
            ".rs": r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)",
            ".java": r"(?:public|private|protected)?\s+(?:static\s+)?[\w<>]+\s+(\w+)\s*\(",
        }
        pattern = func_patterns.get(ext)
        if pattern:
            for m in re.finditer(pattern, content):
                name = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else None)
                if name:
                    analysis.functions.append(ExtractedFunction(name=name))

        # Classes
        class_patterns = {
            ".js": r"class\s+(\w+)(?:\s+extends\s+(\w+))?",
            ".ts": r"(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?",
            ".tsx": r"(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?",
            ".java": r"class\s+(\w+)(?:\s+extends\s+(\w+))?",
        }
        cls_pattern = class_patterns.get(ext)
        if cls_pattern:
            for m in re.finditer(cls_pattern, content):
                bases = [m.group(2)] if m.lastindex and m.lastindex >= 2 and m.group(2) else []
                analysis.classes.append(ExtractedClass(name=m.group(1), bases=bases))

    def _analyze_config(self, path: str, ext: str) -> ConfigPattern | None:
        """Analyze a config file for patterns."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

        fmt = ext.lstrip(".")
        keys: list[str] = []
        depth = 0
        has_env = bool(re.search(r"\$\{?\w+\}?|process\.env\.\w+|os\.environ", content))

        if ext == ".json":
            try:
                data = json.loads(content)
                keys = self._extract_json_keys(data)
                depth = self._json_depth(data)
            except json.JSONDecodeError:
                return None
        elif ext in (".yaml", ".yml"):
            keys = [m.group(1) for m in re.finditer(r"^(\w[\w.-]*):", content, re.MULTILINE)]
            depth = max((len(line) - len(line.lstrip())) for line in content.split("\n") if line.strip()) // 2
        elif ext == ".toml":
            keys = [m.group(1) for m in re.finditer(r"^\[([^\]]+)\]", content, re.MULTILINE)]
            keys += [m.group(1) for m in re.finditer(r"^(\w+)\s*=", content, re.MULTILINE)]
        elif ext in (".ini", ".cfg"):
            keys = [m.group(1) for m in re.finditer(r"^\[([^\]]+)\]", content, re.MULTILINE)]
            keys += [m.group(1) for m in re.finditer(r"^(\w+)\s*=", content, re.MULTILINE)]
        elif ext in (".env", ".conf"):
            keys = [m.group(1) for m in re.finditer(r"^(\w+)=", content, re.MULTILINE)]
            has_env = True

        return ConfigPattern(
            path=path,
            format=fmt,
            keys=keys[:50],
            nested_depth=depth,
            has_env_vars=has_env,
            template_name=Path(path).stem,
        )

    def _analyze_doc(self, path: str) -> DocSummary | None:
        """Analyze a documentation file for key facts."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return None

        lines = content.split("\n")
        headings = [line.lstrip("#").strip() for line in lines if line.startswith("#")]
        title = headings[0] if headings else Path(path).stem

        links = re.findall(r"https?://[^\s\)\"'>]+", content)

        # Extract key facts (lines with bold, bullets, or key patterns)
        key_facts = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("- **") or stripped.startswith("* **"):
                fact = re.sub(r"\*\*([^*]+)\*\*", r"\1", stripped.lstrip("- *"))
                key_facts.append(fact[:200])
            elif re.match(r"^\d+\.\s+\*\*", stripped):
                fact = re.sub(r"\*\*([^*]+)\*\*", r"\1", stripped)
                key_facts.append(fact[:200])

        words = len(content.split())

        return DocSummary(
            path=path,
            title=title[:200],
            headings=headings[:20],
            key_facts=key_facts[:20],
            word_count=words,
            links=links[:20],
        )

    def _generate_templates(self, result: AssimilationResult) -> int:
        """Generate reusable templates from analysis results, with quality grading."""
        created = 0

        # Group code analyses by dominant patterns
        framework_counts: dict[str, int] = defaultdict(int)
        for ca in result.code_analyses:
            for imp in ca.imports:
                if imp.module in ("fastapi", "flask", "django", "express", "hono", "nextjs",
                                  "react", "vue", "svelte", "pydantic", "sqlalchemy", "torch"):
                    framework_counts[imp.module] += 1

        # Create + grade framework templates
        for framework, count in framework_counts.items():
            if count >= 2:
                examples = [
                    ca for ca in result.code_analyses
                    if any(i.module == framework for i in ca.imports)
                ][:5]

                all_funcs = list(set(f.name for ex in examples for f in ex.functions))
                all_classes = list(set(c.name for ex in examples for c in ex.classes))
                avg_lines = sum(ex.total_lines for ex in examples) / max(len(examples), 1)
                has_async = any(f.is_async for ex in examples for f in ex.functions)
                has_types = any(f.returns for ex in examples for f in ex.functions)
                has_docs = any(f.docstring for ex in examples for f in ex.functions)

                template_data = {
                    "framework": framework,
                    "occurrences": count,
                    "common_patterns": {
                        "functions": all_funcs[:20],
                        "classes": all_classes[:10],
                    },
                    "avg_lines": round(avg_lines),
                    "has_async": has_async,
                    "has_type_hints": has_types,
                    "has_docstrings": has_docs,
                    "created": datetime.now(timezone.utc).isoformat(),
                }

                # Grade the template
                graded = self._grade_template(
                    name=f"framework_{framework}",
                    category="framework",
                    content=template_data,
                    occurrences=count,
                    key_count=len(all_funcs) + len(all_classes),
                    depth=0,
                    has_async=has_async,
                    has_types=has_types,
                    has_docs=has_docs,
                    avg_lines=avg_lines,
                )
                result.templates_graded.append(graded)

                template_path = TEMPLATE_DIR / f"template_{framework}.json"
                template_data["grade"] = graded.grade
                template_data["score"] = graded.score
                template_path.write_text(json.dumps(template_data, indent=2))
                created += 1

        # Create + grade config templates from common patterns
        format_groups: dict[str, list[ConfigPattern]] = defaultdict(list)
        for cp in result.config_patterns:
            format_groups[cp.format].append(cp)

        for fmt, patterns in format_groups.items():
            if len(patterns) >= 2:
                all_keys: dict[str, int] = defaultdict(int)
                for p in patterns:
                    for k in p.keys:
                        all_keys[k] += 1
                common_keys = [k for k, v in all_keys.items() if v >= 2]
                max_depth = max((p.nested_depth for p in patterns), default=0)
                has_env = any(p.has_env_vars for p in patterns)

                if common_keys:
                    template_data = {
                        "format": fmt,
                        "common_keys": common_keys[:30],
                        "sample_count": len(patterns),
                        "max_depth": max_depth,
                        "has_env_vars": has_env,
                        "created": datetime.now(timezone.utc).isoformat(),
                    }

                    graded = self._grade_template(
                        name=f"config_{fmt}",
                        category="config",
                        content=template_data,
                        occurrences=len(patterns),
                        key_count=len(common_keys),
                        depth=max_depth,
                    )
                    result.templates_graded.append(graded)

                    template_data["grade"] = graded.grade
                    template_data["score"] = graded.score
                    template_path = TEMPLATE_DIR / f"template_config_{fmt}.json"
                    template_path.write_text(json.dumps(template_data, indent=2))
                    created += 1

        # Grade doc knowledge as "pattern" templates
        if result.doc_summaries:
            total_facts = sum(len(ds.key_facts) for ds in result.doc_summaries)
            total_headings = sum(len(ds.headings) for ds in result.doc_summaries)
            avg_words = sum(ds.word_count for ds in result.doc_summaries) / max(len(result.doc_summaries), 1)

            doc_template = {
                "doc_count": len(result.doc_summaries),
                "total_facts": total_facts,
                "total_headings": total_headings,
                "avg_words": round(avg_words),
                "top_titles": [ds.title for ds in result.doc_summaries[:10]],
                "created": datetime.now(timezone.utc).isoformat(),
            }
            graded = self._grade_template(
                name="documentation_corpus",
                category="pattern",
                content=doc_template,
                occurrences=len(result.doc_summaries),
                key_count=total_facts,
                depth=0,
            )
            result.templates_graded.append(graded)

            template_path = TEMPLATE_DIR / "template_docs.json"
            doc_template["grade"] = graded.grade
            doc_template["score"] = graded.score
            template_path.write_text(json.dumps(doc_template, indent=2))
            created += 1

        return created

    @staticmethod
    def _grade_template(
        name: str,
        category: str,
        content: dict[str, Any],
        occurrences: int = 0,
        key_count: int = 0,
        depth: int = 0,
        has_async: bool = False,
        has_types: bool = False,
        has_docs: bool = False,
        avg_lines: float = 0,
    ) -> GradedTemplate:
        """Grade a template on quality: frequency, completeness, maturity, code quality."""
        score = 0.0

        # Frequency score (0-0.25): more occurrences = more validated pattern
        freq_score = min(occurrences / 20, 1.0) * 0.25
        score += freq_score

        # Completeness score (0-0.25): key count + depth
        comp_raw = min(key_count / 30, 1.0) * 0.15 + min(depth / 5, 1.0) * 0.10
        score += comp_raw

        # Code quality score (0-0.25): type hints, async, docstrings, avg line count
        quality = 0.0
        if has_types:
            quality += 0.08
        if has_async:
            quality += 0.05
        if has_docs:
            quality += 0.07
        if avg_lines > 100:
            quality += min(avg_lines / 2000, 1.0) * 0.05
        score += quality

        # Uniqueness score (0-0.25): inverse of how common the pattern is (rare = unique)
        uniqueness = max(0, 1.0 - (occurrences / 50)) * 0.25
        score += uniqueness

        score = round(min(score, 1.0), 3)

        # Letter grade
        if score >= 0.80:
            grade = "A"
        elif score >= 0.65:
            grade = "B"
        elif score >= 0.45:
            grade = "C"
        elif score >= 0.25:
            grade = "D"
        else:
            grade = "F"

        # Maturity
        if occurrences >= 10:
            maturity = "mature"
        elif occurrences >= 5:
            maturity = "established"
        else:
            maturity = "emerging"

        return GradedTemplate(
            name=name,
            category=category,
            grade=grade,
            score=score,
            occurrences=occurrences,
            key_count=key_count,
            depth=depth,
            uniqueness=round(uniqueness / 0.25 if uniqueness else 0, 3),
            maturity=maturity,
            content=content,
        )

    async def _push_knowledge(self, result: AssimilationResult) -> int:
        """Push assimilated knowledge to Shared Brain, Knowledge Forge, and Memory Prime."""
        if not (SHARED_BRAIN_URL or KNOWLEDGE_FORGE_URL or MEMORY_PRIME_URL):
            logger.info("Knowledge push disabled — no endpoints configured")
            return 0
        pushed = 0
        async with httpx.AsyncClient(timeout=15.0) as client:
            # 1. Push code structure summary to Shared Brain
            if result.code_analyses and SHARED_BRAIN_URL:
                total_funcs = sum(len(ca.functions) for ca in result.code_analyses)
                total_classes = sum(len(ca.classes) for ca in result.code_analyses)
                total_lines = sum(ca.total_lines for ca in result.code_analyses)

                lang_dist: dict[str, int] = defaultdict(int)
                for ca in result.code_analyses:
                    lang_dist[ca.language] += 1

                content = (
                    f"CODE ASSIMILATION: {len(result.code_analyses)} files analyzed. "
                    f"{total_funcs} functions, {total_classes} classes, {total_lines:,} lines. "
                    f"Languages: {', '.join(f'{k}({v})' for k, v in sorted(lang_dist.items(), key=lambda x: -x[1])[:5])}. "
                    f"Templates created: {result.templates_created}."
                )
                try:
                    resp = await client.post(
                        f"{SHARED_BRAIN_URL}/ingest",
                        json={
                            "instance_id": "scanner_assimilator",
                            "role": "assistant",
                            "content": content,
                            "importance": 5,
                            "tags": ["scan", "assimilation", "code"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Code knowledge push failed: {e}")

            # 2. Push doc summaries to Shared Brain
            if result.doc_summaries and SHARED_BRAIN_URL:
                facts = []
                for ds in result.doc_summaries[:20]:
                    for fact in ds.key_facts[:3]:
                        facts.append(f"[{ds.title}] {fact}")

                if facts:
                    content = "EXTRACTED FACTS FROM DOCS:\n" + "\n".join(facts[:30])
                    try:
                        resp = await client.post(
                            f"{SHARED_BRAIN_URL}/ingest",
                            json={
                                "instance_id": "scanner_assimilator",
                                "role": "assistant",
                                "content": content,
                                "importance": 5,
                                "tags": ["scan", "assimilation", "docs", "facts"],
                            },
                        )
                        if resp.status_code < 300:
                            pushed += 1
                    except Exception as e:
                        result.errors.append(f"Doc knowledge push failed: {e}")

            # 3. Push graded templates to Knowledge Forge
            for tpl in (result.templates_graded if KNOWLEDGE_FORGE_URL else []):
                try:
                    forge_content = (
                        f"TEMPLATE [{tpl.grade}] {tpl.name} ({tpl.category}): "
                        f"score={tpl.score:.1%}, occurrences={tpl.occurrences}, "
                        f"keys={tpl.key_count}, maturity={tpl.maturity}. "
                        f"Content: {json.dumps(tpl.content, default=str)[:500]}"
                    )
                    resp = await client.post(
                        f"{KNOWLEDGE_FORGE_URL}/ingest",
                        json={
                            "title": f"Template: {tpl.name}",
                            "content": forge_content,
                            "category": "template",
                            "tags": ["template", tpl.category, tpl.grade, tpl.maturity],
                            "metadata": {
                                "grade": tpl.grade,
                                "score": tpl.score,
                                "occurrences": tpl.occurrences,
                                "maturity": tpl.maturity,
                                "category": tpl.category,
                            },
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Knowledge Forge push failed for {tpl.name}: {e}")

            # 4. Push graded templates to Shared Brain (importance scaled by grade)
            grade_importance = {"A": 8, "B": 7, "C": 6, "D": 5, "F": 4}
            for tpl in (result.templates_graded if SHARED_BRAIN_URL else []):
                try:
                    content = (
                        f"GRADED TEMPLATE [{tpl.grade}] {tpl.name}: "
                        f"score={tpl.score:.1%}, {tpl.occurrences} occurrences, "
                        f"{tpl.maturity} maturity. Category: {tpl.category}."
                    )
                    resp = await client.post(
                        f"{SHARED_BRAIN_URL}/ingest",
                        json={
                            "instance_id": "scanner_assimilator",
                            "role": "assistant",
                            "content": content,
                            "importance": grade_importance.get(tpl.grade, 5),
                            "tags": ["scan", "template", tpl.category, f"grade_{tpl.grade}"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Brain template push failed for {tpl.name}: {e}")

            # 5. Push template grading summary to Memory Prime
            if result.templates_graded and MEMORY_PRIME_URL:
                try:
                    grade_dist: dict[str, int] = defaultdict(int)
                    for tpl in result.templates_graded:
                        grade_dist[tpl.grade] += 1

                    resp = await client.post(
                        f"{MEMORY_PRIME_URL}/store",
                        json={
                            "category": "scan_templates",
                            "content": json.dumps({
                                "templates_count": len(result.templates_graded),
                                "grade_distribution": dict(grade_dist),
                                "avg_score": round(
                                    sum(t.score for t in result.templates_graded) / max(len(result.templates_graded), 1), 3
                                ),
                                "top_templates": [
                                    {"name": t.name, "grade": t.grade, "score": t.score, "category": t.category}
                                    for t in sorted(result.templates_graded, key=lambda x: x.score, reverse=True)[:10]
                                ],
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }),
                            "tags": ["scan", "templates", "grading"],
                        },
                    )
                    if resp.status_code < 300:
                        pushed += 1
                except Exception as e:
                    result.errors.append(f"Memory Prime template push failed: {e}")

        return pushed

    @staticmethod
    def _ext_to_lang(ext: str) -> str:
        return {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".tsx": "typescript", ".jsx": "javascript", ".go": "go",
            ".rs": "rust", ".java": "java", ".cpp": "cpp", ".c": "c", ".cs": "csharp",
        }.get(ext, "unknown")

    @staticmethod
    def _extract_json_keys(data: Any, prefix: str = "") -> list[str]:
        keys: list[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.append(full)
                if isinstance(v, (dict, list)):
                    keys.extend(Assimilator._extract_json_keys(v, full))
        elif isinstance(data, list) and data:
            keys.extend(Assimilator._extract_json_keys(data[0], f"{prefix}[0]"))
        return keys[:100]

    @staticmethod
    def _json_depth(data: Any, depth: int = 0) -> int:
        if isinstance(data, dict):
            if not data:
                return depth
            return max(Assimilator._json_depth(v, depth + 1) for v in data.values())
        if isinstance(data, list) and data:
            return Assimilator._json_depth(data[0], depth + 1)
        return depth
