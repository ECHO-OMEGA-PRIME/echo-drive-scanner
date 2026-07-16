"""
Intelligent Drive Scanner v2.0 - Echo Engine Runtime HTTP Client

Async HTTP client for Echo Engine Runtime API with connection pooling, intelligent
caching, rate limiting, circuit breaker, and batch query optimization.

Features:
- Connection pooling via aiohttp ClientSession
- LRU response cache with TTL
- Token bucket rate limiter (500 req/min)
- Circuit breaker for failure resilience
- Exponential backoff retry logic
- Batch classification with concurrency control
- Comprehensive metrics tracking
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque
from enum import Enum
from typing import Any

import aiohttp
from loguru import logger

from config import (
    CACHE_TTL_SECONDS,
    ENGINE_API_KEY,
    ENGINE_RUNTIME_URL,
    MAX_CONCURRENT_REQUESTS,
    MAX_REQUESTS_PER_MINUTE,
    MAX_RETRIES,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_BACKOFF_BASE,
    RUNTIME_ENDPOINTS,
)
from storage.models import (
    Classification,
    ClassificationResult,
    ClassificationTier,
    ConfidenceLevel,
    CrossDomainResult,
    DomainResult,
    EngineResult,
    FileSample,
    QueryMode,
)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Broken, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


class EngineClient:
    """Async HTTP client for Echo Engine Runtime with pooling, caching, rate limiting."""

    def __init__(self) -> None:
        """Initialize client with connection pool and metrics tracking."""
        self.session: aiohttp.ClientSession | None = None
        self.base_url = ENGINE_RUNTIME_URL.rstrip("/")
        # When no engine runtime is configured (DRIVESCAN_ENGINE_URL unset),
        # classification is skipped cleanly instead of spamming errors and
        # tripping the circuit breaker on every file.
        self._enabled = bool(self.base_url)
        # Log the "not configured" notice only once per client.
        self._logged_disabled = False

        # Response cache: {cache_key: (expiry_timestamp, data)}
        self._cache: dict[str, tuple[float, dict]] = {}
        self._cache_accesses = 0

        # Rate limiter: track request timestamps
        self._request_timestamps: deque[float] = deque(maxlen=MAX_REQUESTS_PER_MINUTE)
        self._rate_limit_lock = asyncio.Lock()

        # Circuit breaker
        self._circuit_state = CircuitState.CLOSED
        self._circuit_failures = 0
        self._circuit_open_until = 0.0
        self._circuit_lock = asyncio.Lock()

        # Metrics
        self._total_requests = 0
        self._cache_hits = 0
        self._errors = 0
        self._latencies: list[float] = []

        logger.info(f"EngineClient initialized | base_url={self.base_url}")

    async def __aenter__(self) -> EngineClient:
        """Context manager entry - create aiohttp session."""
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS,
            limit_per_host=10,
            ttl_dns_cache=300,
        )
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            raise_for_status=False,
        )
        logger.info("aiohttp ClientSession created")
        return self

    async def __aexit__(self, *args) -> None:
        """Context manager exit - close session gracefully."""
        if self.session:
            await self.session.close()
            # Give connection pool time to close
            await asyncio.sleep(0.1)
            logger.info("aiohttp ClientSession closed")

    def _cache_key(self, engine_id: str, query: str, mode: str) -> str:
        """Generate cache key from engine_id, query hash, and mode."""
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        return f"{engine_id}:{query_hash}:{mode}"

    def _check_cache(self, key: str) -> dict | None:
        """Check cache for unexpired entry."""
        if key in self._cache:
            expiry, data = self._cache[key]
            if time.time() < expiry:
                self._cache_hits += 1
                return data
            else:
                # Expired, remove
                del self._cache[key]
        return None

    def _store_cache(self, key: str, data: dict) -> None:
        """Store data in cache with TTL."""
        expiry = time.time() + CACHE_TTL_SECONDS
        self._cache[key] = (expiry, data)

        # Periodic cleanup every 100 accesses
        self._cache_accesses += 1
        if self._cache_accesses >= 100:
            self._cleanup_cache()
            self._cache_accesses = 0

    def _cleanup_cache(self) -> None:
        """Remove all expired cache entries."""
        now = time.time()
        expired_keys = [k for k, (exp, _) in self._cache.items() if exp <= now]
        for key in expired_keys:
            del self._cache[key]
        if expired_keys:
            logger.debug(f"Cache cleanup: removed {len(expired_keys)} expired entries")

    async def _rate_limit(self) -> None:
        """Enforce rate limit using token bucket algorithm."""
        async with self._rate_limit_lock:
            now = time.time()

            # Remove timestamps older than 60 seconds
            cutoff = now - 60.0
            while self._request_timestamps and self._request_timestamps[0] < cutoff:
                self._request_timestamps.popleft()

            # Check if we're at limit
            if len(self._request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
                # Must wait until oldest timestamp expires
                oldest = self._request_timestamps[0]
                wait_time = 60.0 - (now - oldest) + 0.1  # Add 100ms buffer
                if wait_time > 0:
                    logger.warning(f"Rate limit reached, sleeping {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)

            # Record this request
            self._request_timestamps.append(time.time())

    def _circuit_check(self) -> bool:
        """Check if circuit breaker allows request. Returns True if should proceed."""
        if self._circuit_state == CircuitState.CLOSED:
            return True
        elif self._circuit_state == CircuitState.OPEN:
            # Check if timeout expired
            if time.time() >= self._circuit_open_until:
                self._circuit_state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker: OPEN → HALF_OPEN (testing recovery)")
                return True
            else:
                return False
        else:  # HALF_OPEN
            return True

    def _circuit_success(self) -> None:
        """Record successful request for circuit breaker."""
        if self._circuit_state == CircuitState.HALF_OPEN:
            self._circuit_state = CircuitState.CLOSED
            self._circuit_failures = 0
            logger.info("Circuit breaker: HALF_OPEN → CLOSED (recovered)")
        elif self._circuit_state == CircuitState.CLOSED:
            # Reset failure counter on success
            if self._circuit_failures > 0:
                self._circuit_failures = 0

    def _circuit_failure(self) -> None:
        """Record failed request for circuit breaker."""
        self._circuit_failures += 1

        if self._circuit_state == CircuitState.HALF_OPEN:
            # Failed recovery attempt, go back to OPEN
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_until = time.time() + 60.0
            logger.warning("Circuit breaker: HALF_OPEN → OPEN (recovery failed)")
        elif self._circuit_state == CircuitState.CLOSED and self._circuit_failures >= 10:
            # Too many failures, open circuit
            self._circuit_state = CircuitState.OPEN
            self._circuit_open_until = time.time() + 60.0
            logger.error(f"Circuit breaker: CLOSED → OPEN ({self._circuit_failures} consecutive failures)")

    def _record_latency(self, ms: float) -> None:
        """Record request latency for metrics."""
        self._latencies.append(ms)
        # Keep only last 1000 latencies
        if len(self._latencies) > 1000:
            self._latencies = self._latencies[-1000:]

    async def _request(
        self,
        method: str,
        path: str,
        json_data: dict | None = None,
    ) -> dict:
        """
        Execute HTTP request with retry logic and circuit breaker.

        Args:
            method: HTTP method (GET, POST)
            path: API path (will be joined with base_url)
            json_data: Optional JSON body for POST requests

        Returns:
            Response JSON as dict

        Raises:
            aiohttp.ClientError: On unrecoverable errors
        """
        if not self.session:
            raise RuntimeError("Session not initialized - use async context manager")

        # No engine runtime configured — skip cleanly (no error spam, no
        # circuit-breaker trip). This is the expected state when the tool runs
        # without an external engine backend; classification degrades to empty.
        if not self._enabled:
            if not self._logged_disabled:
                logger.info(
                    "Engine runtime not configured (set DRIVESCAN_ENGINE_URL to enable "
                    "classification) — skipping engine queries"
                )
                self._logged_disabled = True
            return {"success": False, "error": "engine_not_configured"}

        # Check circuit breaker
        async with self._circuit_lock:
            if not self._circuit_check():
                logger.warning("Circuit breaker OPEN - request rejected")
                self._errors += 1
                return {"success": False, "error": "Circuit breaker open"}

        # Rate limiting
        await self._rate_limit()

        url = f"{self.base_url}{path}"
        self._total_requests += 1

        # Retry loop with exponential backoff
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                start_time = time.time()

                if method == "GET":
                    async with self.session.get(url, headers={"X-Echo-API-Key": ENGINE_API_KEY}) as resp:
                        data = await resp.json()
                else:  # POST
                    async with self.session.post(url, json=json_data, headers={"X-Echo-API-Key": ENGINE_API_KEY}) as resp:
                        data = await resp.json()

                latency_ms = (time.time() - start_time) * 1000
                self._record_latency(latency_ms)

                # Check for rate limit or server errors
                if resp.status == 401:
                        logger.debug("Engine API 401 — check API key")
                        return {"success": False, "error": "Unauthorized"}
                if resp.status == 429 or resp.status >= 500:
                    if attempt < MAX_RETRIES - 1:
                        backoff = RETRY_BACKOFF_BASE ** attempt
                        logger.warning(
                            f"Request failed: {resp.status} {resp.reason} | "
                            f"retry {attempt+1}/{MAX_RETRIES} after {backoff}s"
                        )
                        await asyncio.sleep(backoff)
                        continue

                # Success
                if resp.status < 400:
                    async with self._circuit_lock:
                        self._circuit_success()
                    return data

                # Client error (4xx except 429)
                logger.error(f"Request failed: {resp.status} {resp.reason}")
                self._errors += 1
                return {"success": False, "error": f"HTTP {resp.status}"}

            except asyncio.TimeoutError:
                last_error = "Request timeout"
                if attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Timeout | retry {attempt+1}/{MAX_RETRIES} after {backoff}s")
                    await asyncio.sleep(backoff)
                    continue

            except aiohttp.ClientError as e:
                last_error = str(e)
                if attempt < MAX_RETRIES - 1:
                    backoff = RETRY_BACKOFF_BASE ** attempt
                    logger.warning(f"Client error: {e} | retry {attempt+1}/{MAX_RETRIES} after {backoff}s")
                    await asyncio.sleep(backoff)
                    continue

        # All retries exhausted
        async with self._circuit_lock:
            self._circuit_failure()
        self._errors += 1
        logger.error(f"Request failed after {MAX_RETRIES} retries | last_error={last_error}")
        return {"success": False, "error": last_error or "Max retries exceeded"}

    async def query_engine(
        self,
        engine_id: str,
        query: str,
        mode: str = "FAST",
    ) -> EngineResult:
        """
        Query a specific engine by ID.

        Args:
            engine_id: Engine identifier (e.g., "LM05", "TX01")
            query: Natural language query
            mode: Response mode (FAST, DEFENSE, MEMO)

        Returns:
            EngineResult with response data
        """
        # Check cache first
        cache_key = self._cache_key(engine_id, query, mode)
        cached = self._check_cache(cache_key)
        if cached:
            logger.debug(f"Cache hit: {engine_id} | query={query[:50]}")
            return EngineResult(
                engine_id=engine_id,
                domain=cached.get("domain", ""),
                domain_label=cached.get("domain_label", ""),
                topic=cached.get("topic", ""),
                conclusion=cached.get("conclusion", cached.get("response", "")),
                confidence=cached.get("confidence", ConfidenceLevel.UNKNOWN.value),
                authority_weight=cached.get("authority_weight", 0),
                score=cached.get("score", 0.0),
                mode=cached.get("mode", mode),
                determinism_hash=cached.get("determinism_hash", ""),
                response_ms=cached.get("latency_ms", cached.get("response_ms", 0)),
                cached=True,
            )

        # Make request
        path = RUNTIME_ENDPOINTS["query_engine"].format(engine_id=engine_id)
        data = await self._request("POST", path, {"query": query, "mode": mode})

        if not data.get("success", False):
            logger.warning(f"Engine query failed: {engine_id} | error={data.get('error')}")
            return EngineResult(
                engine_id=engine_id,
                domain="",
                topic="",
                conclusion="",
                confidence=ConfidenceLevel.UNKNOWN.value,
                score=0.0,
                mode=mode,
                response_ms=0,
                cached=False,
            )

        # Store in cache
        self._store_cache(cache_key, data)

        return EngineResult(
            engine_id=engine_id,
            domain=data.get("domain", ""),
            domain_label=data.get("domain_label", ""),
            topic=data.get("topic", ""),
            conclusion=data.get("conclusion", data.get("response", "")),
            confidence=data.get("confidence", ConfidenceLevel.UNKNOWN.value),
            authority_weight=data.get("authority_weight", 0),
            score=data.get("score", 0.0),
            mode=data.get("mode", mode),
            determinism_hash=data.get("determinism_hash", ""),
            response_ms=data.get("latency_ms", data.get("response_ms", 0)),
            cached=False,
        )

    async def query_domain(
        self,
        domain: str,
        query: str,
        mode: str = "FAST",
    ) -> DomainResult:
        """
        Query all engines in a domain category.

        Args:
            domain: Domain category (e.g., "oil_gas", "tax", "legal")
            query: Natural language query
            mode: Response mode

        Returns:
            DomainResult with aggregated responses
        """
        path = RUNTIME_ENDPOINTS["query_domain"].format(domain=domain)
        data = await self._request("POST", path, {"query": query, "mode": mode})

        if not data.get("success", False):
            return DomainResult(
                domain=domain,
                results=[],
                total_engines=0,
                response_ms=0,
            )

        # Parse engine results
        engine_results = []
        for eng in data.get("engines", data.get("results", [])):
            engine_results.append(
                EngineResult(
                    engine_id=eng.get("engine_id", ""),
                    domain=eng.get("domain", domain),
                    domain_label=eng.get("domain_label", ""),
                    topic=eng.get("topic", ""),
                    conclusion=eng.get("conclusion", eng.get("response", "")),
                    confidence=eng.get("confidence", ConfidenceLevel.UNKNOWN.value),
                    authority_weight=eng.get("authority_weight", 0),
                    score=eng.get("score", eng.get("confidence_score", 0.0)),
                    mode=eng.get("mode", QueryMode.FAST.value),
                    determinism_hash=eng.get("determinism_hash", ""),
                    response_ms=eng.get("latency_ms", eng.get("response_ms", 0)),
                    cached=False,
                )
            )

        return DomainResult(
            domain=domain,
            results=engine_results,
            total_engines=data.get("total_engines", len(engine_results)),
            response_ms=data.get("response_ms", 0),
        )

    async def cross_domain_query(
        self,
        query: str,
        limit: int = 10,
    ) -> CrossDomainResult:
        """
        Search across all domains and return top matches.

        Args:
            query: Natural language query
            limit: Max number of results

        Returns:
            CrossDomainResult with ranked matches
        """
        path = RUNTIME_ENDPOINTS["cross_domain"]
        data = await self._request("POST", path, {"query": query, "limit": limit})

        if not data.get("success", False):
            return CrossDomainResult(query=query, results=[], domains_searched=0)

        # Parse results
        result_list = []
        for m in data.get("results", data.get("matches", [])):
            result_list.append(
                EngineResult(
                    engine_id=m.get("engine_id", ""),
                    domain=m.get("domain", ""),
                    domain_label=m.get("domain_label", ""),
                    topic=m.get("topic", ""),
                    conclusion=m.get("conclusion", m.get("response", "")),
                    confidence=m.get("confidence", ConfidenceLevel.UNKNOWN.value),
                    authority_weight=m.get("authority_weight", 0),
                    score=m.get("score", m.get("confidence_score", 0.0)),
                    mode=m.get("mode", QueryMode.FAST.value),
                    determinism_hash=m.get("determinism_hash", ""),
                    response_ms=m.get("latency_ms", m.get("response_ms", 0)),
                    cached=False,
                )
            )

        return CrossDomainResult(
            query=query,
            results=result_list,
            domains_searched=data.get("domains_searched", data.get("total_searched", 0)),
            response_ms=data.get("response_ms", 0),
        )

    async def global_search(
        self,
        query: str,
        limit: int = 10,
    ) -> list[EngineResult]:
        """
        Global semantic search across all engines.

        Args:
            query: Search query
            limit: Max results

        Returns:
            List of EngineResult ordered by relevance
        """
        path = RUNTIME_ENDPOINTS["global_search"]
        data = await self._request("POST", path, {"query": query, "limit": limit})

        if not data.get("success", False):
            return []

        results = []
        for r in data.get("results", []):
            results.append(
                EngineResult(
                    engine_id=r.get("engine_id", ""),
                    domain=r.get("domain", ""),
                    domain_label=r.get("domain_label", ""),
                    topic=r.get("topic", ""),
                    conclusion=r.get("conclusion", r.get("response", "")),
                    confidence=r.get("confidence", ConfidenceLevel.UNKNOWN.value),
                    authority_weight=r.get("authority_weight", 0),
                    score=r.get("score", 0.0),
                    mode=r.get("mode", QueryMode.FAST.value),
                    determinism_hash=r.get("determinism_hash", ""),
                    response_ms=r.get("latency_ms", r.get("response_ms", 0)),
                    cached=False,
                )
            )

        return results

    async def list_domains(self) -> list[dict]:
        """
        Get list of all available domain categories.

        Returns:
            List of domain info dicts
        """
        path = RUNTIME_ENDPOINTS["list_domains"]
        data = await self._request("GET", path)

        if not data.get("success", False):
            return []

        return data.get("domains", [])

    async def batch_classify(
        self,
        samples: list[FileSample],
        concurrency: int = 20,
    ) -> list[ClassificationResult]:
        """
        Classify multiple file samples in parallel batches.

        Args:
            samples: List of FileSample objects to classify
            concurrency: Max concurrent queries

        Returns:
            List of ClassificationResult in same order as input
        """
        semaphore = asyncio.Semaphore(concurrency)
        results: list[ClassificationResult | None] = [None] * len(samples)

        async def classify_one(idx: int, sample: FileSample) -> None:
            """Classify a single sample and store result."""
            async with semaphore:
                try:
                    # Build query from keywords
                    query = f"File analysis: {' '.join(sample.keywords[:10])}"

                    # Choose query method based on detected domain
                    if sample.detected_domain != "UNKNOWN" and sample.domain_confidence >= 0.5:
                        # Query specific domain
                        domain_result = await self.query_domain(
                            sample.detected_domain,
                            query,
                            mode="FAST",
                        )

                        # Pick best engine from domain
                        if domain_result.engines:
                            best = max(domain_result.engines, key=lambda e: e.confidence)
                            classification = Classification(
                                tier=ClassificationTier.TIER_1,
                                domain=sample.detected_domain,
                                subdomain=best.engine_id,
                                confidence=best.confidence,
                                rationale=best.response[:200],
                            )
                        else:
                            classification = Classification(
                                tier=ClassificationTier.TIER_3,
                                domain="UNKNOWN",
                                subdomain="",
                                confidence=0.0,
                                rationale="No engines responded",
                            )
                    else:
                        # Cross-domain search
                        cross_result = await self.cross_domain_query(query, limit=3)

                        if cross_result.matches:
                            best = cross_result.matches[0]
                            # Determine tier based on confidence
                            if best.confidence >= 0.8:
                                tier = ClassificationTier.TIER_1
                            elif best.confidence >= 0.6:
                                tier = ClassificationTier.TIER_2
                            else:
                                tier = ClassificationTier.TIER_3

                            classification = Classification(
                                tier=tier,
                                domain=sample.detected_domain,
                                subdomain=best.engine_id,
                                confidence=best.confidence,
                                rationale=best.response[:200],
                            )
                        else:
                            classification = Classification(
                                tier=ClassificationTier.TIER_3,
                                domain="UNKNOWN",
                                subdomain="",
                                confidence=0.0,
                                rationale="No matches found",
                            )

                    results[idx] = ClassificationResult(
                        file_path=sample.file_path,
                        classification=classification,
                        query_used=query,
                        latency_ms=0.0,  # Aggregate across queries
                    )

                except Exception as e:
                    logger.error(f"Classification failed for {sample.file_path}: {e}")
                    results[idx] = ClassificationResult(
                        file_path=sample.file_path,
                        classification=Classification(
                            tier=ClassificationTier.TIER_3,
                            domain="ERROR",
                            subdomain="",
                            confidence=0.0,
                            rationale=f"Error: {str(e)[:200]}",
                        ),
                        query_used=query if 'query' in locals() else "",
                        latency_ms=0.0,
                    )

        # Launch all classifications
        tasks = [classify_one(i, sample) for i, sample in enumerate(samples)]
        await asyncio.gather(*tasks)

        # Filter out any None results (shouldn't happen)
        return [r for r in results if r is not None]

    async def health_check(self) -> bool:
        """
        Check if Echo Engine Runtime is healthy and reachable.

        Returns:
            True if healthy, False otherwise
        """
        try:
            path = RUNTIME_ENDPOINTS["health"]
            data = await self._request("GET", path)
            return data.get("success", False) and data.get("status") == "healthy"
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    def get_metrics(self) -> dict:
        """
        Get client performance metrics.

        Returns:
            Dict with metrics: requests, cache_hit_rate, error_rate, latencies
        """
        cache_hit_rate = (
            self._cache_hits / self._total_requests if self._total_requests > 0 else 0.0
        )
        error_rate = (
            self._errors / self._total_requests if self._total_requests > 0 else 0.0
        )

        # Calculate latency percentiles
        p50 = p95 = p99 = 0.0
        if self._latencies:
            sorted_latencies = sorted(self._latencies)
            n = len(sorted_latencies)
            p50 = sorted_latencies[int(n * 0.50)]
            p95 = sorted_latencies[int(n * 0.95)]
            p99 = sorted_latencies[int(n * 0.99)]

        return {
            "total_requests": self._total_requests,
            "cache_hits": self._cache_hits,
            "cache_hit_rate": cache_hit_rate,
            "errors": self._errors,
            "error_rate": error_rate,
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "latency_p99_ms": p99,
            "circuit_state": self._circuit_state.value,
            "circuit_failures": self._circuit_failures,
            "cached_entries": len(self._cache),
        }
