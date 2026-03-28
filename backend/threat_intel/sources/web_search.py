"""Web search for threat intelligence research.

Supports multiple search backends with graceful fallback:
1. SerpAPI (if SERPAPI_KEY configured)
2. Brave Search API (if BRAVE_API_KEY configured)
3. DuckDuckGo (no API key needed, via duckduckgo_search)
4. Returns empty results if nothing is available
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Optional dependencies
_httpx_available = False
try:
    import httpx as _httpx

    _httpx_available = True
except ImportError:
    pass

_ddg_available = False
try:
    from duckduckgo_search import DDGS as _DDGS

    _ddg_available = True
except ImportError:
    pass


class WebSearchSource:
    """Search the web for threat intelligence.

    Automatically selects the best available search backend based on
    configured API keys and installed packages.
    """

    def __init__(
        self,
        serpapi_key: str | None = None,
        brave_api_key: str | None = None,
    ) -> None:
        self._serpapi_key = serpapi_key or os.environ.get("SERPAPI_KEY", "")
        self._brave_api_key = brave_api_key or os.environ.get("BRAVE_API_KEY", "")

    # ------------------------------------------------------------------
    # Main search entry point
    # ------------------------------------------------------------------

    async def search(self, query: str, max_results: int = 10) -> list[dict[str, Any]]:
        """Search using the best available backend.

        Returns a list of ``{title, url, snippet}`` dicts.
        """
        # Strategy 1: SerpAPI
        if self._serpapi_key and _httpx_available:
            try:
                return await self._search_serpapi(query, max_results)
            except Exception as exc:
                logger.warning("SerpAPI search failed: %s", exc)

        # Strategy 2: Brave
        if self._brave_api_key and _httpx_available:
            try:
                return await self._search_brave(query, max_results)
            except Exception as exc:
                logger.warning("Brave search failed: %s", exc)

        # Strategy 3: DuckDuckGo (no API key)
        if _ddg_available:
            try:
                return await self._search_ddg(query, max_results)
            except Exception as exc:
                logger.warning("DuckDuckGo search failed: %s", exc)

        logger.info(
            "No web search backend available. Install duckduckgo_search or configure "
            "SERPAPI_KEY / BRAVE_API_KEY for web search capabilities."
        )
        return []

    # ------------------------------------------------------------------
    # Content extraction
    # ------------------------------------------------------------------

    async def fetch_and_extract(self, url: str) -> dict[str, Any]:
        """Fetch a URL and extract text content.

        Returns ``{url, title, text, extracted_at}`` or an error dict.
        """
        if not _httpx_available:
            return {"url": url, "error": "httpx not installed"}

        try:
            async with _httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "JotiSim/2.0 ThreatIntelBot"})
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            return {"url": url, "error": str(exc)}

        # Try beautifulsoup4 for clean extraction
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html, "html.parser")

            # Remove script and style elements
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.decompose()

            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            text = soup.get_text(separator="\n", strip=True)
            # Truncate to ~10k chars to avoid huge payloads
            text = text[:10000]

            return {
                "url": url,
                "title": title,
                "text": text,
                "extracted_at": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat(),
            }
        except ImportError:
            # No beautifulsoup4 — return raw (truncated) HTML
            return {
                "url": url,
                "title": "",
                "text": html[:10000],
                "extracted_at": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat(),
            }

    # ------------------------------------------------------------------
    # Backend implementations
    # ------------------------------------------------------------------

    async def _search_serpapi(self, query: str, max_results: int) -> list[dict[str, Any]]:
        """Search via SerpAPI (Google results)."""
        async with _httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://serpapi.com/search",
                params={
                    "q": query,
                    "api_key": self._serpapi_key,
                    "num": max_results,
                    "engine": "google",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        results: list[dict[str, Any]] = []
        for item in data.get("organic_results", [])[:max_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
            })
        return results

    async def _search_brave(self, query: str, max_results: int) -> list[dict[str, Any]]:
        """Search via Brave Search API."""
        async with _httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query, "count": max_results},
                headers={
                    "X-Subscription-Token": self._brave_api_key,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        results: list[dict[str, Any]] = []
        for item in data.get("web", {}).get("results", [])[:max_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("description", ""),
            })
        return results

    async def _search_ddg(self, query: str, max_results: int) -> list[dict[str, Any]]:
        """Search via DuckDuckGo (no API key needed)."""
        import asyncio

        def _do_search() -> list[dict[str, Any]]:
            with _DDGS() as ddgs:
                raw = list(ddgs.text(query, max_results=max_results))
            return [
                {
                    "title": r.get("title", ""),
                    "url": r.get("href", r.get("link", "")),
                    "snippet": r.get("body", r.get("snippet", "")),
                }
                for r in raw
            ]

        return await asyncio.to_thread(_do_search)
