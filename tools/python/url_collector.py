#!/usr/bin/env python3
"""
url_collector.py — URL Collection & Analysis Tool

Collects, validates, filters, and exports URLs from HTML pages, sitemaps,
and text sources. Supports scope filtering, domain grouping, CSV/JSON export,
recursive crawling, form action extraction, JS source discovery, and more.

Features: HTML tag extraction, scope filtering, relative URL resolution,
sitemap.xml parsing, form action discovery, JS source collection,
stylesheet URL extraction, image URL collection, iframe source discovery,
domain grouping, CSV/JSON/TXT export, statistics, deduplication,
recursive depth crawling, robots.txt parsing, anchor validation,
URL normalization, parameter extraction, broken link detection,
and rate-limited fetching.
"""

import csv
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.robotparser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs


@dataclass
class CollectedURL:
    url: str
    tag: str = ""
    domain: str = ""
    path: str = ""
    params: str = ""
    depth: int = 0
    status: Optional[int] = None
    content_type: str = ""


class URLCollector:
    """
    Collect and analyze URLs from HTML content with 20+ features.

    Parses HTML tags, filters by scope, resolves relatives,
    groups by domain, exports to multiple formats, supports
    recursive crawling, rate limiting, and more.
    """

    TAG_PATTERNS = {
        "a": re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "link": re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE),
        "script": re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "img": re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "form": re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE),
        "iframe": re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "source": re.compile(r'<source[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "video": re.compile(r'<video[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "audio": re.compile(r'<audio[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "frame": re.compile(r'<frame[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "embed": re.compile(r'<embed[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
        "object": re.compile(r'<object[^>]+data=["\']([^"\']+)["\']', re.IGNORECASE),
        "meta": re.compile(r'<meta[^>]+content=["\']([^"\']+)["\']', re.IGNORECASE),
    }

    IGNORE_PATTERNS = re.compile(
        r'^(javascript|mailto|tel|sms|fax|skype|whatsapp|data|blob|#):',
        re.IGNORECASE
    )

    def __init__(self, source_url: str = ""):
        self.source_url = source_url
        self.base_url = source_url
        self.scope_domains: List[str] = []
        self.urls: Dict[str, CollectedURL] = {}
        self.tag_counts: Dict[str, int] = {}
        self.html_content: str = ""
        self.crawled: Set[str] = set()
        self.max_depth: int = 2
        self.rate_delay: float = 0.5
        self.timeout: int = 15

    def load_html(self, html_content: str) -> None:
        self.html_content = html_content

    def fetch(self, url: Optional[str] = None) -> bool:
        target = url or self.source_url
        if not target:
            return False
        try:
            import requests
            resp = requests.get(target, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,*/*",
            }, timeout=self.timeout, verify=True)
            resp.raise_for_status()
            self.html_content = resp.text
            self.source_url = target
            self.base_url = target
            return True
        except ImportError:
            print("[!] requests library required.", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] Failed to fetch {target}: {e}", file=sys.stderr)
            return False

    def set_scope(self, domains: List[str]) -> None:
        self.scope_domains = [d.lower().lstrip("*.") for d in domains]

    def _is_in_scope(self, url: str) -> bool:
        if not self.scope_domains:
            return True
        try:
            hostname = urlparse(url).hostname or ""
            hostname = hostname.lower()
            return any(domain in hostname or hostname.endswith("." + domain) for domain in self.scope_domains)
        except Exception:
            return False

    def is_valid_url(self, url: str) -> bool:
        if not url or len(url) < 3:
            return False
        if self.IGNORE_PATTERNS.match(url):
            return False
        if url.startswith("//"):
            url = "https:" + url
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except Exception:
            return False

    def normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip("/") or "/"
            query = "?" + parsed.query if parsed.query else ""
            fragment = "#" + parsed.fragment if parsed.fragment else ""
            return f"{scheme}://{netloc}{path}{query}{fragment}"
        except Exception:
            return url

    def resolve_url(self, url: str) -> Optional[str]:
        url = url.strip()
        if not url or len(url) < 2:
            return None
        if url.startswith("//"):
            return "https:" + url
        if url.startswith(("http://", "https://")):
            return url
        try:
            if self.base_url:
                absolute = urljoin(self.base_url, url)
                parsed = urlparse(absolute)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{'?' + parsed.query if parsed.query else ''}"
            return None
        except Exception:
            return None

    def extract_urls_from_html(self) -> List[str]:
        if not self.html_content:
            return []
        self.urls.clear()
        self.tag_counts = {}
        for tag, pattern in self.TAG_PATTERNS.items():
            found = pattern.findall(self.html_content)
            self.tag_counts[tag] = len(found)
            for u in found:
                resolved = self.resolve_url(u)
                if resolved and self.is_valid_url(resolved) and self._is_in_scope(resolved):
                    normalized = self.normalize_url(resolved)
                    if normalized not in self.urls:
                        self.urls[normalized] = CollectedURL(url=normalized, tag=tag)
        return self.get_sorted_urls()

    def extract_urls_from_text(self, text: str) -> List[str]:
        pattern = re.compile(
            r'(?:https?|ftp)://(?:[^\s<>"\'{}|\\^`\[\]]+)(?::\d+)?(?:/[^\s<>"\'{}|\\^`\[\]]*)?(?:\?[^\s<>"\'{}|\\^`\[\]]*)?(?:#[^\s<>"\'{}|\\^`\[\]]*)?',
            re.IGNORECASE
        )
        for url in pattern.findall(text):
            url = url.rstrip(".,;:!?)]}>")
            if self._is_in_scope(url) and self.is_valid_url(url):
                normalized = self.normalize_url(url)
                if normalized not in self.urls:
                    self.urls[normalized] = CollectedURL(url=normalized, tag="text")
        return self.get_sorted_urls()

    def parse_sitemap(self, sitemap_url: str) -> List[str]:
        try:
            import requests
            resp = requests.get(sitemap_url, timeout=self.timeout)
            resp.raise_for_status()
            urls = re.findall(r'<loc>([^<]+)</loc>', resp.text)
            for u in urls:
                normalized = self.normalize_url(u.strip())
                if normalized not in self.urls and self._is_in_scope(normalized):
                    self.urls[normalized] = CollectedURL(url=normalized, tag="sitemap")
            return self.get_sorted_urls()
        except Exception as e:
            print(f"[!] Sitemap parse failed: {e}", file=sys.stderr)
            return []

    def parse_robots_txt(self) -> List[str]:
        try:
            import urllib.robotparser
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(urljoin(self.base_url, "/robots.txt"))
            rp.read()
            sitemaps = rp.site_maps()
            if sitemaps:
                for sm in sitemaps:
                    self.parse_sitemap(sm)
            return self.get_sorted_urls()
        except Exception:
            return []

    def crawl_recursive(self, start_url: str, max_depth: int = 2) -> List[str]:
        self.max_depth = max_depth
        self.crawled.clear()
        self._crawl(start_url, depth=0)
        return self.get_sorted_urls()

    def _crawl(self, url: str, depth: int) -> None:
        if depth > self.max_depth or url in self.crawled:
            return
        self.crawled.add(url)
        if self.rate_delay > 0:
            time.sleep(self.rate_delay)
        collector = URLCollector(source_url=url)
        if not collector.fetch(url):
            return
        urls = collector.extract_urls_from_html()
        for u in urls:
            if u not in self.urls:
                self.urls[u] = CollectedURL(url=u, tag="crawl", depth=depth)
        if depth < self.max_depth:
            with ThreadPoolExecutor(max_workers=3) as ex:
                ex.map(lambda x: self._crawl(x, depth + 1), urls[:10])

    def extract_form_actions(self) -> List[Dict[str, str]]:
        if not self.html_content:
            return []
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', self.html_content, re.IGNORECASE)
        results = []
        for action in forms:
            resolved = self.resolve_url(action)
            if resolved:
                results.append({"action": resolved, "method": "GET"})
                method_match = re.search(r'method=["\'](POST|GET|PUT|DELETE)["\']', self.html_content)
                if method_match:
                    results[-1]["method"] = method_match.group(1)
        return results

    def get_query_params(self, url: Optional[str] = None) -> Dict[str, List[str]]:
        target = url or (list(self.urls.keys())[0] if self.urls else "")
        if not target:
            return {}
        return parse_qs(urlparse(target).query)

    def get_unique_params(self) -> Set[str]:
        params: Set[str] = set()
        for u in self.urls:
            parsed = urlparse(u)
            params.update(parse_qs(parsed.query).keys())
        return params

    def get_url_statistics(self) -> Dict[str, Any]:
        total = len(self.urls)
        if total == 0:
            return {"total": 0}
        domains = Counter()
        tags = Counter()
        depths = Counter()
        for u in self.urls.values():
            domains[u.domain or urlparse(u.url).hostname or "unknown"] += 1
            tags[u.tag] += 1
            depths[u.depth] += 1
        return {
            "total": total,
            "unique_domains": len(domains),
            "domains": dict(domains.most_common(10)),
            "by_tag": dict(tags.most_common()),
            "by_depth": dict(sorted(depths.items())),
            "has_query_params": sum(1 for u in self.urls if urlparse(u).query),
            "has_fragments": sum(1 for u in self.urls if urlparse(u).fragment),
            "https_ratio": sum(1 for u in self.urls if u.startswith("https")) / max(total, 1),
        }

    def export_json(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        data = {
            "statistics": self.get_url_statistics(),
            "urls": self.get_sorted_urls(),
            "detailed": [vars(u) for u in self.urls.values()],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def export_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["#", "URL", "Domain", "Path", "Tag", "Depth"])
            for i, u in enumerate(self.urls.values(), 1):
                parsed = urlparse(u.url)
                w.writerow([i, u.url, parsed.hostname, parsed.path, u.tag, u.depth])

    def export_txt(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(self.get_sorted_urls()))

    def get_sorted_urls(self) -> List[str]:
        return sorted(self.urls.keys())

    def group_by_domain(self) -> Dict[str, List[str]]:
        groups: Dict[str, List[str]] = {}
        for url in self.get_sorted_urls():
            domain = urlparse(url).hostname or "unknown"
            groups.setdefault(domain, []).append(url)
        return groups

    def filter_by_extension(self, extensions: List[str]) -> List[str]:
        return [u for u in self.get_sorted_urls() if any(u.endswith(ext) for ext in extensions)]

    def filter_by_pattern(self, pattern: str) -> List[str]:
        compiled = re.compile(pattern, re.IGNORECASE)
        return [u for u in self.get_sorted_urls() if compiled.search(u)]

    def check_broken_links(self, urls: Optional[List[str]] = None, max_workers: int = 5) -> List[Dict[str, Any]]:
        targets = urls or self.get_sorted_urls()
        results: List[Dict[str, Any]] = []
        def check(url: str) -> Dict[str, Any]:
            try:
                import requests
                resp = requests.head(url, timeout=5, allow_redirects=True)
                return {"url": url, "status": resp.status_code, "ok": resp.status_code < 400}
            except Exception as e:
                return {"url": url, "status": None, "ok": False, "error": str(e)}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for r in ex.map(check, targets):
                results.append(r)
        return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python url_collector.py <url> [--scope domain] [--output dir]")
        sys.exit(1)
    url = sys.argv[1]
    collector = URLCollector(source_url=url)
    scope = [sys.argv[i + 1] for i, arg in enumerate(sys.argv) if arg == "--scope" and i + 1 < len(sys.argv)]
    if scope:
        collector.set_scope(scope)
    if collector.fetch(url):
        urls = collector.extract_urls_from_html()
        stats = collector.get_url_statistics()
        print(json.dumps(stats, indent=2))
        out_dir = sys.argv[sys.argv.index("--output") + 1] if "--output" in sys.argv else "."
        collector.export_csv(os.path.join(out_dir, "urls.csv"))
