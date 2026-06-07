import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from url_collector import URLCollector


class TestURLCollector:
    def setup_method(self):
        self.collector = URLCollector()

    # --- HTML URL extraction (no network calls - just regex parsing) ---

    def test_extract_a_href(self):
        html = '<a href="https://example.com/page1">link</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/page1" in urls

    def test_extract_script_src(self):
        html = '<script src="https://example.com/app.js"></script>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/app.js" in urls

    def test_extract_img_src(self):
        html = '<img src="https://example.com/image.png">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/image.png" in urls

    def test_extract_link_href(self):
        html = '<link href="https://example.com/style.css" rel="stylesheet">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/style.css" in urls

    def test_extract_form_action(self):
        html = '<form action="https://example.com/submit">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/submit" in urls

    def test_extract_iframe_src(self):
        html = '<iframe src="https://example.com/embed"></iframe>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/embed" in urls

    def test_extract_video_src(self):
        html = '<video src="https://example.com/video.mp4"></video>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/video.mp4" in urls

    def test_extract_audio_src(self):
        html = '<audio src="https://example.com/audio.mp3"></audio>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/audio.mp3" in urls

    def test_extract_frame_src(self):
        html = '<frame src="https://example.com/frame">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/frame" in urls

    def test_extract_embed_src(self):
        html = '<embed src="https://example.com/embed.swf">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/embed.swf" in urls

    def test_extract_object_data(self):
        html = '<object data="https://example.com/data"></object>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/data" in urls

    def test_extract_source_src(self):
        html = '<source src="https://example.com/video.webm">'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/video.webm" in urls

    def test_extract_multiple_tags(self):
        html = """
        <a href="https://example.com/page1">link1</a>
        <img src="https://example.com/pic.jpg">
        <script src="https://example.com/app.js"></script>
        """
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert len(urls) >= 3

    def test_no_html_content(self):
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_empty_html(self):
        self.collector.load_html("")
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    # --- Ignored URL schemes ---

    def test_ignores_javascript_href(self):
        html = '<a href="javascript:void(0)">click</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_ignores_mailto(self):
        html = '<a href="mailto:test@example.com">email</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_ignores_tel(self):
        html = '<a href="tel:+1234567890">call</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_ignores_data_uri(self):
        html = '<a href="data:text/html,hello">data</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_ignores_anchor_only(self):
        html = '<a href="#section">anchor</a>'
        self.collector.load_html(html)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    # --- Domain grouping ---

    def test_group_by_domain(self):
        self.collector.load_html("""
            <a href="https://example.com/page1">link1</a>
            <a href="https://example.com/page2">link2</a>
            <a href="https://other.com/page">link3</a>
        """)
        self.collector.extract_urls_from_html()
        groups = self.collector.group_by_domain()
        assert "example.com" in groups
        assert "other.com" in groups
        assert len(groups["example.com"]) == 2
        assert len(groups["other.com"]) == 1

    def test_group_by_domain_empty(self):
        groups = self.collector.group_by_domain()
        assert groups == {}

    # --- URL normalization ---

    def test_normalize_url_lowercases_scheme(self):
        normalized = self.collector.normalize_url("HTTP://EXAMPLE.COM/Path")
        assert normalized == "http://example.com/Path"

    def test_normalize_url_lowercases_hostname(self):
        normalized = self.collector.normalize_url("https://Example.COM/Path")
        assert normalized == "https://example.com/Path"

    def test_normalize_url_removes_trailing_slash(self):
        normalized = self.collector.normalize_url("https://example.com/")
        assert normalized == "https://example.com/"

    def test_normalize_url_preserves_query(self):
        normalized = self.collector.normalize_url("https://example.com/page?q=1&r=2")
        assert "?q=1&r=2" in normalized

    def test_normalize_url_preserves_fragment(self):
        normalized = self.collector.normalize_url("https://example.com/page#section")
        assert "#section" in normalized

    def test_normalize_url_deduplicates(self):
        self.collector.load_html("""
            <a href="https://EXAMPLE.com/page">link1</a>
            <a href="https://example.com/page">link2</a>
        """)
        urls = self.collector.extract_urls_from_html()
        assert len(urls) == 1

    # --- Scope filtering ---

    def test_scope_filter_in_scope(self):
        self.collector.set_scope(["example.com"])
        self.collector.load_html("""
            <a href="https://example.com/page">in scope</a>
        """)
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/page" in urls

    def test_scope_filter_out_of_scope(self):
        self.collector.set_scope(["example.com"])
        self.collector.load_html("""
            <a href="https://evil.com/page">out of scope</a>
        """)
        urls = self.collector.extract_urls_from_html()
        assert urls == []

    def test_scope_filter_mixed(self):
        self.collector.set_scope(["allowed.com"])
        self.collector.load_html("""
            <a href="https://allowed.com/page1">good</a>
            <a href="https://evil.com/page2">bad</a>
            <a href="https://sub.allowed.com/page3">subdomain</a>
        """)
        urls = self.collector.extract_urls_from_html()
        assert "https://allowed.com/page1" in urls
        assert "https://evil.com/page2" not in urls
        assert "https://sub.allowed.com/page3" in urls

    def test_scope_filter_no_scope_returns_all(self):
        self.collector.load_html("""
            <a href="https://example.com/page1">good</a>
            <a href="https://other.com/page2">also good</a>
        """)
        urls = self.collector.extract_urls_from_html()
        assert len(urls) == 2

    def test_scope_with_wildcard(self):
        self.collector.set_scope(["*.example.com"])
        self.collector.load_html('<a href="https://sub.example.com/page">link</a>')
        urls = self.collector.extract_urls_from_html()
        assert "https://sub.example.com/page" in urls

    # --- Relative URL resolution ---

    def test_resolve_relative_url_with_base(self):
        self.collector = URLCollector(source_url="https://example.com/subdir/")
        resolved = self.collector.resolve_url("page.html")
        assert resolved == "https://example.com/subdir/page.html"

    def test_resolve_relative_url_root_relative(self):
        self.collector = URLCollector(source_url="https://example.com/subdir/page.html")
        resolved = self.collector.resolve_url("/css/style.css")
        assert resolved == "https://example.com/css/style.css"

    def test_resolve_absolute_url_unchanged(self):
        self.collector = URLCollector(source_url="https://example.com/")
        resolved = self.collector.resolve_url("https://other.com/page")
        assert resolved == "https://other.com/page"

    def test_resolve_protocol_relative(self):
        self.collector = URLCollector(source_url="https://example.com/")
        resolved = self.collector.resolve_url("//other.com/page")
        assert resolved == "https://other.com/page"

    def test_resolve_short_url_returns_none(self):
        resolved = self.collector.resolve_url("a")
        assert resolved is None

    def test_resolve_empty_url(self):
        resolved = self.collector.resolve_url("")
        assert resolved is None

    def test_resolve_relative_in_html_extraction(self):
        self.collector = URLCollector(source_url="https://example.com/")
        self.collector.load_html('<a href="relative/path">link</a>')
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/relative/path" in urls

    def test_resolve_relative_in_html_with_subdir(self):
        self.collector = URLCollector(source_url="https://example.com/blog/")
        self.collector.load_html('<img src="../images/pic.jpg">')
        urls = self.collector.extract_urls_from_html()
        assert "https://example.com/images/pic.jpg" in urls

    # --- is_valid_url ---

    def test_is_valid_url_full(self):
        assert self.collector.is_valid_url("https://example.com/path") is True

    def test_is_valid_url_invalid(self):
        assert self.collector.is_valid_url("") is False

    def test_is_valid_url_short(self):
        assert self.collector.is_valid_url("ab") is False

    def test_is_valid_url_ignored_scheme(self):
        assert self.collector.is_valid_url("javascript:alert(1)") is False

    # --- extract_urls_from_text ---

    def test_extract_urls_from_text(self):
        text = "Visit https://example.com/page for details"
        self.collector.extract_urls_from_text(text)
        urls = self.collector.get_sorted_urls()
        assert "https://example.com/page" in urls

    def test_extract_urls_from_text_multiple(self):
        text = "Links: https://a.com and https://b.com and http://c.com"
        self.collector.extract_urls_from_text(text)
        urls = self.collector.get_sorted_urls()
        assert len(urls) == 3

    def test_extract_urls_from_text_empty(self):
        self.collector.extract_urls_from_text("No URLs here")
        assert self.collector.get_sorted_urls() == []

    # --- extract_form_actions ---

    def test_extract_form_actions(self):
        self.collector = URLCollector(source_url="https://example.com/")
        self.collector.load_html('<form action="/login" method="POST">')
        forms = self.collector.extract_form_actions()
        assert len(forms) >= 1

    def test_extract_form_actions_no_html(self):
        forms = self.collector.extract_form_actions()
        assert forms == []

    # --- get_sorted_urls ---

    def test_get_sorted_urls_returns_sorted(self):
        self.collector.load_html("""
            <a href="https://z.com/page">z</a>
            <a href="https://a.com/page">a</a>
        """)
        self.collector.extract_urls_from_html()
        urls = self.collector.get_sorted_urls()
        assert urls == sorted(urls)

    # --- get_url_statistics ---

    def test_get_url_statistics_empty(self):
        stats = self.collector.get_url_statistics()
        assert stats["total"] == 0

    def test_get_url_statistics_with_urls(self):
        self.collector.load_html("""
            <a href="https://example.com/page1">link1</a>
            <a href="https://example.com/page2">link2</a>
        """)
        self.collector.extract_urls_from_html()
        stats = self.collector.get_url_statistics()
        assert stats["total"] == 2
        assert stats["https_ratio"] == 1.0

    # --- Filter methods ---

    def test_filter_by_extension(self):
        self.collector.load_html("""
            <link href="https://example.com/style.css" rel="stylesheet">
            <script src="https://example.com/app.js"></script>
            <a href="https://example.com/page.html">page</a>
        """)
        self.collector.extract_urls_from_html()
        css_files = self.collector.filter_by_extension([".css"])
        assert len(css_files) == 1
        assert css_files[0].endswith(".css")

    def test_filter_by_pattern(self):
        self.collector.load_html("""
            <a href="https://example.com/api/v1/users">api</a>
            <a href="https://example.com/about">about</a>
        """)
        self.collector.extract_urls_from_html()
        api_urls = self.collector.filter_by_pattern("/api/")
        assert len(api_urls) == 1

    # --- get_query_params / get_unique_params ---

    def test_get_query_params_with_url(self):
        params = self.collector.get_query_params("https://example.com/page?q=hello&r=world")
        assert params.get("q") == ["hello"]
        assert params.get("r") == ["world"]

    def test_get_query_params_empty(self):
        params = self.collector.get_query_params("https://example.com/page")
        assert params == {}

    def test_get_unique_params(self):
        self.collector.load_html("""
            <a href="https://example.com/page?q=1&r=2">a</a>
            <a href="https://example.com/other?q=3&s=4">b</a>
        """)
        self.collector.extract_urls_from_html()
        params = self.collector.get_unique_params()
        assert "q" in params
        assert "r" in params
        assert "s" in params

    # --- load_html ---

    def test_load_html_sets_content(self):
        html = "<html><body>test</body></html>"
        self.collector.load_html(html)
        assert self.collector.html_content == html

    # --- Tag counting ---

    def test_tag_counts(self):
        html = """
            <a href="https://a.com/page1">a1</a>
            <a href="https://a.com/page2">a2</a>
            <img src="https://a.com/pic.jpg">
        """
        self.collector.load_html(html)
        self.collector.extract_urls_from_html()
        assert self.collector.tag_counts.get("a", 0) == 2
        assert self.collector.tag_counts.get("img", 0) == 1
