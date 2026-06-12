import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from extract_apis import ApiExtractor, Endpoint, EndpointDatabase

class TestEndpoint:
    def test_endpoint_create(self):
        e = Endpoint(method="GET", path="/api/users", params=[], auth=False)
        assert e.method == "GET"
        assert e.path == "/api/users"

    def test_endpoint_to_dict(self):
        e = Endpoint(method="POST", path="/api/login", params=["user", "pass"], auth=True)
        d = e.to_dict()
        assert d["method"] == "POST"
        assert d["auth"] is True

class TestEndpointDatabase:
    def test_database_init(self):
        db = EndpointDatabase()
        assert db.endpoints == []

    def test_add_endpoint(self):
        db = EndpointDatabase()
        e = Endpoint(method="GET", path="/test", params=[], auth=False)
        db.add(e)
        assert len(db.endpoints) == 1

    def test_get_summary_empty(self):
        db = EndpointDatabase()
        s = db.get_summary()
        assert s["total"] == 0

    def test_get_summary_with_data(self):
        db = EndpointDatabase()
        db.add(Endpoint(method="GET", path="/a", params=[], auth=False))
        db.add(Endpoint(method="POST", path="/b", params=[], auth=True))
        s = db.get_summary()
        assert s["total"] == 2
        assert s["by_method"]["GET"] == 1

class TestApiExtractor:
    def test_init_defaults(self):
        ext = ApiExtractor()
        assert ext.silent is False
        assert ext.depth == 2

    def test_init_custom(self):
        ext = ApiExtractor(silent=True, depth=5)
        assert ext.silent is True
        assert ext.depth == 5

    def test_add_pattern(self):
        ext = ApiExtractor()
        ext.add_pattern("CUSTOM", r"/custom/[\w-]+")
        assert "CUSTOM" in ext.patterns

    def test_parse_html_links(self):
        ext = ApiExtractor()
        html = '<a href="/api/users">Users</a><a href="/api/login">Login</a>'
        urls = ext._parse_html_links(html, base_url="http://test.com")
        assert "/api/users" in urls
        assert "/api/login" in urls

    def test_parse_html_scripts(self):
        ext = ApiExtractor()
        html = '<script src="/app.js"></script><script>alert(1)</script>'
        scripts = ext._parse_html_scripts(html, base_url="http://test.com")
        assert "/app.js" in scripts

    def test_pattern_rest_endpoint(self):
        ext = ApiExtractor()
        ext.add_pattern("REST", r"/api/[\w/]+")
        matches = ext._match_patterns("call /api/v2/users/123 profile")
        assert any("/api/v2/users/123" in m for m in matches)

    def test_get_summary_empty(self):
        ext = ApiExtractor()
        s = ext.get_summary()
        assert s["endpoints_found"] == 0

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "extract_apis", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
        assert "--help" in r.stdout or "usage" in r.stdout
