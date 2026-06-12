import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from extract_js import JsExtractor

class TestJsExtractor:
    def test_init_defaults(self):
        ext = JsExtractor()
        assert ext.secret_patterns is not None
        assert len(ext.secret_patterns) > 0

    def test_init_custom(self):
        ext = JsExtractor(depth=3, timeout=60)
        assert ext.depth == 3
        assert ext.timeout == 60

    def test_extract_inline_js(self):
        ext = JsExtractor()
        html = "<script>var x = 1;</script><div>hello</div><script>let y = 2;</script>"
        scripts = ext._extract_inline_js(html)
        assert len(scripts) == 2
        assert "var x = 1;" in scripts
        assert "let y = 2;" in scripts

    def test_extract_external_js_urls(self):
        ext = JsExtractor()
        html = '<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        urls = ext._extract_external_js_urls(html, base_url="http://test.com")
        assert "/app.js" in urls or "http://test.com/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls

    def test_extract_external_js_empty(self):
        ext = JsExtractor()
        html = "<html><body>no scripts</body></html>"
        urls = ext._extract_external_js_urls(html, base_url="http://test.com")
        assert urls == []

    def test_scan_for_secrets_aws_key(self):
        ext = JsExtractor()
        text = 'aws_secret_access_key = "aB3xK7mR9pW2vF5jH8nQ1tY4uI6oP0zC4eX7yL29"'
        findings = ext._scan_for_secrets(text)
        aws = [f for f in findings if "AWS" in f.get("name", "")]
        assert len(aws) >= 1

    def test_scan_for_secrets_jwt(self):
        ext = JsExtractor()
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dyo1a0bQ7mQ9QK0Q0J0g0Q0Q0Q0Q0Q0Q0Q0Q0Q0Q"
        findings = ext._scan_for_secrets(text)
        jwt = [f for f in findings if "JWT" in f.get("name", "")]
        assert len(jwt) >= 1

    def test_scan_for_secrets_empty(self):
        ext = JsExtractor()
        findings = ext._scan_for_secrets("")
        assert findings == []

    def test_extract_urls_from_js(self):
        ext = JsExtractor()
        js = 'fetch("/api/users").then(r => r.json()); xhr.open("POST", "/api/login");'
        urls = ext._extract_urls_from_js(js)
        assert "/api/users" in urls
        assert "/api/login" in urls

    def test_extract_urls_from_js_with_domain(self):
        ext = JsExtractor()
        js = 'var url = "https://api.example.com/v2/endpoint";'
        urls = ext._extract_urls_from_js(js)
        assert "https://api.example.com/v2/endpoint" in urls

    def test_get_summary(self):
        ext = JsExtractor()
        s = ext.get_summary()
        assert "secrets_found" in s
        assert "urls_found" in s

    def test_allow_insecure_flag(self):
        ext = JsExtractor(allow_insecure=True)
        assert ext.allow_insecure is True

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "extract_js", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
