import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from auth_tester import AuthTester, JwtAnalyzer, SessionAnalyzer, LoginDetector, BypassTester, RateLimitDetector

class TestJwtAnalyzer:
    def test_decode_valid_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.xYz"
        analyzer = JwtAnalyzer(token)
        info = analyzer.get_summary()
        assert info["algorithm"] == "HS256" or info.get("valid") is not None
        assert info["payload"] is not None

    def test_invalid_jwt(self):
        analyzer = JwtAnalyzer("not-a-jwt-token")
        info = analyzer.get_summary()
        assert info.get("valid") is False or "error" in info

    def test_empty_jwt(self):
        analyzer = JwtAnalyzer("")
        info = analyzer.get_summary()
        assert info.get("valid") is False or "error" in info

class TestLoginDetector:
    def test_detect_login_form(self):
        detector = LoginDetector()
        html = '<form action="/login"><input name="user"><input name="pass" type="password"></form>'
        result = detector.detect(html)
        assert result.get("has_login_form") is True

    def test_no_login_form(self):
        detector = LoginDetector()
        result = detector.detect("<html><body>Hello</body></html>")
        assert result.get("has_login_form") is False

    def test_detect_password_field(self):
        detector = LoginDetector()
        html = '<input name="password" type="password">'
        result = detector.detect(html)
        assert result.get("has_password") is True

    def test_get_summary(self):
        detector = LoginDetector()
        s = detector.get_summary()
        assert "forms_analyzed" in s

class TestSessionAnalyzer:
    def test_init(self):
        sa = SessionAnalyzer()
        assert sa is not None

    def test_get_summary(self):
        sa = SessionAnalyzer()
        s = sa.get_summary()
        assert isinstance(s, dict)

class TestBypassTester:
    def test_init(self):
        bt = BypassTester()
        assert bt is not None

    def test_bypass_headers(self):
        bt = BypassTester()
        headers = bt.get_bypass_headers()
        assert len(headers) >= 5
        assert "X-Forwarded-For" in headers
        assert "X-Real-IP" in headers

    def test_get_summary(self):
        bt = BypassTester()
        s = bt.get_summary()
        assert "bypasses_tested" in s

    def test_allow_insecure(self):
        bt = BypassTester(allow_insecure=True)
        assert bt.allow_insecure is True

class TestRateLimitDetector:
    def test_init(self):
        rl = RateLimitDetector()
        assert rl is not None

    def test_get_summary(self):
        rl = RateLimitDetector()
        s = rl.get_summary()
        assert "rate_limits_detected" in s

class TestAuthTester:
    def test_init_defaults(self):
        tester = AuthTester()
        assert tester.bypass_tester is not None

    def test_get_summary_empty(self):
        tester = AuthTester()
        s = tester.get_summary()
        assert isinstance(s, dict)
        assert s.get("bypasses_tested", 0) == 0

    def test_allow_insecure(self):
        tester = AuthTester(allow_insecure=True)
        assert tester.allow_insecure is True

    def test_url_length_limit(self):
        tester = AuthTester()
        with pytest.raises(ValueError):
            tester._validate_url("http://x.com/" + "a" * 9000)

    def test_output_path_validation(self):
        tester = AuthTester()
        with pytest.raises((ValueError, OSError)):
            tester._validate_output_path("../../../etc/hosts")

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "auth_tester", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
