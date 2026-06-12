import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from deep_hunt import DeepHunter, Finding, ResponseAnalyzer

class TestFinding:
    def test_finding_create(self):
        f = Finding(vuln_type="IDOR", endpoint="/api/users/123", severity="High", description="Test")
        assert f.vuln_type == "IDOR"
        assert f.severity == "High"

    def test_finding_to_dict(self):
        f = Finding(vuln_type="XSS", endpoint="/search", severity="Medium", description="Reflected XSS")
        d = f.to_dict()
        assert d["vuln_type"] == "XSS"
        assert d["severity"] == "Medium"

class TestDeepHunter:
    def test_init_defaults(self):
        hunter = DeepHunter()
        assert hunter.findings == []
        assert hunter.timeout == 30

    def test_init_custom(self):
        hunter = DeepHunter(threads=5, timeout=10)
        assert hunter.threads == 5
        assert hunter.timeout == 10

    def test_get_summary_empty(self):
        hunter = DeepHunter()
        s = hunter.get_summary()
        assert s["total_findings"] == 0

    def test_get_summary_with_findings(self):
        hunter = DeepHunter()
        hunter.add_finding(Finding("IDOR", "/test", "High", "desc"))
        hunter.add_finding(Finding("XSS", "/test2", "Medium", "desc"))
        s = hunter.get_summary()
        assert s["total_findings"] == 2
        assert s["by_severity"]["High"] == 1

    def test_allow_insecure(self):
        hunter = DeepHunter(allow_insecure=True)
        assert hunter.allow_insecure is True

    def test_url_length_limit(self):
        long_url = "http://test.com/" + "a" * 9000
        with pytest.raises(ValueError):
            hunter = DeepHunter()
            hunter._validate_url(long_url)

    def test_url_valid(self):
        hunter = DeepHunter()
        result = hunter._validate_url("http://test.com/api")
        assert result is None or result is True

    def test_generate_idor_probes(self):
        hunter = DeepHunter()
        probes = hunter._generate_idor_probes("/api/users/123")
        assert len(probes) >= 1
        assert any("456" in p for p in probes) or any("999" in p for p in probes)

    def test_generate_ssrf_probes(self):
        hunter = DeepHunter()
        probes = hunter._generate_ssrf_probes()
        assert len(probes) >= 1
        assert any("169.254.169.254" in p for p in probes) or any("127.0.0.1" in p for p in probes)

    def test_generate_xss_probes(self):
        hunter = DeepHunter()
        probes = hunter._generate_xss_probes()
        assert len(probes) >= 1
        assert any("<script>" in p for p in probes) or any("alert(" in p for p in probes)

    def test_generate_auth_probes(self):
        hunter = DeepHunter()
        probes = hunter._generate_auth_probes()
        assert len(probes) >= 1

    def test_analyze_response_size_delta(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze(original_size=100, new_size=200)
        assert result.get("size_delta_pct", 0) >= 5

    def test_analyze_no_delta(self):
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze(original_size=100, new_size=100)
        assert result.get("size_delta_pct", 100) == 0

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "deep_hunt", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
