import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from endpoint_fuzzer import EndpointFuzzer, FuzzResult, ResponseAnalyzer, WordlistManager

class TestWordlistManager:
    def test_init(self):
        wm = WordlistManager()
        assert wm is not None

    def test_common_paths(self):
        wm = WordlistManager()
        paths = wm.get_common_paths()
        assert len(paths) >= 10
        assert "/admin" in paths
        assert "/api" in paths

    def test_common_extensions(self):
        wm = WordlistManager()
        exts = wm.get_common_extensions()
        assert ".php" in exts
        assert ".json" in exts
        assert ".bak" in exts

    def test_common_parameters(self):
        wm = WordlistManager()
        params = wm.get_common_parameters()
        assert len(params) >= 5
        assert "id" in params or "page" in params

class TestFuzzResult:
    def test_create(self):
        r = FuzzResult(path="/admin", method="GET", status=200, size=500)
        assert r.status == 200
        assert r.size == 500

    def test_to_dict(self):
        r = FuzzResult(path="/.env", method="GET", status=200, size=100)
        d = r.to_dict()
        assert d["path"] == "/.env"
        assert d["status"] == 200

class TestResponseAnalyzer:
    def test_analyze_diff(self):
        ra = ResponseAnalyzer()
        baseline = FuzzResult(path="/", method="GET", status=200, size=100)
        result = FuzzResult(path="/admin", method="GET", status=200, size=500)
        diff = ra.analyze(baseline, result)
        assert diff["size_diff"] == 400
        assert diff["interesting"] is True

    def test_no_diff(self):
        ra = ResponseAnalyzer()
        baseline = FuzzResult(path="/", method="GET", status=200, size=100)
        result = FuzzResult(path="/test", method="GET", status=200, size=100)
        diff = ra.analyze(baseline, result)
        assert diff["size_diff"] == 0

class TestEndpointFuzzer:
    def test_init_defaults(self):
        fuzzer = EndpointFuzzer()
        assert fuzzer.threads == 5

    def test_init_custom(self):
        fuzzer = EndpointFuzzer(threads=10, delay=1.0)
        assert fuzzer.threads == 10
        assert fuzzer.delay == 1.0

    def test_get_summary_empty(self):
        fuzzer = EndpointFuzzer()
        s = fuzzer.get_summary()
        assert s["total_requests"] == 0

    def test_get_summary_with_results(self):
        fuzzer = EndpointFuzzer()
        fuzzer.results.append(FuzzResult("/admin", "GET", 200, 500))
        fuzzer.results.append(FuzzResult("/backup", "GET", 403, 100))
        s = fuzzer.get_summary()
        assert s["total_requests"] == 2
        assert "200" in s["by_status"]

    def test_allow_insecure(self):
        fuzzer = EndpointFuzzer(allow_insecure=True)
        assert fuzzer.allow_insecure is True

    def test_url_length_limit(self):
        fuzzer = EndpointFuzzer()
        with pytest.raises(ValueError):
            fuzzer._validate_url("http://x.com/" + "a" * 9000)

    def test_output_path_validation(self):
        fuzzer = EndpointFuzzer()
        with pytest.raises((ValueError, OSError)):
            fuzzer._validate_output_path("../../../etc/hosts")

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "endpoint_fuzzer", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
