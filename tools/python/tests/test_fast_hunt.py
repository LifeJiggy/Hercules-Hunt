import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from fast_hunt import FastHunter, Probe, ResultCollector

class TestProbe:
    def test_probe_create(self):
        p = Probe(path="/admin", method="GET", description="Admin panel check")
        assert p.path == "/admin"
        assert p.method == "GET"

    def test_probe_to_dict(self):
        p = Probe(path="/.env", method="GET", description="Env file")
        d = p.to_dict()
        assert d["path"] == "/.env"

class TestResultCollector:
    def test_collector_init(self):
        c = ResultCollector()
        assert c.results == []

    def test_add_result(self):
        c = ResultCollector()
        c.add(path="/admin", status=200, size=500)
        assert len(c.results) == 1
        assert c.results[0]["status"] == 200

    def test_get_summary_empty(self):
        c = ResultCollector()
        s = c.get_summary()
        assert s["total"] == 0

    def test_get_summary_with_data(self):
        c = ResultCollector()
        c.add(path="/admin", status=200, size=500)
        c.add(path="/backup", status=403, size=100)
        s = c.get_summary()
        assert s["total"] == 2
        assert s["by_status"]["200"] == 1

class TestFastHunter:
    def test_init_defaults(self):
        hunter = FastHunter()
        assert hunter.results is not None
        assert hunter.timeout == 15

    def test_init_custom(self):
        hunter = FastHunter(aggressive=True, timeout=30)
        assert hunter.aggressive is True
        assert hunter.timeout == 30

    def test_common_paths(self):
        hunter = FastHunter()
        paths = hunter._get_common_paths()
        assert "/admin" in paths
        assert "/.git" in paths
        assert "/.env" in paths
        assert "/backup" in paths
        assert "/api" in paths

    def test_aggressive_paths(self):
        hunter = FastHunter(aggressive=True)
        paths = hunter._get_common_paths()
        assert len(paths) > 5

    def test_default_headers_check(self):
        hunter = FastHunter()
        headers = hunter._get_security_headers()
        assert "Strict-Transport-Security" in headers
        assert "Content-Security-Policy" in headers
        assert "X-Frame-Options" in headers

    def test_get_summary_empty(self):
        hunter = FastHunter()
        s = hunter.get_summary()
        assert s["total_probes"] == 0

    def test_get_summary_with_results(self):
        hunter = FastHunter()
        hunter.results.add(path="/admin", status=200, size=500)
        s = hunter.get_summary()
        assert s["total_probes"] == 1

    def test_allow_insecure(self):
        hunter = FastHunter(allow_insecure=True)
        assert hunter.allow_insecure is True

    def test_output_path_validation(self):
        hunter = FastHunter()
        with pytest.raises((ValueError, OSError)):
            hunter._validate_output_path("../../../etc/passwd")

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "fast_hunt", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
