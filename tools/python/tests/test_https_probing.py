import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from https_probing import TlsProber, CertificateAnalyzer, CipherScanner, HeaderAnalyzer

class TestCertificateAnalyzer:
    def test_init(self):
        ca = CertificateAnalyzer()
        assert ca is not None

    def test_parse_cert_info_none(self):
        ca = CertificateAnalyzer()
        info = ca.parse_cert_info(None)
        assert info["valid"] is False

class TestCipherScanner:
    def test_init(self):
        cs = CipherScanner()
        assert cs is not None

class TestHeaderAnalyzer:
    def test_init(self):
        ha = HeaderAnalyzer()
        assert ha.required_headers is not None

    def test_analyze_headers_all_present(self):
        ha = HeaderAnalyzer()
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        result = ha.analyze(headers)
        assert result["score"] >= 50

    def test_analyze_headers_missing(self):
        ha = HeaderAnalyzer()
        result = ha.analyze({})
        assert result["score"] == 0
        assert len(result["missing_headers"]) >= 4

    def test_analyze_partial(self):
        ha = HeaderAnalyzer()
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        result = ha.analyze(headers)
        assert result["score"] > 0
        assert result["score"] < 100

    def test_get_summary(self):
        ha = HeaderAnalyzer()
        ha.analyze({})
        s = ha.get_summary()
        assert "total_checks" in s

class TestTlsProber:
    def test_init_defaults(self):
        prober = TlsProber()
        assert prober.timeout == 30
        assert prober.allow_insecure is False

    def test_init_custom(self):
        prober = TlsProber(timeout=15, cipher_scan=True)
        assert prober.timeout == 15
        assert prober.cipher_scan is True

    def test_parse_url_good(self):
        prober = TlsProber()
        host, port, use_tls = prober._parse_url("https://example.com")
        assert host == "example.com"
        assert port == 443
        assert use_tls is True

    def test_parse_url_http(self):
        prober = TlsProber()
        host, port, use_tls = prober._parse_url("http://example.com:8080")
        assert host == "example.com"
        assert port == 8080
        assert use_tls is False

    def test_parse_url_with_path(self):
        prober = TlsProber()
        host, port, use_tls = prober._parse_url("https://example.com/api/v1")
        assert host == "example.com"
        assert port == 443

    def test_get_summary(self):
        prober = TlsProber()
        s = prober.get_summary()
        assert "hosts_scanned" in s

    def test_allow_insecure(self):
        prober = TlsProber(allow_insecure=True)
        assert prober.allow_insecure is True

    def test_url_length_limit(self):
        prober = TlsProber()
        long_url = "https://" + "a" * 9000 + ".com"
        with pytest.raises(ValueError):
            prober._validate_url(long_url)

    def test_output_path_validation(self):
        prober = TlsProber()
        with pytest.raises((ValueError, OSError)):
            prober._validate_output_path("/../../etc/hosts")

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "https_probing", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
