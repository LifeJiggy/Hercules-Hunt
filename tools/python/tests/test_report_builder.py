import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from report_builder import ReportBuilder, Cvss31Calculator, Finding, TemplateEngine

class TestFinding:
    def test_finding_create(self):
        f = Finding(title="Test", description="desc", severity="High")
        assert f.title == "Test"
        assert f.severity == "High"

    def test_finding_to_dict(self):
        f = Finding(title="XSS", description="Reflected XSS", severity="Medium", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
        d = f.to_dict()
        assert d["title"] == "XSS"
        assert d["cvss_vector"] is not None

    def test_finding_defaults(self):
        f = Finding(title="Test", description="desc", severity="Low")
        assert f.cvss_vector is None
        assert f.remediation is None

class TestCvss31Calculator:
    def test_calculate_critical(self):
        calc = Cvss31Calculator()
        score = calc.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score["base_score"] >= 9.0
        assert score["severity"] == "Critical"

    def test_calculate_medium(self):
        calc = Cvss31Calculator()
        score = calc.calculate("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N")
        assert score["severity"] in ("Medium", "Low")

    def test_calculate_low(self):
        calc = Cvss31Calculator()
        score = calc.calculate("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
        assert score["severity"] == "None" or score["base_score"] <= 1.0

    def test_calculate_invalid_vector(self):
        calc = Cvss31Calculator()
        score = calc.calculate("invalid")
        assert score.get("error") is not None

    def test_calculate_empty(self):
        calc = Cvss31Calculator()
        score = calc.calculate("")
        assert score.get("error") is not None or score.get("base_score") == 0

    def test_get_summary(self):
        calc = Cvss31Calculator()
        s = calc.get_summary()
        assert "scores_calculated" in s

class TestReportBuilder:
    def test_init_defaults(self):
        builder = ReportBuilder()
        assert builder.platform == "generic"

    def test_init_custom(self):
        builder = ReportBuilder(platform="hackerone")
        assert builder.platform == "hackerone"

    def test_init_invalid_platform(self):
        builder = ReportBuilder(platform="unknown")
        assert builder.platform == "unknown"

    def test_generate_report_empty(self):
        builder = ReportBuilder()
        report = builder.generate([])
        assert report is not None
        assert "No findings" in report or "0" in report

    def test_generate_report_with_finding(self):
        builder = ReportBuilder(platform="generic")
        f = Finding(title="IDOR", description="IDOR on /api/users/123", severity="High")
        report = builder.generate([f])
        assert "IDOR" in report

    def test_add_template(self):
        builder = ReportBuilder()
        builder.add_template("custom", "{{title}}\n{{findings|length}} findings")
        assert "custom" in builder.templates

    def test_get_summary(self):
        builder = ReportBuilder()
        s = builder.get_summary()
        assert s["platform"] == "generic"

    def test_output_path_validation(self):
        builder = ReportBuilder()
        f = Finding(title="Test", description="desc", severity="Low")
        with pytest.raises((ValueError, OSError)):
            builder.export(f, "../../../etc/passwd")

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "report_builder", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
