import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from extract_parameters import ParameterExtractor, UrlParser, BodyParser, ReflectionDetector

class TestUrlParser:
    def test_extract_query_params(self):
        parser = UrlParser()
        params = parser.extract_query_params("http://test.com/api?user=admin&id=123&active=true")
        assert len(params) == 3
        assert params["user"] == "admin"
        assert params["id"] == "123"

    def test_extract_query_params_empty(self):
        parser = UrlParser()
        params = parser.extract_query_params("http://test.com/api")
        assert params == {}

    def test_extract_path_params(self):
        parser = UrlParser()
        params = parser.extract_path_params("/api/users/123/orders/456")
        assert len(params) >= 1

class TestBodyParser:
    def test_parse_json_body(self):
        parser = BodyParser()
        body = '{"user": "admin", "role": "admin", "active": true}'
        params = parser.parse(body, content_type="application/json")
        assert params["user"] == "admin"
        assert params["role"] == "admin"

    def test_parse_form_body(self):
        parser = BodyParser()
        body = "user=admin&pass=secret&remember=1"
        params = parser.parse(body, content_type="application/x-www-form-urlencoded")
        assert params["user"] == "admin"
        assert params["pass"] == "secret"

    def test_parse_invalid_json(self):
        parser = BodyParser()
        params = parser.parse("{bad json", content_type="application/json")
        assert params == {}

    def test_parse_empty(self):
        parser = BodyParser()
        params = parser.parse("", content_type="text/plain")
        assert params == {}

class TestReflectionDetector:
    def test_detect_reflection(self):
        detector = ReflectionDetector()
        result = detector.detect("hello TEST_VALUE world", "TEST_VALUE")
        assert result is True

    def test_detect_no_reflection(self):
        detector = ReflectionDetector()
        result = detector.detect("hello world", "TEST_VALUE")
        assert result is False

class TestParameterExtractor:
    def test_init_defaults(self):
        ext = ParameterExtractor()
        assert ext.depth == 2

    def test_init_custom(self):
        ext = ParameterExtractor(depth=5, fuzz=True)
        assert ext.depth == 5
        assert ext.fuzz is True

    def test_common_get_params(self):
        ext = ParameterExtractor()
        params = ext._get_common_get_params()
        assert len(params) >= 10
        assert "id" in params
        assert "page" in params
        assert "limit" in params

    def test_common_post_params(self):
        ext = ParameterExtractor()
        params = ext._get_common_post_params()
        assert len(params) >= 5
        assert "username" in params or "email" in params

    def test_get_summary_empty(self):
        ext = ParameterExtractor()
        s = ext.get_summary()
        assert s["total_params"] == 0

    def test_get_summary_with_data(self):
        ext = ParameterExtractor()
        ext._found_params = {"id": "123", "user": "admin"}
        s = ext.get_summary()
        assert s["total_params"] == 2

    def test_url_length_limit(self):
        ext = ParameterExtractor()
        with pytest.raises(ValueError):
            ext._validate_url("http://x.com/?" + "a=" + "b" * 9000)

    def test_cli_help(self):
        import subprocess
        r = subprocess.run([sys.executable, "-m", "extract_parameters", "--help"], capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
        assert r.returncode == 0
