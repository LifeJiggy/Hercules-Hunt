import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from base64_utils import Base64Toolkit, DecodeResult


class TestBase64Toolkit:
    def setup_method(self):
        self.tk = Base64Toolkit()

    # --- is_base64 ---

    def test_is_base64_valid_standard(self):
        assert self.tk.is_base64("SGVsbG8gV29ybGQ=") is True

    def test_is_base64_valid_urlsafe(self):
        assert self.tk.is_base64("SGVsbG8tV29ybGQ_") is True

    def test_is_base64_too_short(self):
        assert self.tk.is_base64("abc") is False

    def test_is_base64_empty_string(self):
        assert self.tk.is_base64("") is False

    def test_is_base64_invalid_chars(self):
        assert self.tk.is_base64("!!!!invalid!!!!!!!") is False

    def test_is_base64_plain_text(self):
        assert self.tk.is_base64("Hello World this is not base64 at all") is False

    def test_is_base64_custom_threshold(self):
        assert self.tk.is_base64("SGVsbG8=", threshold=0.5) is True

    def test_is_base64url_valid(self):
        assert self.tk.is_base64url("SGVsbG8tV29ybGQ_") is True

    def test_is_base64url_standard_chars(self):
        assert self.tk.is_base64url("SGVsbG8gV29ybGQ=") is True

    def test_is_base64url_invalid(self):
        assert self.tk.is_base64url("!!!") is False

    # --- encode ---

    def test_encode_standard_string(self):
        result = self.tk.encode("Hello World")
        assert result == "SGVsbG8gV29ybGQ="

    def test_encode_standard_bytes(self):
        result = self.tk.encode(b"Hello World")
        assert result == "SGVsbG8gV29ybGQ="

    def test_encode_urlsafe(self):
        result = self.tk.encode("Hello+World/1", variant="urlsafe")
        assert "/" not in result
        assert "+" not in result

    def test_encode_empty_string(self):
        result = self.tk.encode("")
        assert result == ""

    # --- decode_standard ---

    def test_decode_standard_success(self):
        result = self.tk.decode_standard("SGVsbG8gV29ybGQ=")
        assert result.success is True
        assert result.decoded_text == "Hello World"

    def test_decode_standard_invalid(self):
        result = self.tk.decode_standard("not-valid!!!")
        assert result.success is False

    def test_decode_standard_padding_error(self):
        result = self.tk.decode_standard("SGVsbG8")
        assert result.success is False

    # --- decode_urlsafe ---

    def test_decode_urlsafe_success(self):
        encoded = self.tk.encode("Hello World", variant="urlsafe")
        result = self.tk.decode_urlsafe(encoded)
        assert result.success is True
        assert result.decoded_text == "Hello World"

    def test_decode_urlsafe_auto_padding(self):
        result = self.tk.decode_urlsafe("SGVsbG8")
        assert result.success is True

    def test_decode_urlsafe_invalid(self):
        result = self.tk.decode_standard("!!!!")
        assert result.success is False

    # --- decode_all_variants ---

    def test_decode_all_variants_standard_input(self):
        self.tk.set_input("SGVsbG8gV29ybGQ=")
        results = self.tk.decode_all_variants()
        assert "standard" in results
        assert results["standard"].success is True
        assert results["standard"].decoded_text == "Hello World"

    def test_decode_all_variants_with_data_arg(self):
        results = self.tk.decode_all_variants("SGVsbG8gV29ybGQ=")
        assert results["standard"].success is True

    def test_decode_all_variants_no_input(self):
        results = self.tk.decode_all_variants()
        assert results == {}

    def test_decode_all_variants_has_all_keys(self):
        results = self.tk.decode_all_variants("SGVsbG8gV29ybGQ=")
        expected_keys = {"standard", "standard_nopad", "urlsafe", "urlsafe_nopad", "mime"}
        assert set(results.keys()) == expected_keys

    # --- decode_jwt_segments ---

    def test_decode_jwt_segments_valid(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.xX1m0A"
        result = self.tk.decode_jwt_segments(token)
        assert "header" in result
        assert "payload" in result
        assert result["header"].get("alg") == "HS256"
        assert result["payload"].get("sub") == "1234567890"

    def test_decode_jwt_segments_too_few_parts(self):
        result = self.tk.decode_jwt_segments("onlyone")
        assert "error" in result

    def test_decode_jwt_segments_signature_truncated(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_here_12345"
        result = self.tk.decode_jwt_segments(token)
        assert "signature" in result
        assert result["signature"].endswith("...")

    # --- recursive_decode ---

    def test_recursive_decode_single_layer(self):
        encoded = self.tk.encode("Hello World")
        steps = self.tk.recursive_decode(encoded, max_depth=1)
        assert len(steps) >= 1
        assert steps[0]["variant"] == "standard"

    def test_recursive_decode_not_base64(self):
        steps = self.tk.recursive_decode("plain text", max_depth=3)
        assert len(steps) == 0

    def test_recursive_decode_max_depth(self):
        encoded = self.tk.encode("a")
        steps = self.tk.recursive_decode(encoded, max_depth=0)
        assert len(steps) == 0

    # --- find_encoded_strings ---

    def test_find_encoded_strings_finds_b64(self):
        text = "Some text with SGVsbG8gV29ybGQ= embedded"
        findings = self.tk.find_encoded_strings(text, min_length=10)
        assert len(findings) >= 1
        assert any(f["decoded"] == "Hello World" for f in findings)

    def test_find_encoded_strings_no_match(self):
        findings = self.tk.find_encoded_strings("short text", min_length=50)
        assert len(findings) == 0

    def test_find_encoded_strings_min_length_filter(self):
        text = "aGk= is short but SGVsbG8gV29ybGQ= is long"
        findings = self.tk.find_encoded_strings(text, min_length=15)
        assert len(findings) >= 1

    # --- get_best_decoding ---

    def test_get_best_decoding_no_results(self):
        best = self.tk.get_best_decoding()
        assert best is None

    def test_get_best_decoding_after_decode(self):
        self.tk.decode_all_variants("SGVsbG8gV29ybGQ=")
        best = self.tk.get_best_decoding()
        assert best is not None
        assert best.success is True

    def test_get_best_decoding_prioritizes_json(self):
        import base64
        data = '{"key": "value"}'
        encoded = base64.b64encode(data.encode()).decode()
        self.tk.decode_all_variants(encoded)
        best = self.tk.get_best_decoding()
        assert best is not None
        assert best.content_type == "json"

    # --- analyze_padding ---

    def test_analyze_padding_well_padded(self):
        result = self.tk.analyze_padding("SGVsbG8gV29ybGQ=")
        assert result["padding_chars"] == 1
        assert result["well_padded"] is True
        assert result["has_valid_chars"] is True

    def test_analyze_padding_no_padding(self):
        result = self.tk.analyze_padding("SGVsbG8gV29ybGQ")
        assert result["padding_chars"] == 0

    def test_analyze_padding_invalid_chars(self):
        result = self.tk.analyze_padding("!!!")
        assert result["has_valid_chars"] is False

    # --- hex_to_base64 / base64_to_hex ---

    def test_hex_to_base64(self):
        result = self.tk.hex_to_base64("48656c6c6f")
        assert result == "SGVsbG8="

    def test_hex_to_base64_empty(self):
        result = self.tk.hex_to_base64("")
        assert result == ""

    def test_base64_to_hex(self):
        result = self.tk.base64_to_hex("SGVsbG8=")
        assert result == "48656c6c6f"

    def test_base64_to_hex_roundtrip(self):
        hex_str = "48656c6c6f20576f726c64"
        b64 = self.tk.hex_to_base64(hex_str)
        back = self.tk.base64_to_hex(b64)
        assert back == hex_str

    # --- set_input ---

    def test_set_input(self):
        self.tk.set_input("dGVzdA==")
        assert self.tk.input_string == "dGVzdA=="

    # --- get_statistics ---

    def test_get_statistics_no_results(self):
        stats = self.tk.get_statistics()
        assert stats["variants_tested"] == 0
        assert stats["successful"] == 0
        assert stats["best_variant"] is None

    def test_get_statistics_after_decode(self):
        self.tk.decode_all_variants("SGVsbG8gV29ybGQ=")
        stats = self.tk.get_statistics()
        assert stats["variants_tested"] == 5
        assert stats["successful"] >= 1
        assert stats["best_variant"] is not None

    # --- DecodeResult ---

    def test_decode_result_defaults(self):
        r = DecodeResult(variant="test", success=True)
        assert r.decoded_text == ""
        assert r.decoded_bytes == b""
        assert r.error == ""

    def test_decode_result_failure(self):
        r = DecodeResult(variant="test", success=False, error="something broke")
        assert r.success is False
        assert r.error == "something broke"
