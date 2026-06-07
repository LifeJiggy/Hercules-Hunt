import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from payload_generator import PayloadGenerator


class TestPayloadGenerator:
    def setup_method(self):
        self.gen = PayloadGenerator()

    # --- XSS generation ---

    def test_generate_xss_returns_payloads(self):
        payloads = self.gen.generate("xss")
        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_generate_xss_contains_typical_patterns(self):
        payloads = self.gen.generate("xss")
        assert any("<script>" in p for p in payloads)
        assert any("alert(1)" in p for p in payloads)

    def test_generate_xss_count_limit(self):
        payloads = self.gen.generate("xss", count=5)
        assert len(payloads) == 5

    # --- SQLi generation ---

    def test_generate_sqli_returns_payloads(self):
        payloads = self.gen.generate("sqli")
        assert len(payloads) > 0

    def test_generate_sqli_contains_union(self):
        payloads = self.gen.generate("sqli")
        assert any("UNION" in p for p in payloads)

    def test_generate_sqli_contains_or_pattern(self):
        payloads = self.gen.generate("sqli")
        assert any("OR" in p.upper() for p in payloads)

    # --- SSRF generation ---

    def test_generate_ssrf_returns_payloads(self):
        payloads = self.gen.generate("ssrf")
        assert len(payloads) > 0

    def test_generate_ssrf_contains_metadata(self):
        payloads = self.gen.generate("ssrf")
        assert any("169.254.169.254" in p for p in payloads)

    def test_generate_ssrf_contains_localhost(self):
        payloads = self.gen.generate("ssrf")
        assert any("127.0.0.1" in p or "localhost" in p for p in payloads)

    # --- Other classes ---

    def test_generate_xxe_returns_payloads(self):
        payloads = self.gen.generate("xxe")
        assert len(payloads) > 0
        assert any("DOCTYPE" in p for p in payloads)

    def test_generate_lfi_returns_payloads(self):
        payloads = self.gen.generate("lfi")
        assert len(payloads) > 0
        assert any("passwd" in p for p in payloads)

    def test_generate_cmdi_returns_payloads(self):
        payloads = self.gen.generate("cmdi")
        assert len(payloads) > 0
        assert any("whoami" in p for p in payloads)

    def test_generate_open_redirect_returns_payloads(self):
        payloads = self.gen.generate("open_redirect")
        assert len(payloads) > 0

    def test_generate_ssti_returns_payloads(self):
        payloads = self.gen.generate("ssti")
        assert len(payloads) > 0
        assert any("{{" in p for p in payloads)

    def test_generate_path_traversal_returns_payloads(self):
        payloads = self.gen.generate("path_traversal")
        assert len(payloads) > 0
        assert any("../" in p for p in payloads)

    def test_generate_nosqli_returns_payloads(self):
        payloads = self.gen.generate("nosqli")
        assert len(payloads) > 0

    def test_generate_unknown_class(self):
        payloads = self.gen.generate("nonexistent_class")
        assert payloads == []

    # --- generate_all ---

    def test_generate_all_returns_all_classes(self):
        result = self.gen.generate_all()
        assert isinstance(result, dict)
        assert "xss" in result
        assert "sqli" in result
        assert "ssrf" in result
        assert len(result) >= 10

    # --- Encoding variants ---

    def test_encode_url(self):
        payloads = self.gen.generate("xss", encoding="url")
        assert all("%" in p for p in payloads[:5])

    def test_encode_base64(self):
        payloads = self.gen.generate("xss", encoding="base64")
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for p in payloads for c in p)

    def test_encode_unicode(self):
        payloads = self.gen.generate("xss", encoding="unicode")
        assert all("\\u" in p for p in payloads[:5])

    def test_encode_hex(self):
        payloads = self.gen.generate("xss", encoding="hex")
        assert all("\\x" in p for p in payloads[:5])

    def test_encode_double_url(self):
        payloads = self.gen.generate("sqli", encoding="double_url")
        assert all("%25" in p for p in payloads[:3])

    def test_encode_hex_entity(self):
        payloads = self.gen.generate("xss", encoding="hex_entity")
        assert all("&#x" in p for p in payloads[:3])

    def test_encode_decimal_entity(self):
        payloads = self.gen.generate("xss", encoding="decimal_entity")
        assert all("&#" in p and not p.startswith("&#x") for p in payloads[:3])

    def test_encode_octal(self):
        payloads = self.gen.generate("xss", encoding="octal")
        assert any("\\" in p for p in payloads[:3])

    def test_encode_null_byte(self):
        payloads = self.gen.generate("xss", encoding="null_byte")
        assert any("\x00" in p for p in payloads)

    def test_encode_reverse(self):
        payloads = self.gen.generate("ssrf", encoding="reverse")
        assert len(payloads) > 0
        original = self.gen.generate("ssrf")
        assert payloads != original

    def test_encode_uppercase(self):
        payloads = self.gen.generate("xss", encoding="uppercase")
        assert all(p == p.upper() for p in payloads)

    def test_encode_lowercase(self):
        payloads = self.gen.generate("xss", encoding="lowercase")
        assert all(p == p.lower() for p in payloads)

    def test_encode_case_swap(self):
        payloads = self.gen.generate("xss", encoding="case_swap")
        assert len(payloads) > 0
        original = self.gen.generate("xss")
        assert payloads != original

    def test_encode_unknown_encoding_returns_original(self):
        payloads = self.gen.generate("xss", encoding="unknown_encoding")
        assert len(payloads) > 0

    # --- WAF bypass ---

    def test_generate_waf_bypass_xss_all(self):
        payloads = self.gen.generate_waf_bypass("xss")
        assert len(payloads) > 0

    def test_generate_waf_bypass_sqli_all(self):
        payloads = self.gen.generate_waf_bypass("sqli")
        assert len(payloads) > 0

    def test_generate_waf_bypass_ssrf_all(self):
        payloads = self.gen.generate_waf_bypass("ssrf")
        assert len(payloads) > 0

    def test_generate_waf_bypass_specific_technique(self):
        payloads = self.gen.generate_waf_bypass("xss", technique="url")
        assert len(payloads) > 0
        assert all("%" in p for p in payloads)

    def test_generate_waf_bypass_unknown_class(self):
        payloads = self.gen.generate_waf_bypass("unknown")
        assert payloads == []

    # --- Polyglot ---

    def test_generate_polyglot_xss_sqli(self):
        result = self.gen.generate_polyglot("xss_sqli")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_generate_polyglot_default(self):
        result = self.gen.generate_polyglot()
        assert isinstance(result, str)

    def test_generate_polyglot_unknown_fallback(self):
        result = self.gen.generate_polyglot("unknown_type")
        assert result == self.gen.generate_polyglot("all")

    # --- Mutation ---

    def test_generate_mutation_returns_variants(self):
        results = self.gen.generate_mutation("<script>alert(1)</script>", mutations=5)
        assert len(results) >= 1
        assert results[0] == "<script>alert(1)</script>"

    def test_generate_mutation_zero_mutations(self):
        results = self.gen.generate_mutation("test", mutations=0)
        assert results == ["test"]

    # --- Contextual ---

    def test_generate_contextual_html(self):
        results = self.gen.generate_contextual("xss", context="html")
        assert len(results) > 0
        assert any("<script>" in r for r in results)

    def test_generate_contextual_attribute(self):
        results = self.gen.generate_contextual("xss", context="attribute")
        assert len(results) > 0
        assert any('"' in r for r in results)

    def test_generate_contextual_js(self):
        results = self.gen.generate_contextual("xss", context="js")
        assert len(results) > 0

    def test_generate_contextual_unknown_context(self):
        results = self.gen.generate_contextual("xss", context="unknown")
        assert len(results) > 0

    # --- Fuzzing list ---

    def test_generate_fuzzing_list_xss(self):
        results = self.gen.generate_fuzzing_list("xss")
        assert "<>" in results

    def test_generate_fuzzing_list_sqli(self):
        results = self.gen.generate_fuzzing_list("sqli")
        assert "'" in results

    def test_generate_fuzzing_list_unknown(self):
        results = self.gen.generate_fuzzing_list("unknown")
        assert results == []

    # --- Register custom payload ---

    def test_register_payload(self):
        self.gen.register_payload("custom_xss", ["<custom>test</custom>"], vuln_class="custom")
        payloads = self.gen.generate("custom")
        assert "<custom>test</custom>" in payloads

    # --- get_by_rating ---

    def test_get_by_rating_returns_rated_list(self):
        rated = self.gen.get_by_rating("xss", min_likelihood=1)
        assert len(rated) > 0
        assert "payload" in rated[0]
        assert "likelihood" in rated[0]
        assert "stealth" in rated[0]

    def test_get_by_rating_filters_by_likelihood(self):
        all_rated = self.gen.get_by_rating("xss", min_likelihood=1)
        high_rated = self.gen.get_by_rating("xss", min_likelihood=5)
        assert len(high_rated) <= len(all_rated)

    # --- Output ---

    def test_output_json(self):
        self.gen.generate("xss", count=3)
        output = self.gen.output_json("xss")
        data = __import__("json").loads(output)
        assert data["class"] == "xss"
        assert data["count"] == 3

    def test_output_txt(self):
        self.gen.generate("xss", count=3)
        output = self.gen.output_txt("xss")
        lines = output.split("\n")
        assert len(lines) == 3

    def test_output_http_request_get(self):
        self.gen.generate("xss", count=3)
        output = self.gen.output_http_request("xss", "http://target.com", param="q", method="GET")
        assert "GET http://target.com?q=" in output
        assert "Host: example.com" in output

    def test_output_http_request_post(self):
        self.gen.generate("sqli", count=2)
        output = self.gen.output_http_request("sqli", "http://target.com/login", param="user", method="POST")
        assert "POST http://target.com/login" in output
        assert "Content-Type: application/x-www-form-urlencoded" in output

    # --- get_classes ---

    def test_get_classes(self):
        classes = self.gen.get_classes()
        assert "xss" in classes
        assert "sqli" in classes
        assert "ssrf" in classes
        assert "xxe" in classes
        assert "lfi" in classes
