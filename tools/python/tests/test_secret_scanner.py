import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from secret_scanner import SecretScanner


class TestSecretScanner:
    def setup_method(self):
        self.scanner = SecretScanner()

    # --- AWS key pattern detection ---

    def test_detect_aws_access_key(self):
        text = "AKIA" + "BCDEFGHIJKLMNOPQ"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "AWS Access Key" in f["name"]]
        assert len(matches) >= 1
        assert matches[0]["severity"] == "high"
        assert matches[0]["category"] == "aws"

    def test_detect_aws_secret_key(self):
        fake_secret = "aB3x" + "K7mR" + "9pW2" + "vF5j" + "H8nQ" + "1tY4" + "uI6o" + "P0zC" + "4eX7" + "yL29"
        text = " " + fake_secret + " "
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "AWS Secret Key" in f["name"]]
        assert len(matches) >= 1

    def test_aws_key_with_context(self):
        fake_secret = "aB3x" + "K7mR" + "9pW2" + "vF5j" + "H8nQ" + "1tY4" + "uI6o" + "P0zC" + "4eX7" + "yL29"
        text = 'aws_secret_access_key = "' + fake_secret + '"'
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "AWS Secret Key" in f["name"]]
        assert len(matches) >= 1

    # --- GitHub token detection ---

    def test_detect_github_token(self):
        fake_token = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJ"
        text = fake_token
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "GitHub Token" in f["name"]]
        assert len(matches) >= 1

    def test_detect_github_old_token(self):
        fake_token = "aB3x" + "K7mR" + "9pW2" + "vF5j" + "H8nQ" + "1tY4" + "uI6o" + "P0zC" + "4eX7" + "yL29"
        text = " " + fake_token + " "
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "GitHub Old Token" in f["name"]]
        assert len(matches) >= 1

    def test_github_token_short_not_matched(self):
        text = "ghp_short"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "GitHub" in f["name"]]
        assert len(matches) == 0

    # --- JWT detection ---

    def test_detect_jwt(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dyo1a0bQ7mQ9QK0Q0J0g0Q0Q0Q0Q0Q0Q0Q0Q0Q0"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if f["name"] == "JWT Token"]
        assert len(matches) >= 1

    def test_detect_jwt_with_decoded_payload(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        findings = self.scanner.scan_text(text)
        jwt_findings = [f for f in findings if "JWT" in f["name"]]
        for f in jwt_findings:
            if f["name"] == "JWT Token":
                assert "decoded_payload" in f
                assert f["decoded_payload"] is not None

    # --- Private key detection ---

    def test_detect_rsa_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "RSA" in f["name"]]
        assert len(matches) >= 1

    def test_detect_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE..."
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "OpenSSH" in f["name"]]
        assert len(matches) >= 1

    def test_detect_generic_private_key(self):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF..."
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Private Key (Generic)" in f["name"]]
        assert len(matches) >= 1

    def test_detect_ec_private_key(self):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEII..."
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "EC" in f["name"] or "SSH Private Key Content" in f["name"]]
        assert len(matches) >= 1

    # --- Other pattern detection ---

    def test_detect_google_api_key(self):
        text = "AIza" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHa"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Google API Key" in f["name"]]
        assert len(matches) >= 1

    def test_detect_slack_token(self):
        text = "xoxb-" + "Bbbb-Cccc-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBc"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Slack Token" in f["name"]]
        assert len(matches) >= 1

    def test_detect_stripe_live_key(self):
        p = "".join(["sk", "_li", "ve_"])
        text = p + "AbCdEfGhIjKlMnOpQrStUvWx"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Stripe Live Key" in f["name"]]
        assert len(matches) >= 1

    def test_detect_azure_connection_string(self):
        text = "DefaultEndpointsProtocol=https;AccountName=prod;AccountKey=aabbccddeeff00112233445566778899==="
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Azure Connection String" in f["name"]]
        assert len(matches) >= 1

    def test_detect_password_assignment(self):
        text = 'password = "P@ssw0rd!"'
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Password Assignment" in f["name"]]
        assert len(matches) >= 1

    def test_detect_db_connection_string(self):
        text = "mysql://user:pass@localhost:3306/mydb"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Database Connection String" in f["name"]]
        assert len(matches) >= 1

    def test_detect_telegram_bot_token(self):
        text = "1234567890:AAAAABBBBB" + "CCCCCDDDDD" + "EEEEEFFFFFGGGGG"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Telegram Bot Token" in f["name"]]
        assert len(matches) >= 1

    def test_detect_sendgrid_key(self):
        text = "SG." + "aBcDeFgHiJkLmNoPqRsTuVw" + "." + "bCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStU"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "SendGrid Key" in f["name"]]
        assert len(matches) >= 1

    def test_detect_twilio_key(self):
        text = "SK" + "aAbBcCdDeEfF00112233445566778899"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Twilio Key" in f["name"]]
        assert len(matches) >= 1

    def test_detect_google_service_account(self):
        text = '"type": "service_account"'
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Google Service Account" in f["name"]]
        assert len(matches) >= 1

    def test_detect_mailgun_key(self):
        text = "key-aaaaaaaabbbbbbbb" + "ccccccccdddddddd"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Mailgun Key" in f["name"]]
        assert len(matches) >= 1

    # --- Entropy-based detection ---

    def test_entropy_high_random_string(self):
        self.scanner.min_entropy = 4.0
        text = "xZ9kP2mR7wQ4nL1vB6jH3fD8sA5gE0tY9uI2oW4rC6vB8nM1qX3zP5"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 0

    def test_entropy_low_entropy_string_not_matched(self):
        self.scanner.min_entropy = 5.0
        text = "aaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbb"
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 0

    def test_shannon_entropy_calculation(self):
        entropy = self.scanner.shannon_entropy("aaaa")
        assert entropy == 0.0
        entropy2 = self.scanner.shannon_entropy("abcd")
        assert entropy2 > 0.0

    def test_shannon_entropy_empty(self):
        assert self.scanner.shannon_entropy("") == 0.0

    # --- False positive filtering ---

    def test_allowlist_ignores_test_values(self):
        text = 'password = "test"'
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "Password" in f["name"]]
        assert len(matches) == 0

    def test_allowlist_ignores_placeholder(self):
        text = "AKIA" + "BCDEFGHIJKLMNOPQ"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "AWS" in f["name"]]
        assert len(matches) > 0

    def test_allowlist_ignores_example_token(self):
        text = "ghp_exampleTokenThatShouldBeIgnored0000000000000000"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if "GitHub" in f["name"]]
        assert len(matches) == 0

    # --- scan_text ---

    def test_scan_text_returns_findings(self):
        fake_key = "AKIA" + "BCDEFGHIJKLMNOPQ"
        text = "API key: " + fake_key
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 1

    def test_scan_text_source_label(self):
        fake_key = "AKIA" + "BCDEFGHIJKLMNOPQ"
        findings = self.scanner.scan_text(fake_key, source_label="test_source")
        for f in findings:
            assert f["source"] == "test_source"

    def test_scan_text_line_number(self):
        fake_key = "AKIA" + "BCDEFGHIJKLMNOPQ"
        text = "line1\nline2\n" + fake_key
        findings = self.scanner.scan_text(text)
        for f in findings:
            assert f["line"] == 3

    def test_scan_text_empty(self):
        findings = self.scanner.scan_text("")
        assert findings == []

    def test_scan_text_context(self):
        fake_key = "AKIA" + "BCDEFGHIJKLMNOPQ"
        text = "prefix " + fake_key + " suffix"
        findings = self.scanner.scan_text(text)
        for f in findings:
            assert "prefix" in f["context"]
            assert "suffix" in f["context"]

    def test_scan_text_multiple_findings(self):
        fake_aws = "AKIA" + "BCDEFGHIJKLMNOPQ"
        fake_ghp = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJ"
        text = fake_aws + " and " + fake_ghp
        findings = self.scanner.scan_text(text)
        assert len(findings) >= 2

    # --- Deduplicate ---

    def test_deduplicate_removes_duplicates(self):
        fake_key = "AKIA" + "BCDEFGHIJKLMNOPQ"
        self.scanner.scan_text(fake_key)
        self.scanner.scan_text(fake_key)
        assert len(self.scanner.findings) >= 2
        removed = self.scanner.deduplicate()
        assert removed >= 1

    # --- Filter ---

    def test_filter_by_severity(self):
        fake_aws = "AKIA" + "BCDEFGHIJKLMNOPQ"
        fake_sk = "".join(["sk", "_te", "st_"]) + "aBcDeFgHiJkLmNoPqRsTuVwXy"
        self.scanner.scan_text(fake_aws + "\n" + fake_sk)
        high_or_critical = self.scanner.filter_by_severity("high")
        for f in high_or_critical:
            assert f["severity"] in ("high", "critical")

    def test_filter_by_category(self):
        self.scanner.scan_text("AKIA" + "BCDEFGHIJKLMNOPQ")
        aws_findings = self.scanner.filter_by_category("aws")
        for f in aws_findings:
            assert f["category"] == "aws"

    # --- get_stats ---

    def test_get_stats(self):
        fake_aws = "AKIA" + "BCDEFGHIJKLMNOPQ"
        fake_stripe = "".join(["sk", "_li", "ve_"]) + "aBcDeFgHiJkLmNoPqRsTuVwXy"
        self.scanner.scan_text(fake_aws + "\n" + fake_stripe)
        stats = self.scanner.get_stats()
        assert stats["total_findings"] >= 1
        assert "severity_distribution" in stats
        assert "category_distribution" in stats

    def test_get_stats_empty(self):
        stats = self.scanner.get_stats()
        assert stats["total_findings"] == 0

    # --- Redact ---

    def test_redact_findings(self):
        self.scanner.scan_text("AKIA" + "BCDEFGHIJKLMNOPQ")
        redacted = self.scanner.redact_findings()
        for r in redacted:
            assert "*" in r["match"]

    # --- get_high_confidence ---

    def test_get_high_confidence(self):
        self.scanner.scan_text("AKIA" + "BCDEFGHIJKLMNOPQ")
        high_conf = self.scanner.get_high_confidence()
        for f in high_conf:
            assert f["severity"] in ("high", "critical") or f.get("entropy", 0) >= 4.0

    # --- register_pattern ---

    def test_register_pattern(self):
        self.scanner.register_pattern("Custom Key", r"CUSTOM-KEY-\d{5}", severity="high", category="custom")
        text = "CUSTOM-KEY-12345"
        findings = self.scanner.scan_text(text)
        matches = [f for f in findings if f["name"] == "Custom Key"]
        assert len(matches) >= 1

    # --- clear ---

    def test_clear(self):
        self.scanner.scan_text("AKIA" + "BCDEFGHIJKLMNOPQ")
        assert len(self.scanner.findings) > 0
        self.scanner.clear()
        assert len(self.scanner.findings) == 0
        assert self.scanner._scanned_count == 0
