import unittest
import importlib.util
from pathlib import Path
import sys

_PROJECT_SRC = Path(__file__).resolve().parents[1] / "src"
if _PROJECT_SRC.is_dir():
    sys.path.insert(0, str(_PROJECT_SRC))
try:
    from email_detection import header_forensics
except ImportError:
    _MODULE_PATH = Path(__file__).with_name("header_forensics.py")
    _SPEC = importlib.util.spec_from_file_location("header_forensics", _MODULE_PATH)
    header_forensics = importlib.util.module_from_spec(_SPEC)
    sys.modules[_SPEC.name] = header_forensics
    _SPEC.loader.exec_module(header_forensics)
analyze_email_header = header_forensics.analyze_email_header


def rules(report):
    return {finding["rule_id"] for finding in report["findings"]}


class TestHeaderForensics(unittest.TestCase):
    def test_all_authentication_passes(self):
        result = analyze_email_header(
            "From: Example <alice@example.com>\r\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\r\n"
        )
        assert result["from_address"] == "alice@example.com"
        assert result["from_domain"] == "example.com"
        assert result["authentication"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        assert result["threat_score"] == 0

    def test_all_documented_authentication_statuses_parse(self):
        for status in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"):
            with self.subTest(status=status):
                result = analyze_email_header(
                    f"From: a@example.com\nAuthentication-Results: mx; spf={status}\n"
                )
                self.assertEqual(result["authentication"]["spf"], status)

    def test_duplicate_agreeing_authentication_results_are_not_a_conflict(self):
        result = analyze_email_header(
            "From: a@example.com\n"
            "Authentication-Results: mx1; spf=pass\n"
            "Authentication-Results: mx2; spf=pass\n"
        )
        self.assertEqual(result["authentication"]["spf"], "pass")
        self.assertNotIn("CONFLICTING_SPF_RESULTS", rules(result))
    
    
    def test_explicit_spf_failure_is_scored(self):
        result = analyze_email_header("From: a@example.com\nReceived-SPF: fail\n")
        assert result["authentication"]["spf"] == "fail"
        assert "SPF_FAIL" in rules(result)
        assert result["threat_score"] == 20
    
    
    def test_explicit_dkim_failure_is_scored(self):
        result = analyze_email_header("From: a@example.com\nAuthentication-Results: mx; dkim=fail\n")
        assert result["authentication"]["dkim"] == "fail"
        assert "DKIM_FAIL" in rules(result)
    
    
    def test_explicit_dmarc_failure_is_scored(self):
        result = analyze_email_header("From: a@example.com\nAuthentication-Results: mx; dmarc=fail\n")
        assert result["authentication"]["dmarc"] == "fail"
        assert "DMARC_FAIL" in rules(result)
        assert result["threat_score"] == 25
    
    
    def test_reply_to_mismatch_is_explained_but_not_malware_verdict(self):
        result = analyze_email_header("From: support@example.com\nReply-To: reply@untrusted.example\n")
        assert result["reply_to_domain"] == "untrusted.example"
        assert "REPLY_TO_DOMAIN_MISMATCH" in rules(result)
        assert result["threat_score"] == 15
    
    
    def test_sender_from_mismatch(self):
        result = analyze_email_header("From: support@example.com\nSender: relay@untrusted.example\n")
        assert "SENDER_FROM_DOMAIN_MISMATCH" in rules(result)
        assert result["threat_score"] == 10
    
    
    def test_missing_authentication_is_unknown_not_failure(self):
        result = analyze_email_header("From: a@example.com\n")
        assert set(result["authentication"].values()) == {"unknown"}
        assert "AUTHENTICATION_RESULTS_MISSING" in rules(result)
        assert not ({"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} & rules(result))
        assert result["threat_score"] == 0
    
    
    def test_malformed_and_incomplete_headers_do_not_crash(self):
        result = analyze_email_header("From: not-an-address\nReply-To: <bad@>\nThis is not a header\n")
        assert result["from_address"] is None
        assert "FROM_UNPARSEABLE" in rules(result)
        assert "MALFORMED_HEADER_BLOCK" in rules(result)
        assert isinstance(result["threat_score"], int)
    
    
    def test_conflicting_authentication_results_become_unknown(self):
        result = analyze_email_header(
            "From: a@example.com\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            "Authentication-Results: other; spf=fail; dkim=pass; dmarc=pass\n"
        )
        assert result["authentication"]["spf"] == "unknown"
        assert "CONFLICTING_SPF_RESULTS" in rules(result)
        assert "SPF_FAIL" not in rules(result)
    
    
    def test_legitimate_third_party_sender_configuration_is_not_auto_malicious(self):
        result = analyze_email_header(
            "From: newsletter@example.com\nSender: bounce@mailer.example\n"
            "Return-Path: <bounce@mailer.example>\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        )
        assert result["risk_level"] == "Low"
        assert result["threat_score"] == 10
        assert "SENDER_FROM_DOMAIN_MISMATCH" in rules(result)
    
    
    def test_score_bounds_and_authentication_group_cap(self):
        result = analyze_email_header(
            "From: a@example.com\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n"
        )
        assert 0 <= result["threat_score"] <= 100
        assert result["threat_score"] == 45
        assert sum(f["score_contribution"] for f in result["findings"]) == result["threat_score"]
        auth_failures = [f for f in result["findings"] if f["rule_id"] in {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}]
        self.assertEqual(len(auth_failures), 3)
        self.assertTrue(all(f["score_contribution"] > 0 for f in auth_failures))
    
    
    def test_identical_input_has_stable_output(self):
        raw = "From: a@example.com\nAuthentication-Results: mx; spf=softfail\n"
        assert analyze_email_header(raw) == analyze_email_header(raw)
    
    
    def test_idn_and_trailing_dot_are_normalized(self):
        result = analyze_email_header("From: user@EXÄMPLE.com.\n")
        assert result["from_domain"] == "xn--exmple-cua.com"
    
    
    def test_dkim_signature_is_not_mistaken_for_validation(self):
        result = analyze_email_header("From: a@example.com\nDKIM-Signature: v=1; d=example.com; s=x\n")
        assert result["authentication"]["dkim"] == "unknown"
        assert "DKIM_SIGNATURE_UNVERIFIED" in rules(result)
    
    
    def test_configurable_weights_and_bands(self):
        config = header_forensics.ScoreConfig(
            weights={**header_forensics.DEFAULT_RULE_WEIGHTS, "spf_fail": 7},
            risk_bands={"Low": (0, 10), "Medium": (11, 30), "High": (31, 100)},
        )
        result = analyze_email_header("From: a@example.com\nReceived-SPF: fail\n", config=config)
        assert result["threat_score"] == 7
        assert result["risk_level"] == "Low"
    


