"""Explainable, offline analysis of email header authentication and identities.

This module reads recorded header values; it does not verify cryptographic
signatures, query DNS, or establish that an authentication result is trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from email.utils import getaddresses
from typing import Mapping

try:  # installed as email_detection.header_forensics in the project
    from .domains import best_trusted_match, normalize_domain
except ImportError:  # imported directly for standalone use/tests
    best_trusted_match = None

    def normalize_domain(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("Domain must be text.")
        value = value.strip().rstrip(".").casefold()
        if not value or len(value) > 253:
            raise ValueError("Domain is empty or too long.")
        value = value.encode("idna").decode("ascii")
        labels = value.split(".")
        if len(labels) < 2 or any(
            len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Invalid fully qualified domain.")
        return value


AUTH_METHODS = ("spf", "dkim", "dmarc")
AUTH_STATUSES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"}
DEFAULT_RULE_WEIGHTS = {
    "spf_fail": 20,
    "dkim_fail": 20,
    "dmarc_fail": 25,
    "reply_to_mismatch": 15,
    "sender_from_mismatch": 10,
    "lookalike_candidate": 10,
}
DEFAULT_RISK_BANDS = {"Low": (0, 29), "Medium": (30, 59), "High": (60, 100)}
_AUTH_RE = re.compile(
    r"(?:^|[;\s])(?P<method>spf|dkim|dmarc)\s*=\s*"
    r"(?P<status>pass|fail|softfail|neutral|none|temperror|permerror|unknown)\b",
    re.IGNORECASE,
)
_SPF_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror|unknown)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ScoreConfig:
    """Named heuristic weights and configurable risk band upper bounds."""

    weights: Mapping[str, int] | None = None
    risk_bands: Mapping[str, tuple[int, int]] | None = None
    authentication_cap: int = 45

    def __post_init__(self) -> None:
        weights = dict(DEFAULT_RULE_WEIGHTS if self.weights is None else self.weights)
        bands = dict(DEFAULT_RISK_BANDS if self.risk_bands is None else self.risk_bands)
        if set(bands) != {"Low", "Medium", "High"}:
            raise ValueError("risk_bands must define Low, Medium, and High.")
        if any(not isinstance(v, int) or v < 0 for v in weights.values()):
            raise ValueError("Rule weights must be non-negative integers.")
        if not 0 <= self.authentication_cap <= 100:
            raise ValueError("authentication_cap must be between 0 and 100.")
        ordered = [bands[k] for k in ("Low", "Medium", "High")]
        if ordered[0][0] != 0 or ordered[-1][1] != 100 or any(
            lo > hi or (i and lo != ordered[i - 1][1] + 1)
            for i, (lo, hi) in enumerate(ordered)
        ):
            raise ValueError("Risk bands must cover 0..100 without gaps or overlap.")
        object.__setattr__(self, "weights", weights)
        object.__setattr__(self, "risk_bands", bands)


def _addresses(values: list[str]) -> tuple[str | None, str | None, list[str]]:
    found: list[tuple[str, str]] = []
    malformed = []
    for value in values:
        try:
            parsed = getaddresses([value])
        except Exception:
            parsed = []
        for display_name, address in parsed:
            address = address.strip()
            if address.count("@") != 1:
                if address:
                    malformed.append("An address field was present but could not be parsed safely.")
                continue
            local, domain = address.rsplit("@", 1)
            if not local or any(ch.isspace() for ch in local):
                malformed.append("An address field was present but could not be parsed safely.")
                continue
            try:
                normalized = normalize_domain(domain)
            except (ValueError, UnicodeError):
                malformed.append("An address domain was invalid or could not be normalized.")
                continue
            # The display name is deliberately ignored; only the parsed addr-spec is used.
            found.append((f"{local}@{normalized}", normalized))
    unique = list(dict.fromkeys(found))
    if len(unique) > 1:
        malformed.append("Multiple distinct addresses were present; the first valid address is used.")
    if not unique:
        return None, None, malformed
    return unique[0][0], unique[0][1], malformed


def _statuses(headers: list[str], received_spf: list[str]) -> tuple[dict[str, str], dict[str, list[str]], list[str]]:
    values: dict[str, list[str]] = {name: [] for name in AUTH_METHODS}
    for header in headers:
        for match in _AUTH_RE.finditer(header):
            values[match.group("method").lower()].append(match.group("status").lower())
    for header in received_spf:
        match = _SPF_RE.match(header)
        if match:
            values["spf"].append(match.group(1).lower())
    statuses: dict[str, str] = {}
    conflicts: list[str] = []
    for method, results in values.items():
        unique = list(dict.fromkeys(results))
        if len(unique) > 1:
            statuses[method] = "unknown"
            conflicts.append(method)
        else:
            statuses[method] = unique[0] if unique else "unknown"
    return statuses, values, conflicts


def analyze_email_header(
    raw_header: str,
    *,
    config: ScoreConfig | None = None,
    expected_domain: str | None = None,
    trusted_domains: list[str] | None = None,
) -> dict:
    """Parse and score an RFC-style header without network access.

    Scores are heuristic indicators, not probabilities. Authentication status
    fields are reported results recorded in the supplied header, not verified
    facts. ``expected_domain``/``trusted_domains`` must come from trusted caller
    context before similarity analysis is enabled.
    """
    if not isinstance(raw_header, str):
        raise TypeError("raw_header must be a string.")
    cfg = config or ScoreConfig()
    try:
        message = Parser(policy=policy.default).parsestr(raw_header, headersonly=True)
    except Exception as exc:
        raise ValueError("Could not parse the supplied header text.") from exc

    findings: list[dict] = []

    def raw_values(field: str) -> list[str]:
        # raw_items avoids lossy recovery by parsed header objects (for example,
        # malformed addresses may otherwise be rendered as the empty mailbox <>).
        return [str(value) for name, value in message.raw_items() if name.lower() == field.lower()]

    def add(identifier: str, explanation: str, *, weight: int = 0, severity: str = "info") -> None:
        findings.append({
            "rule_id": identifier,
            "severity": severity,
            "score_contribution": int(weight),
            "explanation": explanation,
        })

    if message.defects:
        add("MALFORMED_HEADER_BLOCK", "The header parser detected malformed input; available fields were analyzed conservatively.")

    parsed: dict[str, tuple[str | None, str | None]] = {}
    for field, key in (("From", "from"), ("Reply-To", "reply_to"), ("Sender", "sender"), ("Return-Path", "return_path")):
        field_values = raw_values(field)
        address, domain, issues = _addresses(field_values)
        parsed[key] = (address, domain)
        for issue in issues:
            add(f"MALFORMED_OR_DUPLICATE_{field.upper().replace('-', '_')}", issue)
    if not raw_values("From"):
        add("FROM_MISSING", "No From field was supplied; sender identity could not be assessed.")
    elif parsed["from"][0] is None:
        add("FROM_UNPARSEABLE", "The From field did not contain one safely parseable email address.")

    auth_headers = raw_values("Authentication-Results")
    spf_headers = raw_values("Received-SPF")
    auth, raw_auth, conflicts = _statuses(auth_headers, spf_headers)
    for method in conflicts:
        add(f"CONFLICTING_{method.upper()}_RESULTS", f"Conflicting recorded {method.upper()} results were found; status is reported as unknown.")
    if not auth_headers and not spf_headers:
        add("AUTHENTICATION_RESULTS_MISSING", "No Authentication-Results or Received-SPF result was supplied; missing is treated as unknown.")
    if raw_values("DKIM-Signature"):
        add("DKIM_SIGNATURE_UNVERIFIED", "A DKIM-Signature header exists, but signature presence alone does not prove validity.")

    def mismatch(left: str, right: str, rule_id: str, weight_key: str, explanation: str) -> None:
        left_domain, right_domain = parsed[left][1], parsed[right][1]
        if left_domain and right_domain and left_domain != right_domain:
            add(rule_id, explanation, weight=cfg.weights.get(weight_key, 0), severity="medium")

    mismatch("reply_to", "from", "REPLY_TO_DOMAIN_MISMATCH", "reply_to_mismatch",
             "Reply-To and From domains differ. This can be legitimate, so review the sending context.")
    mismatch("sender", "from", "SENDER_FROM_DOMAIN_MISMATCH", "sender_from_mismatch",
             "Sender and From domains differ. Third-party sending services can cause this; review the context.")
    mismatch("return_path", "from", "RETURN_PATH_DOMAIN_MISMATCH", "", 
             "Return-Path and From domains differ. This is common in mailing systems and is informational only.")

    if expected_domain is not None or trusted_domains:
        if best_trusted_match is not None and parsed["from"][1]:
            try:
                similarity, reason = best_trusted_match(parsed["from"][1], expected_domain, trusted_domains or [])
                if similarity and similarity["relation"] == "lookalike_candidate":
                    add("SENDER_DOMAIN_LOOKALIKE", "The From domain resembles a trusted expected domain; this heuristic is not proof of maliciousness.",
                        weight=cfg.weights.get("lookalike_candidate", 0), severity="medium")
            except ValueError:
                similarity, reason = None, "trusted_domain_invalid"
        else:
            similarity, reason = None, "sender_domain_unavailable"
    else:
        similarity, reason = None, "trusted_expected_domain_not_provided"

    # Aggregate authentication signals with a group cap because DMARC may summarize
    # SPF/DKIM alignment failures. If the raw total exceeds the cap, scale all active
    # contributions proportionally and distribute rounding points deterministically.
    auth_contributions = {"dmarc": 0, "spf": 0, "dkim": 0}
    if auth["dmarc"] == "fail":
        auth_contributions["dmarc"] = cfg.weights.get("dmarc_fail", 0)
    if auth["spf"] == "fail":
        auth_contributions["spf"] = cfg.weights.get("spf_fail", 0)
    if auth["dkim"] == "fail":
        auth_contributions["dkim"] = cfg.weights.get("dkim_fail", 0)
    raw_auth_total = sum(auth_contributions.values())
    if raw_auth_total > cfg.authentication_cap:
        priority = {"dmarc": 0, "spf": 1, "dkim": 2}
        exact = {
            method: weight * cfg.authentication_cap / raw_auth_total
            for method, weight in auth_contributions.items()
        }
        auth_contributions = {method: int(value) for method, value in exact.items()}
        points_left = cfg.authentication_cap - sum(auth_contributions.values())
        rounding_order = sorted(
            exact,
            key=lambda method: (-(exact[method] - int(exact[method])), priority[method]),
        )
        for method in rounding_order[:points_left]:
            auth_contributions[method] += 1
    auth_rule_ids = {"spf": "SPF_FAIL", "dkim": "DKIM_FAIL", "dmarc": "DMARC_FAIL"}
    auth_explanations = {
        "spf": "The supplied Authentication-Results/Received-SPF records an SPF failure.",
        "dkim": "The supplied Authentication-Results records a DKIM failure.",
        "dmarc": "The supplied Authentication-Results records a DMARC failure.",
    }
    for method in ("spf", "dkim", "dmarc"):
        if auth[method] == "fail":
            contribution = auth_contributions[method]
            suffix = " Authentication-related contributions are capped to reduce correlated double counting." if contribution < cfg.weights.get(f"{method}_fail", 0) else ""
            add(auth_rule_ids[method], auth_explanations[method] + suffix, weight=contribution, severity="high")

    score = min(100, max(0, sum(item["score_contribution"] for item in findings)))
    bands = cfg.risk_bands
    risk_level = next(name for name in ("Low", "Medium", "High") if bands[name][0] <= score <= bands[name][1])
    recommendations = []
    if any(auth[m] == "fail" for m in AUTH_METHODS):
        recommendations.append("Check the authentication results against trusted receiving-MTA logs before taking action.")
    if any(item["rule_id"] in {"REPLY_TO_DOMAIN_MISMATCH", "SENDER_FROM_DOMAIN_MISMATCH", "SENDER_DOMAIN_LOOKALIKE"} for item in findings):
        recommendations.append("Verify the sender and reply destination through an independently trusted channel.")
    if any(auth[m] == "unknown" for m in AUTH_METHODS):
        recommendations.append("Treat unknown authentication results as unavailable; obtain trusted gateway results if needed.")
    if not recommendations:
        recommendations.append("No configured high-risk rule fired; continue normal email security controls.")

    return {
        "from_address": parsed["from"][0], "from_domain": parsed["from"][1],
        "reply_to_address": parsed["reply_to"][0], "reply_to_domain": parsed["reply_to"][1],
        "sender_address": parsed["sender"][0], "sender_domain": parsed["sender"][1],
        "return_path": parsed["return_path"][0], "return_path_domain": parsed["return_path"][1],
        "authentication": auth,
        "authentication_sources": {
            "spf": "Authentication-Results/Received-SPF" if raw_auth["spf"] else "unavailable",
            "dkim": "Authentication-Results" if raw_auth["dkim"] else ("DKIM-Signature header only; unverified" if raw_values("DKIM-Signature") else "unavailable"),
            "dmarc": "Authentication-Results" if raw_auth["dmarc"] else "unavailable",
        },
        "threat_score": score, "risk_level": risk_level,
        "findings": findings, "recommendations": recommendations,
        "limitations": [
            "Authentication statuses are parsed from the supplied headers and are not independently verified.",
            "Header fields can be forged outside a trusted mail infrastructure; prefer trusted receiving-MTA records.",
            "The 0-100 score is a configurable heuristic indicator, not a calibrated probability.",
            "Domain similarity is evaluated only when trusted expected-domain context is supplied; similarity is not proof of maliciousness.",
        ],
        "domain_similarity": similarity, "domain_similarity_reason": reason,
    }
