"""Domain parsing and lookalike comparison, independent of text classification."""

from __future__ import annotations

import ipaddress
import re
from email.utils import getaddresses, parseaddr
from rapidfuzz.fuzz import ratio


def normalize_domain(value: str) -> str:
    """Return a validated lower-case ASCII IDNA domain without a trailing dot."""
    if not isinstance(value, str):
        raise ValueError("Domain must be a string.")
    value = value.strip().casefold()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253:
        raise ValueError("Domain is empty or longer than 253 characters.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain cannot be normalized with IDNA.") from exc
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted as domains.")
    labels = value.split(".")
    if len(labels) < 2 or any(
        len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Provide a valid fully qualified domain name.")
    return value


def extract_sender_domain(sender_address: str) -> str:
    """Extract and validate the domain portion of one sender address."""
    if not isinstance(sender_address, str) or not sender_address.strip():
        raise ValueError("sender_address must contain an email address.")
    sender_address = sender_address.strip()
    if ("<" in sender_address) != (">" in sender_address):
        raise ValueError("sender_address has unbalanced angle brackets.")
    if "<" not in sender_address and any(char.isspace() for char in sender_address):
        raise ValueError("sender_address must be one email address, optionally with a display name.")
    parsed = getaddresses([sender_address])
    if len(parsed) != 1:
        raise ValueError("sender_address must contain exactly one email address.")
    _, address = parseaddr(sender_address)
    if not address or address.count("@") != 1:
        raise ValueError("sender_address must contain exactly one email address.")
    local, domain = address.rsplit("@", 1)
    if not local or any(char.isspace() for char in local):
        raise ValueError("sender_address is malformed or contains multiple addresses.")
    return normalize_domain(domain)


def compare_domain(sender_domain: str, expected_domain: str) -> dict:
    """Compare two already-provided domains; similarity is a heuristic, not a verdict."""
    sender = normalize_domain(sender_domain)
    expected = normalize_domain(expected_domain)
    if sender == expected:
        score, relation = 1.0, "exact_match"
    elif sender.endswith("." + expected):
        score, relation = 1.0, "sender_is_subdomain"
    else:
        score = ratio(sender, expected) / 100.0
        relation = "lookalike_candidate" if score >= 0.80 else "unrelated"
    reason = {
        "exact_match": "Sender domain exactly matches the expected domain after normalization.",
        "sender_is_subdomain": "Sender domain is a subdomain of the expected domain.",
        "lookalike_candidate": "Sender domain is textually similar to the expected domain; verify ownership separately.",
        "unrelated": "Sender domain is not an exact match, expected subdomain, or close textual match.",
    }[relation]
    return {
        "sender_domain": sender,
        "expected_domain": expected,
        "similarity": round(float(score), 6),
        "relation": relation,
        "reason": reason,
        "heuristic_threshold": 0.80,
    }


def best_trusted_match(sender_domain: str, expected_domain: str | None, trusted_domains: list[str]) -> tuple[dict | None, str | None]:
    if not sender_domain:
        return None, "sender_address_not_provided"
    candidates = [normalize_domain(expected_domain)] if expected_domain else trusted_domains
    if not candidates:
        return None, "no_explicit_or_configured_trusted_expected_domain"
    comparisons = [compare_domain(sender_domain, candidate) for candidate in candidates]
    best = max(comparisons, key=lambda result: (result["similarity"], result["relation"] == "exact_match"))
    best["comparison_source"] = "request_expected_domain" if expected_domain else "configured_trusted_domains"
    return best, None
