"""Deterministic lexical URL features; no network, DNS, or page access."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit


SCHEMA_VERSION = "1.0.0"
FEATURE_NAMES = (
    "url_length",
    "url_dot_count",
    "url_hyphen_count",
    "url_underscore_count",
    "url_slash_count",
    "url_question_mark_count",
    "url_equals_count",
    "url_ampersand_count",
    "url_at_sign_count",
    "url_percent_count",
    "url_fragment_marker_count",
    "scheme_is_https",
    "scheme_is_http",
    "scheme_is_implicit",
    "userinfo_present",
    "hostname_length_idna",
    "hostname_dot_count",
    "hostname_label_count",
    "subdomain_label_count_heuristic",
    "host_is_ip_literal",
    "hostname_has_unicode",
    "hostname_has_punycode_label",
    "port_present",
    "port_is_nondefault",
    "path_length",
    "path_segment_count",
    "query_present",
    "query_length",
    "query_parameter_count",
    "fragment_present",
    "fragment_length",
    "percent_encoded_octet_count",
    "invalid_percent_escape_count",
    "encoded_reserved_char_count",
)

_SPECIAL_COUNTS = {
    "url_dot_count": ".",
    "url_hyphen_count": "-",
    "url_underscore_count": "_",
    "url_slash_count": "/",
    "url_question_mark_count": "?",
    "url_equals_count": "=",
    "url_ampersand_count": "&",
    "url_at_sign_count": "@",
    "url_percent_count": "%",
    "url_fragment_marker_count": "#",
}
_PERCENT_OCTET = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_RESERVED = re.compile(r"%(?:2f|3a|40|2e|5c)", re.IGNORECASE)
_SCHEME_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


def _parse_url(raw_url: str) -> tuple[str, str, bool, bool, int | None, str, str, str]:
    if not isinstance(raw_url, str):
        raise TypeError("URL must be a string")
    value = raw_url.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("URL must not contain unescaped whitespace or control characters")

    scheme_match = _SCHEME_PREFIX.match(value)
    explicit_scheme = scheme_match is not None
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")
        parse_value = value
    else:
        scheme = "http"
        parse_value = "http:" + value if value.startswith("//") else "http://" + value

    try:
        parts = urlsplit(parse_value)
        hostname = parts.hostname
        port = parts.port  # raises for malformed or out-of-range ports
    except ValueError as exc:
        raise ValueError(f"Malformed URL authority: {exc}") from exc
    if not hostname:
        raise ValueError("URL must contain a hostname")

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    has_unicode = any(ord(ch) > 127 for ch in hostname)
    if is_ip:
        canonical_host = hostname.lower()
    else:
        try:
            canonical_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError(f"Hostname cannot be converted to IDNA ASCII: {exc}") from exc
        if len(canonical_host) > 253 or any(not label for label in canonical_host.rstrip(".").split(".")):
            raise ValueError("Hostname has an invalid label structure")

    return (
        value, scheme, explicit_scheme, is_ip, port, canonical_host,
        parts.path, parts.query,  # type: ignore[return-value]
    )


def extract_url_features(raw_url: str) -> dict[str, int]:
    """Extract a stable ordered mapping of integer features from one URL.

    Outer whitespace is stripped. Inputs without a scheme are parsed as HTTP,
    while explicit non-HTTP(S) schemes, missing hosts, invalid ports, internal
    whitespace, and control characters are rejected. Values are lexical only.
    """
    parsed = _parse_url(raw_url)
    value, scheme, explicit_scheme, is_ip, port, host, path, query = parsed
    # Reparse only after the validated normalization above to read authority flags.
    parse_value = value if explicit_scheme else ("http:" + value if value.startswith("//") else "http://" + value)
    parts = urlsplit(parse_value)
    labels = [] if is_ip else host.rstrip(".").split(".")
    path_segments = [segment for segment in path.split("/") if segment]
    query_pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    default_port = 443 if scheme == "https" else 80

    features = {name: value.count(char) for name, char in _SPECIAL_COUNTS.items()}
    features.update({
        "url_length": len(value),
        "scheme_is_https": int(scheme == "https"),
        "scheme_is_http": int(scheme == "http"),
        "scheme_is_implicit": int(not explicit_scheme),
        "userinfo_present": int("@" in parts.netloc),
        "hostname_length_idna": len(host),
        "hostname_dot_count": host.count("."),
        "hostname_label_count": len(labels),
        # Heuristic only: subtracting two labels is not a public-suffix lookup.
        "subdomain_label_count_heuristic": max(len(labels) - 2, 0),
        "host_is_ip_literal": int(is_ip),
        "hostname_has_unicode": int(any(ord(ch) > 127 for ch in parts.hostname or "")),
        "hostname_has_punycode_label": int(any(label.startswith("xn--") for label in labels)),
        "port_present": int(port is not None),
        "port_is_nondefault": int(port is not None and port != default_port),
        "path_length": len(path),
        "path_segment_count": len(path_segments),
        "query_present": int("?" in value.split("#", 1)[0]),
        "query_length": len(query),
        "query_parameter_count": len(query_pairs),
        "fragment_present": int("#" in value),
        "fragment_length": len(parts.fragment),
        "percent_encoded_octet_count": len(_PERCENT_OCTET.findall(value)),
        "invalid_percent_escape_count": len(_INVALID_PERCENT.findall(value)),
        "encoded_reserved_char_count": len(_ENCODED_RESERVED.findall(value)),
    })
    # The explicit mapping order is part of the feature schema contract.
    return {name: int(features[name]) for name in FEATURE_NAMES}


def extract_feature_row(raw_url: str) -> list[int]:
    """Return feature values in ``FEATURE_NAMES`` order."""
    return list(extract_url_features(raw_url).values())


def normalized_hostname(raw_url: str) -> str:
    """Return the canonical IDNA hostname used for safe split grouping."""
    return _parse_url(raw_url)[5]
