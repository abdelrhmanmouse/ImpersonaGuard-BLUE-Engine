"""Possible brand-impersonation alerts for domain names.

This module is intentionally separate from ImpersonaGuard's DGA and
Rule-Based/Hybrid experiment code. Similarity alerts are not confirmations of
malicious activity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import tldextract


DEFAULT_BRAND_GROUPS: dict[str, tuple[str, ...]] = {
    "search_and_productivity": (
        "google.com", "gmail.com", "youtube.com", "microsoft.com", "outlook.com",
        "live.com", "office.com", "apple.com", "icloud.com", "adobe.com",
        "dropbox.com", "salesforce.com", "slack.com", "zoom.us", "notion.so",
        "openai.com", "chatgpt.com",
    ),
    "social_and_communication": (
        "facebook.com", "instagram.com", "whatsapp.com", "tiktok.com", "x.com",
        "twitter.com", "linkedin.com", "reddit.com", "snapchat.com", "discord.com",
        "telegram.org",
    ),
    "commerce_and_media": (
        "amazon.com", "amazonaws.com", "ebay.com", "walmart.com", "target.com",
        "aliexpress.com", "netflix.com", "spotify.com", "twitch.tv", "disneyplus.com",
        "hulu.com", "roblox.com", "steampowered.com", "steamcommunity.com",
        "epicgames.com", "booking.com", "airbnb.com", "uber.com", "lyft.com",
    ),
    "payments_and_finance": (
        "paypal.com", "venmo.com", "stripe.com", "visa.com", "mastercard.com",
        "americanexpress.com", "wise.com", "cash.app", "chase.com", "citi.com",
        "bankofamerica.com",
    ),
    "developer_and_cloud": (
        "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
        "docker.com", "cloudflare.com", "amazonaws.com",
    ),
}

DEFAULT_TRUSTED_BRANDS: tuple[str, ...] = tuple(
    dict.fromkeys(domain for group in DEFAULT_BRAND_GROUPS.values() for domain in group)
)

_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
_CONFUSABLE_MAP = str.maketrans(
    {
        "а": "a", "ɑ": "a", "α": "a", "в": "b", "Ь": "b", "с": "c",
        "ϲ": "c", "ԁ": "d", "е": "e", "ε": "e", "ё": "e", "һ": "h",
        "н": "h", "і": "i", "ι": "i", "ј": "j", "κ": "k", "к": "k",
        "ӏ": "l", "м": "m", "ո": "n", "п": "n", "о": "o", "ο": "o",
        "р": "p", "ρ": "p", "գ": "q", "г": "r", "ѕ": "s", "т": "t",
        "υ": "u", "ν": "v", "х": "x", "χ": "x", "у": "y", "ү": "y",
    }
)

_EXTRACT = tldextract.TLDExtract(
    # Use the package's bundled suffix snapshot only. Inference must not make
    # network calls to refresh the Public Suffix List.
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)


@dataclass(frozen=True)
class TyposquattingConfig:
    """Thresholds and high-risk addition tokens for possible-brand alerts."""

    similarity_threshold: float = 0.86
    max_edit_distance: int = 1
    min_edit_brand_length: int = 5
    suspicious_addition_tokens: tuple[str, ...] = (
        "account", "billing", "help", "login", "office", "official", "password",
        "secure", "security", "service", "signin", "support", "update", "verify",
        "wallet", "webmail",
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be between 0 and 1")
        if self.max_edit_distance < 0:
            raise ValueError("max_edit_distance cannot be negative")
        if self.min_edit_brand_length < 1:
            raise ValueError("min_edit_brand_length must be positive")


@dataclass(frozen=True)
class TyposquattingResult:
    """Structured result; an alert indicates similarity, not confirmed abuse."""

    original_input: Any
    normalized_hostname: str
    registered_domain: str
    possible_typosquatting: bool
    closest_trusted_brand: str | None
    similarity_score: float
    detection_reason: str
    brand_group: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_hostname(value: Any) -> str:
    """Return a lowercase ASCII/IDNA hostname from a URL or domain-like input."""

    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""

    try:
        if raw.startswith("//"):
            hostname = urlsplit(raw).hostname
        elif "://" in raw:
            hostname = urlsplit(raw).hostname
        else:
            # Parse bare hosts, optional ports, paths, query strings and fragments.
            hostname = urlsplit("//" + raw).hostname
        if not hostname:
            return ""
        hostname = hostname.rstrip(".").lower()
        return hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, ValueError):
        return ""


def _domain_parts(hostname: str) -> tuple[str, str]:
    """Return (registered domain, registrable label) using the Public Suffix List."""

    extracted = _EXTRACT(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}", extracted.domain.lower()

    # The PSL has no entry for special-use/test suffixes; conservatively treat the
    # final label as the suffix so synthetic test domains still compare by SLD.
    labels = hostname.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[-2].lower()
    return hostname, hostname.lower()


def _unicode_label(label: str) -> str:
    try:
        return label.encode("ascii").decode("idna").lower()
    except (UnicodeError, ValueError):
        return label.lower()


def _skeleton(label: str) -> str:
    return _unicode_label(label).translate(_CONFUSABLE_MAP).translate(_LEET_MAP)


def _damerau_levenshtein(left: str, right: str) -> int:
    """Optimal-string-alignment distance, including adjacent transpositions."""

    rows, cols = len(left) + 1, len(right) + 1
    matrix = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        matrix[i][0] = i
    for j in range(cols):
        matrix[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )
            if (
                i > 1 and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + cost)
    return matrix[-1][-1]


def _similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _flatten_groups(groups: Mapping[str, Sequence[str]]) -> list[tuple[str, str]]:
    flattened: list[tuple[str, str]] = []
    seen: set[str] = set()
    for group, domains in groups.items():
        for domain in domains:
            normalized = normalize_hostname(domain)
            if normalized and normalized not in seen:
                flattened.append((normalized, group))
                seen.add(normalized)
    return flattened


class TyposquattingDetector:
    """Compare a candidate's registered domain with configurable trusted brands."""

    def __init__(
        self,
        brand_groups: Mapping[str, Sequence[str]] | None = None,
        trusted_brands: Sequence[str] | None = None,
        config: TyposquattingConfig | None = None,
    ) -> None:
        if brand_groups is not None and trusted_brands is not None:
            raise ValueError("Pass brand_groups or trusted_brands, not both")
        self.config = config or TyposquattingConfig()
        if brand_groups is not None:
            self._brands = _flatten_groups(brand_groups)
        elif trusted_brands is not None:
            self._brands = [(n, "custom") for n in map(normalize_hostname, trusted_brands) if n]
        else:
            self._brands = _flatten_groups(DEFAULT_BRAND_GROUPS)
        if not self._brands:
            raise ValueError("At least one valid trusted brand domain is required")

    @property
    def trusted_brands(self) -> tuple[str, ...]:
        return tuple(domain for domain, _ in self._brands)

    def detect(self, value: Any) -> TyposquattingResult:
        host = normalize_hostname(value)
        if not host:
            return TyposquattingResult(
                value, "", "", False, None, 0.0, "invalid_or_empty_input", None
            )

        candidate_registered, candidate_sld = _domain_parts(host)
        best_brand: str | None = None
        best_group: str | None = None
        best_score = -1.0
        best_reason = "below_configured_threshold"
        best_alert: tuple[float, str, str, str] | None = None

        for brand, group in self._brands:
            brand_registered, brand_sld = _domain_parts(brand)
            if candidate_registered == brand_registered:
                return TyposquattingResult(
                    value, host, candidate_registered, False, brand, 1.0,
                    "exact_trusted_registered_domain_exemption", group,
                )

            candidate_unicode = _unicode_label(candidate_sld)
            brand_unicode = _unicode_label(brand_sld)
            candidate_skeleton = _skeleton(candidate_sld)
            brand_skeleton = _skeleton(brand_sld)
            score = max(
                _similarity(candidate_sld, brand_sld),
                _similarity(candidate_unicode, brand_unicode),
                _similarity(candidate_skeleton, brand_skeleton),
            )
            distance = _damerau_levenshtein(candidate_skeleton, brand_skeleton)

            reason: str | None = None
            if self._has_suspicious_addition(candidate_skeleton, brand_skeleton):
                reason = "brand_plus_suspicious_addition"
            elif candidate_skeleton == brand_skeleton and candidate_sld != brand_sld:
                if any(ord(char) > 127 for char in candidate_unicode):
                    reason = "idn_confusable_match"
                else:
                    reason = "lookalike_character_substitution"
            elif (
                len(brand_skeleton) >= self.config.min_edit_brand_length
                and distance <= self.config.max_edit_distance
                and distance > 0
            ):
                reason = f"edit_distance_{distance}_including_transposition"
                score = max(score, 1.0 - distance / max(len(candidate_skeleton), len(brand_skeleton)))
            elif score >= self.config.similarity_threshold:
                reason = "character_similarity_threshold"

            if score > best_score:
                best_score = score
                best_brand = brand
                best_group = group
                best_reason = reason or "below_configured_threshold"
            if reason is not None and (best_alert is None or score > best_alert[0]):
                best_alert = (score, brand, group, reason)

        if best_alert is not None:
            best_score, best_brand, best_group, best_reason = best_alert

        return TyposquattingResult(
            original_input=value,
            normalized_hostname=host,
            registered_domain=candidate_registered,
            possible_typosquatting=best_alert is not None,
            closest_trusted_brand=best_brand,
            similarity_score=max(0.0, min(1.0, best_score)),
            detection_reason=best_reason,
            brand_group=best_group,
        )

    def _has_suspicious_addition(self, candidate: str, brand: str) -> bool:
        if not candidate or not brand:
            return False
        tokens = set(self.config.suspicious_addition_tokens)
        if not tokens:
            return False
        candidate_parts = [part for part in candidate.replace("_", "-").split("-") if part]
        if brand in candidate_parts and tokens.intersection(candidate_parts):
            return True
        for token in tokens:
            if candidate in {brand + token, brand + "-" + token, token + brand, token + "-" + brand}:
                return True
        return False


__all__ = [
    "DEFAULT_BRAND_GROUPS",
    "DEFAULT_TRUSTED_BRANDS",
    "TyposquattingConfig",
    "TyposquattingDetector",
    "TyposquattingResult",
    "normalize_hostname",
]
