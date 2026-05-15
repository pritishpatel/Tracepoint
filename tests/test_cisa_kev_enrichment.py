"""Tests for CISA KEV category and severity enrichment."""

from __future__ import annotations

from scripts.import_cisa_kev import category_from_kev, severity_from_kev


def make_record(name: str, description: str, ransomware: str = "Unknown") -> dict[str, str]:
    """Create a minimal KEV-style record."""
    return {
        "cveID": "CVE-2026-9999",
        "vendorProject": "Example",
        "product": "Example Product",
        "vulnerabilityName": name,
        "shortDescription": description,
        "requiredAction": "Apply mitigations per vendor instructions.",
        "knownRansomwareCampaignUse": ransomware,
        "notes": "https://example.com/advisory",
    }


def test_auth_bypass_maps_to_critical() -> None:
    """Authentication bypass should map to auth_bypass and critical."""
    record = make_record(
        "Example Authentication Bypass Vulnerability",
        "Allows an unauthenticated remote attacker to bypass authentication "
        "and obtain administrative privileges.",
    )

    assert category_from_kev(record) == "auth_bypass"
    assert severity_from_kev(record) == "critical"


def test_remote_code_execution_maps_to_critical() -> None:
    """Remote code execution should map to RCE and critical."""
    record = make_record(
        "Example Remote Code Execution Vulnerability",
        "Allows attackers to execute arbitrary code on affected systems.",
    )

    assert category_from_kev(record) == "remote_code_execution"
    assert severity_from_kev(record) == "critical"


def test_path_traversal_maps_to_high() -> None:
    """Path traversal should map to path_traversal and high."""
    record = make_record(
        "Example Path Traversal Vulnerability",
        "Allows an attacker to write arbitrary files using a crafted archive.",
    )

    assert category_from_kev(record) == "path_traversal"
    assert severity_from_kev(record) == "high"


def test_xss_maps_to_medium() -> None:
    """XSS should map to xss and medium."""
    record = make_record(
        "Example Cross-Site Scripting Vulnerability",
        "Allows attackers to execute arbitrary JavaScript within a user session.",
    )

    assert category_from_kev(record) == "xss"
    assert severity_from_kev(record) == "medium"


def test_unknown_kev_defaults_to_known_exploited_medium() -> None:
    """Unmatched KEV records should still remain known exploited vulnerabilities."""
    record = make_record(
        "Example Protection Mechanism Failure Vulnerability",
        "The product contains a protection mechanism failure vulnerability.",
    )

    assert category_from_kev(record) == "known_exploited_vulnerability"
    assert severity_from_kev(record) == "medium"


def test_known_ransomware_use_promotes_to_high() -> None:
    """Known ransomware use should promote weakly described records to high."""
    record = make_record(
        "Example Vulnerability",
        "The product contains a weakness currently exploited in the wild.",
        ransomware="Known",
    )

    assert severity_from_kev(record) == "high"
