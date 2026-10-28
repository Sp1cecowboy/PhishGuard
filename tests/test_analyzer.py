import pytest
from app.main import analyze_url


def test_plain_domain_has_no_findings():
    result = analyze_url("https://example.com")
    assert result.risk_score == 0
    assert result.risk_level == "low"
    assert result.findings == []


def test_http_adds_finding():
    result = analyze_url("http://example.com")
    assert any(f.code == "NO_HTTPS" for f in result.findings)


def test_ip_host_is_flagged():
    result = analyze_url("http://192.0.2.10/login")
    assert any(f.code == "IP_HOST" for f in result.findings)


def test_sensitive_keywords_are_explained():
    result = analyze_url("https://example.com/verify-account")
    assert any(f.code == "SENSITIVE_KEYWORDS" for f in result.findings)


def test_non_http_scheme_is_rejected():
    with pytest.raises(ValueError):
        analyze_url("javascript:alert(1)")


def test_score_is_bounded():
    result = analyze_url("http://192.0.2.10/login/verify/account/password")
    assert 0 <= result.risk_score <= 100
