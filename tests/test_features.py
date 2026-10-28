from PhishGuard.feature_extractor import FEATURE_COLUMNS, extract_url_features


def test_url_features_have_stable_schema_and_order():
    features = extract_url_features("https://www.example.com/login?user=a%20b#section")
    assert list(features) == ["FullDomain", *FEATURE_COLUMNS]
    assert features["FullDomain"] == "example.com"
    assert features["IsHTTPS"] == 1
    assert features["HasQuery"] == 1
    assert features["HasFragment"] == 1
    assert features["HasEncodedQuery"] == 1


def test_features_support_schemeless_hosts_and_ip_addresses():
    schemeless = extract_url_features("example.org:8080/a/b")
    address = extract_url_features("https://192.0.2.1/a")
    assert schemeless["HasScheme"] == 0
    assert schemeless["PortNumber"] == 8080
    assert address["IsIPAddress"] == 1
    assert address["FullDomain"] == "192.0.2.1"


def test_invalid_urls_fail_clearly():
    import pytest

    with pytest.raises(ValueError, match="hostname"):
        extract_url_features("http:///relative/path")
    with pytest.raises(ValueError, match="port"):
        extract_url_features("https://example.com:99999/")
