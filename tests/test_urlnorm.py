import pytest

from webvault.urlnorm import (
    UrlError,
    canonicalize_url,
    from_cdx_timestamp,
    normalize_timestamp,
    to_cdx_timestamp,
    urlkey,
)


def test_canonicalization_is_conservative():
    assert canonicalize_url("HTTPS://Site-A.TEST:443/a/../b?b=2&a=1#frag") == (
        "https://site-a.test/a/../b?b=2&a=1"
    )
    assert canonicalize_url("http://site-b.test:80") == "http://site-b.test/"
    assert canonicalize_url("http://site-b.test:8080/x") == "http://site-b.test:8080/x"
    assert canonicalize_url("https://site-a.test/a%2fb") == "https://site-a.test/a%2Fb"


def test_query_order_is_never_reordered():
    assert canonicalize_url("https://site-a.test/s?z=1&a=2").endswith("?z=1&a=2")


def test_surt_style_urlkey_and_ports():
    assert urlkey("https://site-a.test/index.html?b=2&a=1") == (
        "https://(test,site-a)/index.html?b=2&a=1"
    )
    assert urlkey("http://site-b.test:8080/") == "http://(test,site-b:8080)/"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://site-a.test/file",
        "https:///missing-host",
        "/relative/path",
        "https://user:pass@site-a.test/",
        "https://site-a.test/bad%zz",
        "https://site-a.test/has space",
    ],
)
def test_invalid_urls_are_rejected(value):
    with pytest.raises(UrlError):
        canonicalize_url(value)


def test_timestamp_normalization_and_cdx_roundtrip():
    assert normalize_timestamp("2024-03-01T10:00:00+01:00") == "2024-03-01T09:00:00Z"
    assert normalize_timestamp("2024-03-01T09:00:00.900Z") == "2024-03-01T09:00:00Z"
    stamp = to_cdx_timestamp("2024-03-01T09:00:00Z")
    assert stamp == "20240301090000"
    assert from_cdx_timestamp(stamp) == "2024-03-01T09:00:00Z"
    with pytest.raises(ValueError):
        normalize_timestamp("2024-03-01T09:00:00")
