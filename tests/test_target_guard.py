"""Precise anti-SSRF tests for secqurityVali/target_guard.validate_target.

The guard is the gate that stops a customer-supplied URL from pointing our
sandbox at internal/metadata/loopback hosts. Resolution is injected so every
edge case is deterministic.
"""

import pytest

from secqurityVali.target_guard import PinnedTarget, TargetRejected, validate_target


def fixed(ip):
    """A resolver that always returns one IP, whatever the host."""
    return lambda host: [ip]


def mapping(table):
    """A resolver backed by {host: [ips]}; unknown host raises (NXDOMAIN-like)."""
    def _r(host):
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]
    return _r


# --- the happy path ----------------------------------------------------

def test_accepts_public_http_and_pins_resolved_ip():
    t = validate_target("http://shop.example.com/login", resolve=fixed("93.184.216.34"))
    assert t == PinnedTarget(ip="93.184.216.34", port=80, scheme="http", host="shop.example.com")


def test_accepts_https_default_port():
    t = validate_target("https://api.example.com/", resolve=fixed("93.184.216.34"))
    assert t.scheme == "https" and t.port == 443


def test_explicit_port_is_honoured():
    t = validate_target("https://x.example.com:8443/a", resolve=fixed("93.184.216.34"))
    assert t.port == 8443


def test_accepts_public_ipv6():
    t = validate_target("http://[2606:4700:4700::1111]/", resolve=fixed("2606:4700:4700::1111"))
    assert t.ip == "2606:4700:4700::1111"


def test_pins_resolved_ip_not_hostname():
    t = validate_target("http://rebind.example.com/", resolve=fixed("93.184.216.34"))
    assert t.ip == "93.184.216.34" and t.host == "rebind.example.com"


# --- scheme ------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "gopher://x/", "dict://x:11211/", "ftp://x/", "ldap://x/",
    "//no-scheme.example.com/", "javascript:alert(1)",
])
def test_rejects_non_http_schemes(url):
    with pytest.raises(TargetRejected):
        validate_target(url, resolve=fixed("93.184.216.34"))


# --- IP literals: private / loopback / link-local / metadata -----------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254",
    "0.0.0.0", "100.64.0.1",                       # unspecified, CGNAT
])
def test_rejects_private_ipv4_literals(ip):
    with pytest.raises(TargetRejected):
        validate_target(f"http://{ip}/", resolve=fixed(ip))


@pytest.mark.parametrize("ip", [
    "::1",                 # loopback
    "fd00::1",             # unique-local
    "fe80::1",             # link-local
    "::ffff:169.254.169.254",   # IPv4-mapped metadata (bypass attempt)
    "::ffff:10.0.0.1",          # IPv4-mapped private
])
def test_rejects_private_ipv6_and_mapped(ip):
    with pytest.raises(TargetRejected):
        validate_target(f"http://[{ip}]/", resolve=fixed(ip))


def test_rejects_metadata_even_if_somehow_public_flagged():
    with pytest.raises(TargetRejected):
        validate_target("http://metadata.example.com/", resolve=fixed("169.254.169.254"))


# --- the resolved IP is what matters (encodings resolve first) ---------

def test_decimal_encoded_ip_is_caught_via_resolution():
    # 2130706433 == 127.0.0.1; the resolver yields the real loopback -> rejected
    with pytest.raises(TargetRejected):
        validate_target("http://2130706433/", resolve=fixed("127.0.0.1"))


# --- userinfo bypass ---------------------------------------------------

def test_userinfo_does_not_fool_host_parsing():
    # real host is evil.internal (after @); it resolves private -> rejected
    r = mapping({"evil.internal": ["10.0.0.1"], "good.example.com": ["93.184.216.34"]})
    with pytest.raises(TargetRejected):
        validate_target("http://good.example.com@evil.internal/", resolve=r)


# --- mixed records: ANY private rejects --------------------------------

def test_mixed_public_and_private_records_are_rejected():
    r = mapping({"mixed.example.com": ["93.184.216.34", "10.0.0.1"]})
    with pytest.raises(TargetRejected):
        validate_target("http://mixed.example.com/", resolve=r)


# --- ports / host / resolution failures --------------------------------

def test_rejects_out_of_range_port():
    with pytest.raises(TargetRejected):
        validate_target("http://x.example.com:0/", resolve=fixed("93.184.216.34"))


def test_rejects_unresolvable_host():
    with pytest.raises(TargetRejected):
        validate_target("http://nope.invalid/", resolve=mapping({}))


def test_rejects_host_that_resolves_to_nothing():
    with pytest.raises(TargetRejected):
        validate_target("http://empty.example.com/", resolve=lambda h: [])


# --- connector / internal-target mode ----------------------------------

def test_allow_private_permits_internal_target_for_connector_mode():
    t = validate_target("http://intranet.corp/", resolve=fixed("10.0.0.5"), allow_private=True)
    assert t.ip == "10.0.0.5"
    # ...but metadata is blocked even then
    with pytest.raises(TargetRejected):
        validate_target("http://x/", resolve=fixed("169.254.169.254"), allow_private=True)
