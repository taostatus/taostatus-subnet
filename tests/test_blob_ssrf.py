"""F3 fix: the validator validates a miner-supplied blob_url before fetching it,
so the miner cannot point it at the validator's own internal network or cloud
metadata (SSRF). The validation reuses target_guard.validate_target; these pin
down that blob-style URLs resolving to non-public addresses are refused and a
genuine public one passes."""

import pytest

from secqurityVali.target_guard import TargetRejected, validate_target


def _resolve_to(ip):
    return lambda host: [ip]


def test_blob_url_to_cloud_metadata_is_refused():
    with pytest.raises(TargetRejected):
        validate_target("http://169.254.169.254/latest/meta-data/agent.enc",
                        resolve=_resolve_to("169.254.169.254"))


def test_blob_url_to_loopback_is_refused_even_via_hostname():
    # a hostname that resolves to loopback must still be refused (DNS trick)
    with pytest.raises(TargetRejected):
        validate_target("http://miner.example/agent.enc", resolve=_resolve_to("127.0.0.1"))


def test_blob_url_to_private_network_is_refused():
    for ip in ("10.0.0.5", "192.168.1.9", "172.16.0.3"):
        with pytest.raises(TargetRejected):
            validate_target("http://internal/agent.enc", resolve=_resolve_to(ip))


def test_blob_url_non_http_scheme_refused():
    with pytest.raises(TargetRejected):
        validate_target("file:///etc/passwd", resolve=_resolve_to("1.2.3.4"))


def test_genuine_public_blob_url_passes():
    pinned = validate_target("http://1.2.3.4:8912/agent.enc", resolve=_resolve_to("1.2.3.4"))
    assert pinned.ip == "1.2.3.4" and pinned.port == 8912 and pinned.scheme == "http"
