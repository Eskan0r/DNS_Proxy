"""Upstream resolver: DoH resolve, UDP fallback, failure, latency overhead (Toan)."""
import socket

import pytest
from dnslib import DNSRecord, RCODE

from src.upstream import UpstreamError, UpstreamResolver

# Nothing listens on port 1, so DoH fails fast with "connection refused"
DEAD_DOH = ["https://127.0.0.1:1/dns-query"]


def _online() -> bool:
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2).close()
        return True
    except OSError:
        return False


needs_net = pytest.mark.skipif(not _online(), reason="no network")


@needs_net
def test_resolve_example_com():
    # fallback=None: DoH alone must work, UDP can't mask a DoH bug
    answers, ttl, ms, rcode = UpstreamResolver(fallback=None).resolve("example.com")
    assert answers and ttl > 0 and ms > 0
    assert rcode == RCODE.NOERROR


@needs_net
def test_nxdomain_keeps_rcode():
    answers, _, _, rcode = UpstreamResolver().resolve("does-not-exist.invalid")
    assert answers == []
    assert rcode == RCODE.NXDOMAIN


@needs_net
def test_timeout_fallback():
    up = UpstreamResolver(doh_urls=DEAD_DOH, timeout=0.5)
    answers, _, _, rcode = up.resolve("example.com")
    assert answers and rcode == RCODE.NOERROR


def test_all_down_raises():
    up = UpstreamResolver(doh_urls=DEAD_DOH, timeout=0.5, fallback=None)
    with pytest.raises(UpstreamError):
        up.resolve("example.com")


def test_bad_qtype_raises_before_network():
    up = UpstreamResolver(doh_urls=[], fallback=None)
    with pytest.raises(UpstreamError, match="Unsupported qtype"):
        up.resolve("example.com", "NOTATYPE")


@needs_net
def test_latency_measure():
    up = UpstreamResolver()
    assert up.measure_direct("example.com") > 0
    up.resolve("example.com")
    s = up.stats()
    assert s["upstream"]["count"] == 1 and s["direct"]["count"] == 1
    assert "overhead_ms" in s


def test_stats_empty():
    s = UpstreamResolver(doh_urls=[], fallback=None).stats()
    assert s["upstream"]["count"] == 0 and "overhead_ms" not in s


def test_valid_checks_id_qr_and_rcode():
    q = DNSRecord.question("example.com")
    query = q.pack()
    assert UpstreamResolver._valid(q.reply().pack(), query)

    assert not UpstreamResolver._valid(query, query)          # echoed query, QR=0

    other = q.reply()
    other.header.id = (q.header.id + 1) % 65536
    assert not UpstreamResolver._valid(other.pack(), query)   # wrong transaction ID

    servfail = q.reply()
    servfail.header.rcode = RCODE.SERVFAIL
    assert not UpstreamResolver._valid(servfail.pack(), query)

    assert not UpstreamResolver._valid(b"garbage", query)


def test_qtype_attribute_name_rejected():
    with UpstreamResolver(doh_urls=[], fallback=None) as up:
        with pytest.raises(UpstreamError, match="Unsupported qtype"):
            up.resolve("example.com", "get")


def test_measure_direct_without_fallback():
    with UpstreamResolver(doh_urls=[], fallback=None) as up:
        with pytest.raises(UpstreamError, match="No UDP fallback"):
            up.measure_direct("example.com")


@needs_net
def test_hung_doh_does_not_starve_next():
    # Listener that never accepts: the TLS handshake hangs until the per-try timeout
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    hung = f"https://127.0.0.1:{srv.getsockname()[1]}/dns-query"
    try:
        with UpstreamResolver(doh_urls=[hung, "https://cloudflare-dns.com/dns-query"],
                              timeout=2, fallback=None) as up:
            answers, _, _, _ = up.resolve("example.com")
        assert answers
    finally:
        srv.close()
