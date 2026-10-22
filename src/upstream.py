"""Upstream resolver (DoH + fallback), Toan Nguyen

Contract for proxy.py:
    up = UpstreamResolver()
    answers, ttl, latency_ms, rcode = up.resolve("example.com", "A")
    # answers=["93.184.216.34"], ttl=300 -> cache + reply
    # On total failure -> raise UpstreamError so proxy returns SERVFAIL.

Requirements:
- DoH (https://cloudflare-dns.com/dns-query, dns.google) via httpx/requests.
- Timeout (config.UPSTREAM_TIMEOUT_SEC) + retries + UDP fallback to 8.8.8.8.
- Measure latency_ms per query for Kareem's eval (direct vs proxy overhead).
"""
import socket
import statistics
import threading
import time
from collections import deque

import httpx
from dnslib import DNSRecord, QTYPE, RCODE

from . import config


class UpstreamError(Exception):
    """Raised when all upstreams fail."""


class UpstreamResolver:

    def __init__(self, doh_urls: list[str] | None = None,
                 timeout: float = config.UPSTREAM_TIMEOUT_SEC,
                 retries: int = config.UPSTREAM_RETRIES,
                 fallback: tuple[str, int] = config.UPSTREAM_FALLBACK_UDP):
        self.doh_urls = config.UPSTREAM_DOH_URLS if doh_urls is None else doh_urls
        self.timeout = timeout
        self.retries = max(1, retries)
        self.fallback = fallback
        self._client = httpx.Client(timeout=timeout)
        self._lock = threading.Lock()
        self._latencies = deque(maxlen=10_000)
        self._direct = deque(maxlen=10_000)

    def resolve(self, domain: str, qtype: str = "A") -> tuple[list[str], int, float, int]:
        """Try each DoH URL, then UDP fallback. Return (ips, ttl, latency_ms, rcode)."""
        # Check before any network call; dnslib raises DNSError (not AttributeError) on unknown names
        try:
            want = getattr(QTYPE, qtype)
        except Exception:
            raise UpstreamError(f"Unsupported qtype {qtype}") from None

        start = time.perf_counter()
        reply = DNSRecord.parse(self.forward(DNSRecord.question(domain, qtype).pack()))

        answers = [str(rr.rdata) for rr in reply.rr if rr.rtype == want]

        if reply.rr:
            ttl = min(rr.ttl for rr in reply.rr)
        else:
            soa = [rr for rr in reply.auth if rr.rtype == QTYPE.SOA]
            ttl = min(soa[0].ttl, soa[0].rdata.times[-1]) if soa else 0

        return answers, ttl, self._record(start, self._latencies), reply.header.rcode

    def forward(self, query: bytes) -> bytes:
        """send raw DNS wire bytes upstream, return raw DNS wire bytes reply, or raise UpstreamError."""
        query = bytes(query)  # dnslib .pack() gives bytearray; httpx would stream it as ints
        deadline = time.perf_counter() + self.timeout

        errors = []

        for _ in range(self.retries):
            for url in self.doh_urls:
                if time.perf_counter() >= deadline:
                    break
                try:
                    r = self._client.post(url, content=query, headers={
                        "Content-Type": "application/dns-message",
                        "Accept": "application/dns-message",},
                        timeout=max(0.1, deadline - time.perf_counter()))

                    if r.status_code == 200 and self._valid(r.content, query):
                        return r.content

                    reason = "invalid reply" if r.status_code == 200 else f"HTTP {r.status_code}"
                    errors.append(f"DoH {url} failed: {reason}")
                except httpx.HTTPError as e:
                    errors.append(f"DoH {url} failed: {e}")

        if self.fallback:
            try:
                reply = self._udp(query)
                if self._valid(reply, query):
                    return reply
                errors.append(f"UDP fallback {self.fallback[0]} failed: invalid reply")
            except OSError as e:
                errors.append(f"UDP fallback {self.fallback[0]} failed: {e}")

        raise UpstreamError("; ".join(errors) or "no upstreams configured")

    def _udp(self, query: bytes) -> bytes:
        """One plain UDP query to the fallback server; used by forward() and measure_direct()."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query, self.fallback)
            reply, _ = sock.recvfrom(4096)
            return reply

    def stats(self) -> dict:
        """Latency for the report: upstream (resolve) vs direct UDP (measure_direct), successes only."""
        with self._lock:
            up, direct = sorted(self._latencies), sorted(self._direct)
        out = {"upstream": self._summary(up), "direct": self._summary(direct)}
        if up and direct:
            out["overhead_ms"] = round(statistics.mean(up) - statistics.mean(direct), 2)
        return out

    @staticmethod
    def _summary(latencies: list[float]) -> dict:
        if not latencies:
            return {"count": 0, "mean": None, "median": None, "min": None, "max": None}
        return {
            "count": len(latencies),
            "mean": round(statistics.mean(latencies), 2),
            "median": round(statistics.median(latencies), 2),
            "min": round(min(latencies), 2),
            "max": round(max(latencies), 2),
        }

    def measure_direct(self, domain: str, qtype: str = "A") -> float:
        """Time one plain UDP query to fallback resolver, return latency_ms. For eval only."""
        query = DNSRecord.question(domain, qtype).pack()
        start = time.perf_counter()
        try:
            reply = self._udp(query)
        except OSError as e:
            raise UpstreamError(f"Direct UDP {self.fallback[0]} failed: {e}")
        if not self._valid(reply, query):
            raise UpstreamError(f"Direct UDP {self.fallback[0]} failed: invalid reply")
        return self._record(start, self._direct)

    def _record(self, start: float, into) -> float:
        ms = (time.perf_counter() - start) * 1000
        with self._lock:
            into.append(ms)
        return ms

    @staticmethod
    def _valid(data: bytes, query: bytes) -> bool:
        # A response (QR=1) with the same transaction ID, and upstream didn't itself fail
        # (SERVFAIL/REFUSED -> try next)
        try:
            reply = DNSRecord.parse(data)
        except Exception:
            return False
        return (data[:2] == query[:2] and reply.header.qr == 1
                and reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN))
