"""Feed updater + allowlist override + sinkhole builder, Artin Seyrafi

Contract for proxy.py:
    updater.update_daily()                    # download URLhaus / PhishTank / MDL
    allow = Allowlist(); allow.is_allowed("mybank.com") -> True (override, allow first)
    resp = build_sinkhole_reply(request)      # dnslib reply with 0.0.0.0

Pipeline order matters: allowlist checked BEFORE blocklist to avoid FP.

Requirements:
- Download feeds daily, clean/normalize (lower, strip, dedupe, drop invalid).
- Save to data/blocklist.txt + data/allowlist.txt
- Sinkhole: A -> config.SINKHOLE_IPV4, AAAA -> config.SINKHOLE_IPV6, TTL=SINKHOLE_TTL
"""
# TODO: imports dnslib.DNSRecord, urllib/requests, pathlib


class ThreatFeedUpdater:
    """TODO: implement fetch + clean + save."""

    FEEDS = {
        # TODO: fill real URLs: URLhaus, PhishTank, Malware Domain List
        "urlhaus": "https://urlhaus.abuse.ch/downloads/text/",
    }

    def update_daily(self) -> int:
        """Download all feeds, return total unique bad domains saved."""
        raise NotImplementedError

    def clean(self, raw_lines: list[str]) -> list[str]:
        """Lower, strip, drop comments/empties/invalid, dedupe."""
        raise NotImplementedError


class Allowlist:
    """Local override. If here -> ALLOW even if blocklisted."""

    def load(self, domains: list[str]) -> None:
        raise NotImplementedError

    def is_allowed(self, domain: str) -> bool:
        raise NotImplementedError


def build_sinkhole_reply(request, qtype: str = "A"):
    """TODO: given dnslib request, return reply with sinkhole IP.
    Hint: request.reply(), add .add_answer(RR(qname, QTYPE.A, rdata=A(SINKHOLE_IPV4), ttl=60))
    """
    raise NotImplementedError
