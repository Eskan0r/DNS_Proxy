"""Artin's threat-feed updater, exact allowlist, and DNS sinkhole responder.

Run a due update with ``python -m src.feeds``. This module does not start a
scheduler, perform blocklist lookups, or wire itself into the proxy.
"""

import argparse
from contextlib import nullcontext
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from threading import Lock
import time
from urllib.parse import quote, urlsplit

from dnslib import A, AAAA, CLASS, DNSRecord, OPCODE, QTYPE, RCODE, RR
import httpx

from . import config


class FeedUpdateError(RuntimeError):
    """A refresh failed; an existing published blocklist is left intact."""


def _hostname(raw: str) -> str | None:
    """Validate a feed hostname, including IDNA; never accept URLs or IPs.

    Feed validation is deliberately self-contained: the shared utils helpers
    are currently stubs and do not provide this stricter validation contract.
    """
    name = raw.strip().removesuffix(".")
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in labels):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def _domains_from_line(raw: str) -> list[str]:
    line = raw.strip().lstrip("\ufeff")
    if not line or line.startswith("#"):
        return []
    if "://" in line:
        try:
            url = urlsplit(line)
            if (url.scheme.lower() not in {"http", "https"} or not url.hostname
                    or any(char.isspace() for char in line)):
                return []
            # Accessing port also validates a malformed/non-numeric port.
            url.port
            name = _hostname(url.hostname)
        except ValueError:
            return []
        return [name] if name else []

    fields = line.split("#", 1)[0].split()
    if len(fields) > 1:
        try:
            ipaddress.ip_address(fields[0])
        except ValueError:
            return []
        fields = fields[1:]  # hosts-file records may contain several aliases
    return [name for field in fields if (name := _hostname(field))]


class ThreatFeedUpdater:
    """Publish a complete, validated feed union at most once per 24 hours.

    Pass ``feeds={source: https_url}`` for explicit configuration. Otherwise,
    sources are enabled only when their environment settings are present.
    Every configured source must succeed and contain at least one valid domain.
    """

    FEEDS = {
        "urlhaus": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "phishtank": "https://data.phishtank.com/data/{key}/online-valid.json",
    }

    def __init__(self, feeds: dict[str, str] | None = None,
                 blocklist_path: str | Path | None = None, *,
                 client: httpx.Client | None = None):
        self.feeds = dict(feeds) if feeds is not None else self._configured_feeds()
        self.blocklist_path = (Path(blocklist_path) if blocklist_path is not None
                               else config.DATA_DIR / "blocklist.txt")
        self._client = client
        self._lock = Lock()
        self.updated = False

    @classmethod
    def _configured_feeds(cls) -> dict[str, str]:
        feeds = {}
        for source, key_env in (("urlhaus", "URLHAUS_AUTH_KEY"),
                                ("phishtank", "PHISHTANK_APP_KEY")):
            if url := os.getenv(f"{source.upper()}_FEED_URL"):
                feeds[source] = url
            elif key := os.getenv(key_env):
                feeds[source] = cls.FEEDS[source].format(key=quote(key, safe=""))
        # MDL has no verified current endpoint. Enable only an explicitly set URL.
        if url := os.getenv("MDL_FEED_URL"):
            feeds["mdl"] = url
        return feeds

    def clean(self, raw_lines: list[str]) -> list[str]:
        """Extract valid exact hostnames from domain, URL, or hosts-file lines."""
        return sorted({domain for line in raw_lines
                       for domain in _domains_from_line(line)})

    def _parse_feed(self, source: str, text: str) -> list[str]:
        if text.lstrip().startswith("<"):
            raise ValueError("HTML/XML is not a supported feed")
        if source == "phishtank":
            if text.lstrip().startswith("["):
                rows = json.loads(text)
            else:
                reader = csv.DictReader(io.StringIO(text))
                if not {"url", "verified", "online"}.issubset(reader.fieldnames or []):
                    raise ValueError("Unexpected PhishTank schema")
                rows = list(reader)
            urls = []
            for row in rows:
                if (not isinstance(row, dict) or not isinstance(row.get("url"), str)
                        or "verified" not in row or "online" not in row):
                    raise ValueError("Unexpected PhishTank record")
                if row["verified"] in ("yes", True) and row["online"] in ("yes", True):
                    urls.append(row["url"])
            return self.clean(urls)

        lines = [line for line in text.splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if (source == "urlhaus" and lines and "," in lines[0]
                and not lines[0].lower().startswith(("http://", "https://"))):
            rows = list(csv.reader(lines, strict=True))
            header = [field.strip().lower() for field in rows[0]]
            index = header.index("url") if "url" in header else 2
            if "url" in header:
                rows = rows[1:]
            # URLhaus's commented-header CSV has its malicious URL at index 2.
            # Never ingest metadata URLs such as the URLhaus detail-page link.
            urls = [row[index] for row in rows if len(row) > index
                    and row[index].lower().startswith(("http://", "https://"))]
            return self.clean(urls)
        return self.clean(lines)

    def _download(self, client: httpx.Client, source: str, url: str) -> list[str]:
        headers = {"User-Agent": os.getenv("DNS_PROXY_FEED_USER_AGENT",
                                          config.FEED_USER_AGENT)}
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() != "https" or not parsed.hostname:
                raise ValueError("A complete HTTPS feed URL is required")
            parsed.port
            # Redirects are rejected: configure the final HTTPS download URL.
            with client.stream("GET", url, headers=headers,
                               timeout=config.FEED_TIMEOUT_SEC,
                               follow_redirects=False) as response:
                response.raise_for_status()
                if "html" in response.headers.get("content-type", "").lower():
                    raise ValueError("Feed endpoint returned HTML")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > config.FEED_MAX_BYTES:
                        raise ValueError("Feed exceeds size limit")
            domains = self._parse_feed(source, body.decode("utf-8-sig"))
            if not domains:
                raise ValueError("Feed contains no valid domains")
            return domains
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, csv.Error) as exc:
            # Auth keys may be embedded in request URLs. Do not expose URLs or
            # HTTP exception text in CLI output or a proxy's failure message.
            raise FeedUpdateError(
                f"{source}: download/validation failed ({type(exc).__name__})"
            ) from None

    def _publish(self, domains: list[str]) -> None:
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.blocklist_path.parent,
                prefix=".blocklist-", suffix=".tmp", delete=False,
            ) as output:
                temp_path = Path(output.name)
                output.write("\n".join(domains) + "\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, self.blocklist_path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def update_daily(self, *, force: bool = False) -> int:
        """Return the published domain count; raise FeedUpdateError on failure.

        A nonempty blocklist's modification time is the persisted success time.
        ``updated`` is true only when this call publishes a new snapshot. A
        forced call bypasses the age check. Scheduling remains the caller's job.
        """
        with self._lock:
            self.updated = False
            if not self.feeds:
                raise FeedUpdateError("No feeds configured; set feed URLs or API keys")
            try:
                if not force and self.blocklist_path.exists():
                    age = time.time() - self.blocklist_path.stat().st_mtime
                    existing = self.clean(self.blocklist_path.read_text(
                        encoding="utf-8").splitlines())
                    if existing and 0 <= age < config.FEED_UPDATE_INTERVAL_SEC:
                        return len(existing)
                context = (nullcontext(self._client) if self._client is not None
                           else httpx.Client())
                domains = set()
                with context as client:
                    for source, url in self.feeds.items():
                        domains.update(self._download(client, source, url))
                self._publish(sorted(domains))
            except (OSError, UnicodeError) as exc:
                raise FeedUpdateError(
                    f"Could not read/publish blocklist ({type(exc).__name__})"
                ) from None
            self.updated = True
            return len(domains)


class Allowlist:
    """User-maintained exact-hostname overrides, independent of feed refreshes.

    A missing file starts empty. Explicit reloads must succeed before replacing
    the in-memory snapshot. A parent entry never implicitly allows subdomains.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else config.DATA_DIR / "allowlist.txt"
        self._domains: frozenset[str] = frozenset()
        if self.path.exists():
            self.load_file()

    def load(self, domains: list[str]) -> None:
        """Replace entries; reject invalid non-comment entries without changes."""
        normalized = set()
        for raw in domains:
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            domain = _hostname(entry)
            if domain is None:
                raise ValueError("Allowlist entries must be valid hostnames, not URLs/IPs")
            normalized.add(domain)
        self._domains = frozenset(normalized)

    def load_file(self, path: str | Path | None = None) -> int:
        """Reload a UTF-8 file; failures retain the current in-memory entries."""
        target = Path(path) if path is not None else self.path
        self.load(target.read_text(encoding="utf-8-sig").splitlines())
        self.path = target
        return len(self._domains)

    def is_allowed(self, domain: str) -> bool:
        return _hostname(domain) in self._domains


def build_sinkhole_reply(request: DNSRecord, qtype: str | None = None) -> DNSRecord:
    """Build an IN A/AAAA reply; callers pack it for transmission.

    Derive the type from the question. An optional legacy string argument must
    agree with it. Other types/classes, responses, and multi-question messages
    are rejected rather than receiving a mismatched answer.
    """
    if (request.header.qr or request.header.opcode != OPCODE.QUERY
            or len(request.questions) != 1):
        raise ValueError("Sinkhole requires a single-question DNS query")
    question = request.q
    if question.qclass != CLASS.IN or question.qtype not in (QTYPE.A, QTYPE.AAAA):
        raise ValueError("Sinkhole supports only IN A and AAAA queries")
    if qtype is not None and qtype.upper() != QTYPE[question.qtype]:
        raise ValueError("Explicit qtype must match the DNS question")
    reply = request.reply(aa=0, ra=1)
    reply.header.ad = 0  # A local policy answer is not DNSSEC-authenticated.
    reply.header.tc = 0
    reply.header.rcode = RCODE.NOERROR
    data = (A(config.SINKHOLE_IPV4) if question.qtype == QTYPE.A
            else AAAA(config.SINKHOLE_IPV6))
    reply.add_answer(RR(question.qname, question.qtype, rclass=CLASS.IN,
                        ttl=config.SINKHOLE_TTL, rdata=data))
    return reply


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh DNS threat feeds if due")
    parser.add_argument("--force", action="store_true", help="Ignore the 24-hour age check")
    parser.add_argument("--output", type=Path, help="Override data/blocklist.txt")
    args = parser.parse_args(argv)
    updater = ThreatFeedUpdater(blocklist_path=args.output)
    try:
        count = updater.update_daily(force=args.force)
    except FeedUpdateError as exc:
        print(f"Feed update failed: {exc}", file=sys.stderr)
        return 1
    action = "Updated" if updater.updated else "Already current"
    print(f"{action}: {count} unique domains in {updater.blocklist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
