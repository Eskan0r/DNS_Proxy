"""Artin's module tests: no live feeds, proxy, or peer implementations needed."""

import json
import os
import time

from dnslib import CLASS, DNSHeader, DNSQuestion, DNSRecord, OPCODE, QTYPE
import httpx
import pytest

from src import config, feeds
from src.feeds import Allowlist, FeedUpdateError, ThreatFeedUpdater, build_sinkhole_reply


@pytest.fixture(autouse=True)
def isolate_feed_environment(monkeypatch):
    for name in ("URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY", "URLHAUS_FEED_URL",
                 "PHISHTANK_FEED_URL", "MDL_FEED_URL", "DNS_PROXY_FEED_USER_AGENT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def updater_factory(tmp_path):
    clients = []

    def make(handler, sources=None, path=None):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        clients.append(client)
        return ThreatFeedUpdater(
            feeds=sources if sources is not None else {"test": "https://feeds.test/list"},
            blocklist_path=path or tmp_path / "blocklist.txt", client=client,
        )

    yield make
    for client in clients:
        client.close()


def test_clean_mixed_feeds_preserves_exact_hostnames():
    updater = ThreatFeedUpdater(feeds={})
    assert updater.clean([
        " # comment", "", " BAD.Example. ", "bad.example # note",
        "HTTPS://Sub.Bad.Example:443/payload?a=b#fragment",
        "0.0.0.0 BAD.example alias.example # hosts entry",
        ":: ipv6-host.example", "bücher.example", "xn--bcher-kva.example",
        "https://192.0.2.1/payload", "https://[2001:db8::1]/payload",
        "192.0.2.1", "localhost", "not a domain", "*.wild.example",
        "-bad.example", "bad-.example", "bad..example", "bad.example..",
        "bad_name.example", "ftp://bad.example/path", "example.123",
        "https://bad.example:nope/path", "https://[broken/path",
        "https://bad.example/path with spaces", "a" * 64 + ".example",
        "<html>bad.example</html>",
    ]) == ["alias.example", "bad.example", "ipv6-host.example",
           "sub.bad.example", "xn--bcher-kva.example"]


def test_urlhaus_csv_extracts_only_the_threat_url(updater_factory):
    body = ('# URLhaus recent export\n# id,dateadded,url,url_status,threat,tags,urlhaus_link\n'
            '1,2026-10-22,"https://Sub.Bad.Example/payload,a",online,malware,x,'
            'https://urlhaus.abuse.ch/url/1/\n'
            '2,2026-10-22,http://192.0.2.1/file,online,malware,x,'
            'https://urlhaus.abuse.ch/url/2/\n')
    updater = updater_factory(lambda request: httpx.Response(200, text=body),
                              {"urlhaus": "https://feeds.test/recent.csv"})
    assert updater.update_daily() == 1
    assert updater.blocklist_path.read_text() == "sub.bad.example\n"


def test_urlhaus_uncommented_csv_header(updater_factory):
    body = 'id,dateadded,url,url_status\n1,date,https://bad.example/path,online\n'
    updater = updater_factory(lambda request: httpx.Response(200, text=body),
                              {"urlhaus": "https://feeds.test/recent.csv"})
    assert updater.update_daily() == 1
    assert updater.blocklist_path.read_text() == "bad.example\n"


def test_urlhaus_url_text_can_contain_commas(updater_factory):
    updater = updater_factory(
        lambda request: httpx.Response(200, text="https://bad.example/path,a\n"),
        {"urlhaus": "https://feeds.test/list"},
    )
    assert updater.update_daily() == 1


@pytest.mark.parametrize("format", ["json", "csv"])
def test_phishtank_uses_verified_online_url_field_only(updater_factory, format):
    rows = [
        {"url": "https://phish.example/login", "verified": "yes", "online": "yes",
         "phish_detail_url": "https://phishtank.org/details"},
        {"url": "https://offline.example", "verified": "yes", "online": "no"},
        {"url": "https://unverified.example", "verified": "no", "online": "yes"},
    ]
    if format == "json":
        body = json.dumps(rows)
    else:
        body = ("url,verified,online,phish_detail_url\n"
                "https://phish.example/login,yes,yes,https://phishtank.org/details\n"
                "https://offline.example,yes,no,\n"
                "https://unverified.example,no,yes,\n")
    updater = updater_factory(lambda request: httpx.Response(200, text=body),
                              {"phishtank": "https://feeds.test/online-valid"})
    assert updater.update_daily() == 1
    assert updater.blocklist_path.read_text() == "phish.example\n"


def test_sources_merge_and_refresh_does_not_touch_allowlist(updater_factory, tmp_path):
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("# My exception\nbad.example\n")
    bodies = {"/urls": "https://bad.example/file\nhttps://z.example\n",
              "/hosts": "0.0.0.0 bad.example a.example\n"}
    updater = updater_factory(lambda request: httpx.Response(200, text=bodies[request.url.path]),
                              {"urlhaus": "https://feeds.test/urls",
                               "mdl": "https://feeds.test/hosts"})
    assert updater.update_daily() == 3
    assert updater.updated is True
    assert updater.blocklist_path.read_text() == "a.example\nbad.example\nz.example\n"
    assert allowlist.read_text() == "# My exception\nbad.example\n"
    # Keep threat evidence even when a local override currently permits it.
    assert Allowlist(allowlist).is_allowed("bad.example")


def test_daily_guard_survives_new_instances_and_force_bypasses_it(updater_factory):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, text="bad.example\n")

    updater = updater_factory(handler)
    assert updater.update_daily() == 1
    published_at = updater.blocklist_path.stat().st_mtime_ns
    second = updater_factory(handler, path=updater.blocklist_path)
    assert second.update_daily() == 1
    assert second.updated is False
    assert second.blocklist_path.stat().st_mtime_ns == published_at
    assert len(requests) == 1
    assert second.update_daily(force=True) == 1
    assert second.updated is True
    assert len(requests) == 2


@pytest.mark.parametrize("age", [config.FEED_UPDATE_INTERVAL_SEC, -3600])
def test_expired_or_future_timestamp_refreshes(updater_factory, age):
    updater = updater_factory(lambda request: httpx.Response(200, text="new.example\n"))
    updater.blocklist_path.write_text("old.example\n")
    timestamp = time.time() - age
    os.utime(updater.blocklist_path, (timestamp, timestamp))
    assert updater.update_daily() == 1
    assert updater.updated is True
    assert updater.blocklist_path.read_text() == "new.example\n"


def test_empty_existing_file_does_not_suppress_download(updater_factory):
    updater = updater_factory(lambda request: httpx.Response(200, text="new.example\n"))
    updater.blocklist_path.touch()
    assert updater.update_daily() == 1
    assert updater.updated is True


@pytest.mark.parametrize("failure", ["timeout", "status", "html", "empty", "oversize",
                                    "invalid-utf8", "redirect", "bad-json"])
def test_failed_updates_preserve_last_good_snapshot(
    updater_factory, monkeypatch, failure,
):
    def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("secret URL", request=request)
        if failure == "status":
            return httpx.Response(503)
        if failure == "html":
            return httpx.Response(200, text="<html>login</html>",
                                  headers={"content-type": "text/html"})
        if failure == "empty":
            return httpx.Response(200, text="# no domains\n")
        if failure == "oversize":
            return httpx.Response(200, text="a.example\nb.example\n")
        if failure == "invalid-utf8":
            return httpx.Response(200, content=b"\xff\xfe")
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://other.test"})
        return httpx.Response(200, text='[{"url":')

    if failure == "oversize":
        monkeypatch.setattr(config, "FEED_MAX_BYTES", 10)
    source = "phishtank" if failure == "bad-json" else "test"
    updater = updater_factory(handler, {source: "https://feeds.test/secret-key"})
    updater.blocklist_path.write_text("old.example\n")
    timestamp = updater.blocklist_path.stat().st_mtime_ns
    with pytest.raises(FeedUpdateError) as error:
        updater.update_daily(force=True)
    assert "secret" not in str(error.value)
    assert updater.blocklist_path.read_text() == "old.example\n"
    assert updater.blocklist_path.stat().st_mtime_ns == timestamp
    assert updater.updated is False


def test_partial_source_failure_does_not_publish_reduced_coverage(updater_factory):
    def handler(request):
        return (httpx.Response(200, text="new.example\n") if request.url.path == "/ok"
                else httpx.Response(403))

    updater = updater_factory(handler, {"first": "https://feeds.test/ok",
                                       "second": "https://feeds.test/fail"})
    updater.blocklist_path.write_text("old.example\n")
    with pytest.raises(FeedUpdateError, match="second"):
        updater.update_daily(force=True)
    assert updater.blocklist_path.read_text() == "old.example\n"


def test_atomic_publication_and_failed_replace_cleanup(updater_factory, monkeypatch):
    updater = updater_factory(lambda request: httpx.Response(200, text="new.example\n"))
    updater.blocklist_path.write_text("old.example\n")

    def fail_replace(source, target):
        assert source.read_text() == "new.example\n"
        assert target.read_text() == "old.example\n"
        assert source.parent == target.parent
        raise PermissionError("Cannot replace")

    monkeypatch.setattr(feeds.os, "replace", fail_replace)
    with pytest.raises(FeedUpdateError):
        updater.update_daily(force=True)
    assert updater.blocklist_path.read_text() == "old.example\n"
    assert list(updater.blocklist_path.parent.glob(".blocklist-*.tmp")) == []


def test_missing_configuration_is_an_explicit_error(tmp_path):
    updater = ThreatFeedUpdater(blocklist_path=tmp_path / "blocklist.txt")
    with pytest.raises(FeedUpdateError, match="No feeds configured"):
        updater.update_daily()
    assert not updater.blocklist_path.exists()


def test_environment_configuration_and_url_override(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "sample/key")
    monkeypatch.setenv("PHISHTANK_APP_KEY", "sample-key")
    updater = ThreatFeedUpdater()
    assert updater.feeds == {
        "urlhaus": "https://urlhaus-api.abuse.ch/v2/files/exports/sample%2Fkey/recent.csv",
        "phishtank": "https://data.phishtank.com/data/sample-key/online-valid.json",
    }
    monkeypatch.setenv("URLHAUS_FEED_URL", "https://feeds.test/hosts")
    monkeypatch.setenv("MDL_FEED_URL", "https://feeds.test/mdl")
    assert ThreatFeedUpdater().feeds["urlhaus"] == "https://feeds.test/hosts"
    assert ThreatFeedUpdater().feeds["mdl"] == "https://feeds.test/mdl"
    assert ThreatFeedUpdater(feeds={}).feeds == {}


def test_request_has_descriptive_user_agent_and_timeout(updater_factory, monkeypatch):
    monkeypatch.setenv("DNS_PROXY_FEED_USER_AGENT", "phishtank/class-project")

    def handler(request):
        assert request.headers["user-agent"] == "phishtank/class-project"
        assert request.extensions["timeout"]["read"] == config.FEED_TIMEOUT_SEC
        return httpx.Response(200, text="bad.example\n")

    assert updater_factory(handler).update_daily() == 1


@pytest.mark.parametrize("url", ["http://feeds.test/list", "https://[broken", "https://"])
def test_invalid_feed_configuration_fails_cleanly(updater_factory, url):
    updater = updater_factory(lambda request: pytest.fail("Must not download"), {"test": url})
    with pytest.raises(FeedUpdateError):
        updater.update_daily()


def test_allowlist_load_normalizes_exact_entries_and_replaces_snapshot(tmp_path):
    allow = Allowlist(tmp_path / "missing.txt")
    assert not allow.is_allowed("safe.example")
    allow.load([" SAFE.Example. ", "# comment", "bücher.example # explanation"])
    assert allow.is_allowed("Safe.Example.")
    assert allow.is_allowed("xn--bcher-kva.example")
    assert not allow.is_allowed("sub.safe.example")
    assert not allow.is_allowed("notsafe.example")
    assert not allow.is_allowed("safe.example.attacker.test")
    assert not allow.is_allowed("https://safe.example")
    allow.load(["replacement.example"])
    assert not allow.is_allowed("safe.example")
    assert allow.is_allowed("replacement.example")
    allow.load([])
    assert not allow.is_allowed("replacement.example")


@pytest.mark.parametrize("entry", ["*.example.com", "https://safe.example", "192.0.2.1",
                                   "bad..example", "not a domain"])
def test_invalid_allowlist_reload_keeps_previous_snapshot(tmp_path, entry):
    path = tmp_path / "allowlist.txt"
    path.write_text("safe.example\n", encoding="utf-8")
    allow = Allowlist(path)
    path.write_text(f"new.example\n{entry}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        allow.load_file()
    assert allow.is_allowed("safe.example")
    assert not allow.is_allowed("new.example")
    path.unlink()
    with pytest.raises(FileNotFoundError):
        allow.load_file()
    assert allow.is_allowed("safe.example")


def test_allowlist_default_path_and_bom(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    path = tmp_path / "allowlist.txt"
    path.write_text("\ufeffSAFE.Example. # comment\nsafe.example\n", encoding="utf-8")
    allow = Allowlist()
    assert allow.is_allowed("safe.example")
    assert allow.load_file() == 1


@pytest.mark.parametrize("qtype,ip", [("A", "0.0.0.0"), ("AAAA", "::")])
def test_sinkhole_dns_wire_roundtrip_preserves_question_and_id(qtype, ip):
    request = DNSRecord.question("Sub.Bad.Example.", qtype)
    request.header.id = 4389
    request.header.rd = 0
    request.header.ad = 1
    request.header.tc = 1
    original = request.pack()
    reply = DNSRecord.parse(build_sinkhole_reply(request).pack())
    assert reply.header.id == 4389
    assert reply.header.qr == 1
    assert reply.header.rcode == 0
    assert reply.header.rd == 0
    assert reply.header.ra == 1
    assert reply.header.aa == reply.header.ad == reply.header.tc == 0
    assert reply.q == request.q
    assert len(reply.rr) == 1
    assert reply.rr[0].rname == request.q.qname
    assert reply.rr[0].rtype == QTYPE.reverse[qtype]
    assert reply.rr[0].rclass == CLASS.IN
    assert reply.rr[0].ttl == config.SINKHOLE_TTL
    assert str(reply.rr[0].rdata) == ip
    assert request.pack() == original


def test_sinkhole_uses_configuration_and_accepts_matching_legacy_type(monkeypatch):
    monkeypatch.setattr(config, "SINKHOLE_IPV4", "192.0.2.9")
    monkeypatch.setattr(config, "SINKHOLE_TTL", 15)
    reply = build_sinkhole_reply(DNSRecord.question("bad.example"), "a")
    assert str(reply.rr[0].rdata) == "192.0.2.9"
    assert reply.rr[0].ttl == 15
    with pytest.raises(ValueError, match="must match"):
        build_sinkhole_reply(DNSRecord.question("bad.example", "AAAA"), "A")


@pytest.mark.parametrize("case", ["mx", "class", "empty", "multiple", "response", "opcode"])
def test_sinkhole_rejects_unsupported_messages(case):
    request = DNSRecord.question("bad.example", "MX" if case == "mx" else "A")
    if case == "class":
        request.q.qclass = CLASS.CH
    elif case == "empty":
        request = DNSRecord(DNSHeader())
    elif case == "multiple":
        request.add_question(DNSQuestion("second.example"))
    elif case == "response":
        request.header.qr = 1
    elif case == "opcode":
        request.header.opcode = OPCODE.UPDATE
    with pytest.raises(ValueError):
        build_sinkhole_reply(request)


def test_cli_reports_failure_without_creating_files(tmp_path, capsys):
    path = tmp_path / "blocklist.txt"
    assert feeds.main(["--output", str(path)]) == 1
    assert "No feeds configured" in capsys.readouterr().err
    assert not path.exists()


def test_cli_update_and_not_due_paths(updater_factory, monkeypatch, capsys):
    updater = updater_factory(lambda request: httpx.Response(200, text="bad.example\n"))
    monkeypatch.setattr(feeds, "ThreatFeedUpdater", lambda **kwargs: updater)
    assert feeds.main(["--force"]) == 0
    assert "Updated: 1 unique domains" in capsys.readouterr().out
    assert feeds.main([]) == 0
    assert "Already current: 1 unique domains" in capsys.readouterr().out
