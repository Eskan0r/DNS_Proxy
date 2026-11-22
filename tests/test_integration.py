"""Real component integration using loopback DNS and a mocked DoH transport."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import sqlite3
import threading
import time

import httpx
from dnslib import A, DNSRecord, QTYPE, RR

from src import config
from src.proxy import DNSProxy
from src.feeds import ThreatFeedUpdater


def test_default_components_udp_and_sqlite(tmp_path, monkeypatch):
    top = (config.DATA_DIR / "top200.txt").read_text()
    (tmp_path / "top200.txt").write_text(top)
    (tmp_path / "blocklist.txt").write_text("bad.com\n")
    db = tmp_path / "queries.db"
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", db)
    proxy = DNSProxy(port=0)
    upstream_calls = []
    def doh(request):
        query = DNSRecord.parse(request.content)
        upstream_calls.append(str(query.q.qname))
        reply = query.reply()
        reply.add_answer(RR(query.q.qname, QTYPE.A, ttl=120, rdata=A("192.0.2.1")))
        return httpx.Response(200, content=bytes(reply.pack()))
    proxy.upstream._client.close()
    proxy.upstream._client = httpx.Client(transport=httpx.MockTransport(doh))
    failures = []
    def serve():
        try:
            proxy.serve_forever()
        except Exception as exc:
            failures.append(exc)
    thread = threading.Thread(target=serve)
    thread.start()
    def ask(name):
        query = DNSRecord.question(name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query.pack(), ("127.0.0.1", proxy.port))
            reply = DNSRecord.parse(sock.recvfrom(65535)[0])
        assert reply.header.id == query.header.id
        return str(reply.rr[0].rdata)
    try:
        deadline = time.monotonic() + 3
        while proxy.port == 0 and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert proxy.port != 0, failures
        assert ask("google.com") == "192.0.2.1"
        assert ask("google.com") == "192.0.2.1"
        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(ask, ["a.bad.com", "gooogle.com"] * 4)) == ["0.0.0.0"] * 8
        proxy.allowlist.load(["a.bad.com"])
        assert ask("a.bad.com") == "192.0.2.1"
        assert len(upstream_calls) == 2
    finally:
        proxy.shutdown()
        thread.join(5)
    assert not thread.is_alive() and not failures
    with sqlite3.connect(db) as connection:
        decisions = dict(connection.execute("SELECT decision, COUNT(*) FROM queries GROUP BY decision"))
        assert decisions == {"allow": 2, "cache": 1, "block": 8}


def test_running_feed_reload_allowlist_and_risk_logging(tmp_path, monkeypatch):
    """Exercise the background worker through UDP, HTTP transports, and SQLite."""
    (tmp_path / 'top200.txt').write_text('google.com\n')
    monkeypatch.setattr(config, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(config, 'DB_PATH', tmp_path / 'queries.db')
    monkeypatch.setattr(config, 'POLICY_RELOAD_INTERVAL_SEC', 0.02)
    monkeypatch.setattr(config, 'NEW_DOMAIN_LEARNING_SEC', 0)
    proxy = DNSProxy(port=0)
    feed_client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text='feed-domain.com\n')))
    proxy._maintenance.updater = ThreatFeedUpdater(
        feeds={'test': 'https://feed.invalid/'}, blocklist_path=tmp_path / 'blocklist.txt',
        client=feed_client)
    def doh(request):
        query = DNSRecord.parse(request.content)
        reply = query.reply()
        reply.add_answer(RR(query.q.qname, QTYPE.A, ttl=5, rdata=A('192.0.2.1')))
        return httpx.Response(200, content=bytes(reply.pack()))
    proxy.upstream._client.close()
    proxy.upstream._client = httpx.Client(transport=httpx.MockTransport(doh))
    failures = []
    def serve():
        try:
            proxy.serve_forever()
        except Exception as exc:
            failures.append(exc)
    thread = threading.Thread(target=serve)
    def wait_until(predicate):
        deadline = time.monotonic() + 3
        while not predicate() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert predicate(), failures
    def ask():
        query = DNSRecord.question('feed-domain.com')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query.pack(), ('127.0.0.1', proxy.port))
            reply = DNSRecord.parse(sock.recvfrom(65535)[0])
        return str(reply.rr[0].rdata)
    thread.start()
    try:
        wait_until(lambda: proxy.port != 0 and proxy.blocklist.is_blocked('feed-domain.com')[0])
        assert ask() == '0.0.0.0'
        (tmp_path / 'allowlist.txt').write_text('feed-domain.com\n')
        wait_until(lambda: proxy.allowlist.is_allowed('feed-domain.com'))
        assert ask() == '192.0.2.1'
        (tmp_path / 'allowlist.txt').write_text('')
        wait_until(lambda: not proxy.allowlist.is_allowed('feed-domain.com'))
        assert ask() == '0.0.0.0'
        (tmp_path / 'blocklist.txt').write_text('different-domain.com\n')
        wait_until(lambda: not proxy.blocklist.is_blocked('feed-domain.com')[0])
        assert ask() == '192.0.2.1'
    finally:
        proxy.shutdown()
        thread.join(5)
        feed_client.close()
    assert not thread.is_alive() and not failures
    assert not proxy._maintenance._thread.is_alive()
    with sqlite3.connect(config.DB_PATH) as connection:
        rows = connection.execute('SELECT decision, risk_signals, upstream_min_ttl FROM queries').fetchall()
    assert [row[0] for row in rows] == ['block', 'allow', 'block', 'allow']
    assert rows[1][1:] == ('["newly-observed", "short-ttl"]', 5)
    assert rows[2][1:] == ('["newly-observed"]', None)
