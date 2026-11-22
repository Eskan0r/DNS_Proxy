"""Core pipeline and real UDP tests, independent of unmerged components."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import socket
import sqlite3
import threading
import time
from unittest.mock import Mock

from dnslib import A, AAAA, CNAME, DNSRecord, EDNS0, QTYPE, RCODE, RR, TXT
import pytest

import main
from src import config
from src.proxy import DNSProxy, _SerialLogger
from src.utils import is_subdomain, normalize_domain, split_labels


@pytest.fixture
def parts():
    def forward(data):
        request = DNSRecord.parse(data)
        reply = request.reply()
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=120, rdata=A("192.0.2.1")))
        elif request.q.qtype == QTYPE.AAAA:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, ttl=120, rdata=AAAA("2001:db8::1")))
        return reply.pack()
    return dict(
        cache=Mock(get=Mock(return_value=None)),
        allowlist=Mock(is_allowed=Mock(return_value=False)),
        blocklist=Mock(is_blocked=Mock(return_value=(False, None))),
        typosquat=Mock(is_lookalike=Mock(return_value=(False, None, None))),
        dga=Mock(score=Mock(return_value=(False, 1.0, "clean"))),
        upstream=Mock(forward=Mock(side_effect=forward)),
        logger=Mock(),
    )


@pytest.fixture
def proxy(parts):
    instance = DNSProxy(port=0, **parts)
    yield instance
    instance.close()


def ask(proxy, qtype="A", domain="Example.COM"):
    query = DNSRecord.question(domain, qtype)
    return query, DNSRecord.parse(proxy.handle_query(query.pack(), ("127.0.0.1", 12345)))


def test_utils():
    assert normalize_domain(" A.Bad.COM. ") == "a.bad.com"
    assert is_subdomain(" A.BAD.COM. ", "Bad.com")
    assert is_subdomain("bad.com", "bad.com")
    assert not is_subdomain("notbad.com", "bad.com")
    assert not is_subdomain("bad.com", "")
    assert split_labels(" A.B.COM. ") == ["a", "b", "com"]
    assert split_labels(".") == []


@pytest.mark.parametrize("qtype,ip", [("A", "0.0.0.0"), ("AAAA", "::")])
def test_sinkhole_before_cache(proxy, parts, qtype, ip):
    parts["blocklist"].is_blocked.return_value = (True, "example.com")
    query, reply = ask(proxy, qtype)
    assert reply.header.id == query.header.id
    assert str(reply.rr[0].rdata) == ip
    assert reply.rr[0].ttl == config.SINKHOLE_TTL
    assert reply.header.ad == 0
    parts["cache"].get.assert_not_called()
    parts["upstream"].forward.assert_not_called()
    assert parts["logger"].log.call_args.kwargs["category"] == "blocklist:example.com"


@pytest.mark.parametrize("layer", ["typosquat", "dga"])
def test_heuristic_blocks(proxy, parts, layer):
    if layer == "typosquat":
        parts[layer].is_lookalike.return_value = (True, "paypal.com", 1)
    else:
        parts[layer].score.return_value = (True, 4.2, "random")
    assert str(ask(proxy)[1].rr[0].rdata) == "0.0.0.0"
    assert parts["logger"].log.call_args.kwargs["category"].startswith(layer + ":")


def test_allowlist_overrides_all_detectors(proxy, parts):
    parts["allowlist"].is_allowed.return_value = True
    assert str(ask(proxy)[1].rr[0].rdata) == "192.0.2.1"
    parts["blocklist"].is_blocked.assert_not_called()
    parts["typosquat"].is_lookalike.assert_not_called()
    parts["dga"].score.assert_not_called()


@pytest.mark.parametrize("qtype,ip", [("A", "192.0.2.2"), ("AAAA", "2001:db8::2")])
def test_cache_hit_remaining_ttl(proxy, parts, qtype, ip):
    parts["cache"].get.return_value = SimpleNamespace(answers=[ip], remaining_ttl=lambda: 42)
    query, reply = ask(proxy, qtype)
    assert str(reply.rr[0].rdata) == ip and reply.rr[0].ttl == 42
    assert reply.header.id == query.header.id
    parts["upstream"].forward.assert_not_called()
    assert parts["logger"].log.call_args.kwargs["decision"] == "cache"


def test_expired_hit_goes_upstream(proxy, parts):
    parts["cache"].get.return_value = SimpleNamespace(answers=["192.0.2.2"], remaining_ttl=lambda: 0)
    assert str(ask(proxy)[1].rr[0].rdata) == "192.0.2.1"
    parts["cache"].set.assert_called_once_with("example.com", "A", ["192.0.2.1"], 120)


@pytest.mark.parametrize("kind", ["nxdomain", "nodata", "cname", "txt", "short", "truncated", "authenticated"])
def test_raw_upstream_semantics(proxy, parts, kind):
    query = DNSRecord.question("example.com", "TXT" if kind == "txt" else "A")
    reply = query.reply()
    if kind == "nxdomain":
        reply.header.rcode = RCODE.NXDOMAIN
    elif kind == "cname":
        reply.add_answer(RR("example.com", QTYPE.CNAME, ttl=60, rdata=CNAME("alias.example")))
        reply.add_answer(RR("alias.example", QTYPE.A, ttl=60, rdata=A("192.0.2.3")))
    elif kind == "txt":
        reply.add_answer(RR("example.com", QTYPE.TXT, ttl=60, rdata=TXT("hello")))
    elif kind in ("short", "truncated", "authenticated"):
        reply.add_answer(RR("example.com", QTYPE.A, ttl=0 if kind == "short" else 120,
                            rdata=A("192.0.2.1")))
        reply.header.tc = int(kind == "truncated")
        reply.header.ad = int(kind == "authenticated")
    wire = reply.pack()
    parts["upstream"].forward.side_effect = lambda _: wire
    assert proxy.handle_query(query.pack(), ("127.0.0.1", 12345)) == wire
    parts["cache"].set.assert_not_called()
    if kind == "txt":
        parts["blocklist"].is_blocked.assert_not_called()


def test_edns_bypasses_address_cache(proxy, parts):
    query = DNSRecord.question("example.com")
    query.add_ar(EDNS0(flags="do", udp_len=1232))
    proxy.handle_query(query.pack(), ("127.0.0.1", 1))
    parts["cache"].get.assert_not_called()
    parts["cache"].set.assert_not_called()
    parts["upstream"].forward.assert_called_once_with(query.pack())


def test_original_ttl_logged_only_for_complete_upstream_answers(proxy, parts):
    ask(proxy)
    assert parts['logger'].log.call_args.kwargs['upstream_min_ttl'] == 120
    parts['cache'].get.return_value = SimpleNamespace(
        answers=['192.0.2.1'], remaining_ttl=lambda: 5)
    ask(proxy)
    assert 'upstream_min_ttl' not in parts['logger'].log.call_args.kwargs
    parts['cache'].get.return_value = None
    def truncated(wire):
        reply = DNSRecord.parse(wire).reply()
        reply.header.tc = 1
        reply.add_answer(RR(reply.q.qname, QTYPE.A, ttl=0, rdata=A('192.0.2.1')))
        return reply.pack()
    parts['upstream'].forward.side_effect = truncated
    ask(proxy)
    assert 'upstream_min_ttl' not in parts['logger'].log.call_args.kwargs


@pytest.mark.parametrize("failure", ["timeout", "wrong-id", "wrong-question", "invalid"])
def test_upstream_errors_servfail(proxy, parts, failure):
    query = DNSRecord.question("example.com")
    if failure == "timeout":
        parts["upstream"].forward.side_effect = TimeoutError("timeout")
    else:
        reply = query.reply()
        if failure == "wrong-id":
            reply.header.id ^= 1
        if failure == "wrong-question":
            reply.questions = DNSRecord.question("other.com").questions
        wire = b"bad" if failure == "invalid" else reply.pack()
        parts["upstream"].forward.side_effect = lambda _: wire
    reply = DNSRecord.parse(proxy.handle_query(query.pack(), ("127.0.0.1", 1)))
    assert reply.header.rcode == RCODE.SERVFAIL and reply.header.id == query.header.id
    assert parts["logger"].log.call_args.kwargs["decision"] == "error"


def test_malformed_and_unsupported(proxy, parts):
    reply = DNSRecord.parse(proxy.handle_query(b"\x12\x34bad", ("127.0.0.1", 1)))
    assert reply.header.rcode == RCODE.FORMERR and reply.header.id == 0x1234
    query = DNSRecord.question("example.com")
    query.add_question(DNSRecord.question("other.com").q)
    assert DNSRecord.parse(proxy.handle_query(query.pack(), ("127.0.0.1", 1))).header.rcode == RCODE.FORMERR
    query = DNSRecord.question("example.com")
    query.header.opcode = 2
    assert DNSRecord.parse(proxy.handle_query(query.pack(), ("127.0.0.1", 1))).header.rcode == RCODE.NOTIMP
    query.header.opcode = 0
    query.q.qclass = 3
    assert DNSRecord.parse(proxy.handle_query(query.pack(), ("127.0.0.1", 1))).header.rcode == RCODE.REFUSED
    assert proxy.handle_query(query.reply().pack(), ("127.0.0.1", 1)) == b""
    parts["upstream"].forward.assert_not_called()


def test_logging_failure_does_not_break_reply(proxy, parts):
    parts["logger"].log.side_effect = RuntimeError("database unavailable")
    assert ask(proxy)[1].header.rcode == RCODE.NOERROR


def test_policy_change_overrides_previous_cache(proxy, parts):
    parts["cache"].get.return_value = SimpleNamespace(
        answers=["192.0.2.2"], remaining_ttl=lambda: 100)
    assert str(ask(proxy)[1].rr[0].rdata) == "192.0.2.2"
    parts["blocklist"].is_blocked.return_value = (True, "example.com")
    assert str(ask(proxy)[1].rr[0].rdata) == "0.0.0.0"
    assert parts["cache"].get.call_count == 1


def test_component_failure_never_bypasses_policy(proxy, parts):
    parts["dga"].score.side_effect = RuntimeError("broken detector")
    assert ask(proxy)[1].header.rcode == RCODE.SERVFAIL
    parts["upstream"].forward.assert_not_called()
    assert parts["logger"].log.call_args.kwargs["category"] == "dga"


def test_udp_response_size_limits():
    query = DNSRecord.question("example.com", "TXT")
    reply = query.reply()
    for _ in range(4):
        reply.add_answer(RR("example.com", QTYPE.TXT, ttl=60, rdata=TXT("x" * 200)))
    wire = reply.pack()
    assert len(wire) > 512
    truncated = DNSRecord.parse(DNSProxy._udp_reply(query.pack(), wire))
    assert truncated.header.tc == 1 and not truncated.rr
    assert truncated.questions == query.questions
    query.add_ar(EDNS0(udp_len=1232))
    assert DNSProxy._udp_reply(query.pack(), wire) == wire


def test_udp_concurrency_and_shutdown(proxy, parts):
    errors = []
    def serve():
        try:
            proxy.serve_forever()
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        deadline = time.monotonic() + 3
        while proxy.port == 0 and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert proxy.port != 0, errors
        def exchange(index):
            query = DNSRecord.question(f"site{index}.example")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(query.pack(), ("127.0.0.1", proxy.port))
                reply = DNSRecord.parse(sock.recvfrom(65535)[0])
            assert reply.header.id == query.header.id
            assert str(reply.rr[0].rdata) == "192.0.2.1"
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(24)))
    finally:
        proxy.shutdown()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert parts["logger"].log.call_count == 24
    # Caller owns injected objects, even when they expose a close method.
    parts["upstream"].close.assert_not_called()


def test_serial_logger_sqlite_thread_ownership(monkeypatch):
    import src.logger
    thread_ids = []
    class SQLiteLogger:
        def __init__(self, path):
            self.connection = sqlite3.connect(":memory:")
            self.connection.execute("CREATE TABLE events (domain TEXT)")
            thread_ids.append(threading.get_ident())
        def log(self, **event):
            self.connection.execute("INSERT INTO events VALUES (?)", (event["domain"],))
            thread_ids.append(threading.get_ident())
        def close(self):
            assert self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 24
            thread_ids.append(threading.get_ident())
            self.connection.close()
    monkeypatch.setattr(src.logger, "QueryLogger", SQLiteLogger)
    logger = _SerialLogger()
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: logger.log(domain=str(i)), range(24)))
    finally:
        logger.close()
    assert len(set(thread_ids)) == 1


def test_cli(monkeypatch):
    engine = Mock()
    constructor = Mock(return_value=engine)
    monkeypatch.setattr(main, "DNSProxy", constructor)
    assert main.main(["--ip", "0.0.0.0", "--port", "5354"]) == 0
    constructor.assert_called_once_with("0.0.0.0", 5354)
    engine.serve_forever.assert_called_once()
    with pytest.raises(SystemExit) as exc:
        main.main(["--port", "0"])
    assert exc.value.code == 2
    constructor.side_effect = RuntimeError("component stub")
    assert main.main([]) == 1
