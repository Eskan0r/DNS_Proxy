"""Demo isolation, real query display, policy reload, and graceful reset."""
import socket
import threading
import time

from dnslib import A, DNSRecord, QTYPE, RR

from scripts import demo
from src import config
from src.proxy import DNSProxy
from src.upstream import UpstreamResolver


def prepare_root(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, 'ROOT', tmp_path)
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'top200.txt').write_text('google.com\npaypal.com\n')
    (data / 'blocklist.txt').write_text('production-blocked.com\n')
    (data / 'allowlist.txt').write_text('production-allowed.com\n')
    return data


def test_demo_policies_and_reset_preserve_production_files(tmp_path, monkeypatch):
    data = prepare_root(tmp_path, monkeypatch)
    snapshots = {path: path.read_bytes() for path in data.iterdir()}
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / 'dns_proxy.db').write_bytes(b'production database stays here')
    demo.update_policy('allowlist')
    demo.update_policy('blocklist')
    directory = demo.demo_dir()
    assert (directory / 'data/blocklist.txt').read_text() == 'example.com\n'
    assert (directory / 'data/allowlist.txt').read_text() == ''
    demo.update_policy('allowlist')
    assert (directory / 'data/allowlist.txt').read_text() == 'example.com\n'
    (directory / 'dns_proxy.db').write_bytes(b'demo-only database')
    demo.reset()
    assert not (directory / 'dns_proxy.db').exists()
    assert (directory / 'data/blocklist.txt').read_text() == ''
    assert (directory / 'data/allowlist.txt').read_text() == ''
    assert all(path.read_bytes() == contents for path, contents in snapshots.items())
    assert (logs / 'dns_proxy.db').read_bytes() == b'production database stays here'


def test_demo_queries_reload_charts_and_reset_while_running(tmp_path, monkeypatch, capsys):
    prepare_root(tmp_path, monkeypatch)
    # Register restoration of configuration changed by the demo entry point.
    monkeypatch.setattr(config, 'DATA_DIR', config.DATA_DIR)
    monkeypatch.setattr(config, 'DB_PATH', config.DB_PATH)
    monkeypatch.setattr(config, 'POLICY_RELOAD_INTERVAL_SEC', 0.01)
    instances = []
    def constructor(*args, **kwargs):
        instance = DNSProxy(*args, **kwargs)
        instances.append(instance)
        return instance
    monkeypatch.setattr('src.proxy.DNSProxy', constructor)
    def upstream(self, wire):
        question = DNSRecord.parse(wire)
        reply = question.reply()
        reply.add_answer(RR(question.q.qname, QTYPE.A, ttl=120, rdata=A('192.0.2.1')))
        return reply.pack()
    monkeypatch.setattr(UpstreamResolver, 'forward', upstream)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    failures = []
    def serve():
        try:
            demo.start(port)
        except Exception as exc:
            failures.append(exc)
    def wait_until(predicate):
        deadline = time.monotonic() + 4
        while not predicate() and not failures and time.monotonic() < deadline:
            time.sleep(0.01)
        assert predicate(), failures
    worker = threading.Thread(target=serve)
    worker.start()
    try:
        wait_until(lambda: demo.running_server() is not None)
        assert demo.query('google.com') == 0
        assert demo.query('google.com') == 0
        assert 'ALLOWED - CACHE HIT' in capsys.readouterr().out
        demo.update_policy('blocklist')
        wait_until(lambda: instances[0].blocklist.is_blocked('example.com')[0])
        assert demo.query('example.com') == 0
        assert 'BLOCKED' in capsys.readouterr().out
        demo.update_policy('allowlist')
        wait_until(lambda: instances[0].allowlist.is_allowed('example.com'))
        assert demo.query('example.com') == 0
        assert 'ALLOWED' in capsys.readouterr().out
        info = demo.server_info()
        assert not demo.control(dict(info, token='wrong-token'), 'stop')
        assert demo.running_server() is not None
        demo.display()
        assert 'CACHE' in capsys.readouterr().out
        demo.charts(open_images=False)
        assert (demo.demo_dir() / 'report/decisions.png').stat().st_size > 0
        demo.reset()
        worker.join(5)
        assert not worker.is_alive() and not failures
        assert demo.running_server() is None
        assert not (demo.demo_dir() / 'dns_proxy.db').exists()
        assert (tmp_path / 'data/blocklist.txt').read_text() == 'production-blocked.com\n'
    finally:
        if worker.is_alive() and instances:
            instances[0].shutdown()
            worker.join(5)
