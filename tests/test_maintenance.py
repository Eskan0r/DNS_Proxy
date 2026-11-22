"""Running policy replacement, scheduling, failure retention, and shutdown."""
from types import SimpleNamespace
from unittest.mock import Mock

from src import config
from src.blocklist import BlocklistChecker
from src.feeds import Allowlist
from src.maintenance import PolicyMaintenance


def make_maintenance(tmp_path, monkeypatch, updater=None):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    proxy = SimpleNamespace(blocklist=BlocklistChecker(["old.com"]),
                            allowlist=Allowlist(tmp_path / "allowlist.txt"))
    updater = updater or SimpleNamespace(feeds={})
    return proxy, PolicyMaintenance(proxy, updater=updater)


def test_replace_reload_remove_and_empty(tmp_path, monkeypatch):
    proxy, worker = make_maintenance(tmp_path, monkeypatch)
    path = tmp_path / "blocklist.txt"
    path.write_text("new-domain.com\n")
    worker.tick()
    assert proxy.blocklist.is_blocked("new-domain.com")[0]
    assert not proxy.blocklist.is_blocked("old.com")[0]
    snapshot = proxy.blocklist
    worker.tick()
    assert proxy.blocklist is snapshot
    path.write_text('https://malformed-policy.com/path\n')
    worker.tick()
    assert proxy.blocklist is snapshot
    path.write_bytes(b'\xff')
    worker.tick()
    assert proxy.blocklist is snapshot
    path.unlink()
    worker.tick()
    assert proxy.blocklist is snapshot
    path.write_text("")
    worker.tick()
    assert len(proxy.blocklist) == 0


def test_allowlist_invalid_or_unreadable_retains_snapshot(tmp_path, monkeypatch):
    proxy, worker = make_maintenance(tmp_path, monkeypatch)
    path = tmp_path / "allowlist.txt"
    path.write_text("good.com\n")
    worker.tick()
    assert proxy.allowlist.is_allowed("good.com")
    snapshot = proxy.allowlist
    path.write_text("https://invalid.example/path\n")
    worker.tick()
    assert proxy.allowlist is snapshot
    path.write_bytes(b"\xff")
    worker.tick()
    assert proxy.allowlist is snapshot
    path.write_text("other-good.com\n")
    worker.tick()
    assert proxy.allowlist.is_allowed("other-good.com")
    assert not proxy.allowlist.is_allowed("good.com")


def test_feed_schedule_reload_and_retry(tmp_path, monkeypatch, caplog):
    now = [100.0]
    monkeypatch.setattr("src.maintenance.time.monotonic", lambda: now[0])
    path = tmp_path / "blocklist.txt"
    updater = Mock(feeds={"test": "https://feed.invalid/"}, blocklist_path=path)
    updater.update_daily.side_effect = lambda: path.write_text("feed-domain.com\n")
    proxy, worker = make_maintenance(tmp_path, monkeypatch, updater)
    worker.tick()
    assert proxy.blocklist.is_blocked("feed-domain.com")[0]
    worker.tick()
    assert updater.update_daily.call_count == 1
    now[0] += config.FEED_UPDATE_INTERVAL_SEC + 1
    updater.update_daily.side_effect = RuntimeError("secret feed key")
    worker.tick()
    assert proxy.blocklist.is_blocked("feed-domain.com")[0]
    assert updater.update_daily.call_count == 2
    worker.tick()
    assert updater.update_daily.call_count == 2
    now[0] += config.FEED_RETRY_INTERVAL_SEC
    worker.tick()
    assert updater.update_daily.call_count == 3
    assert "secret feed key" not in caplog.text


def test_worker_stops_and_does_not_replace_injected_components(tmp_path, monkeypatch):
    proxy, _ = make_maintenance(tmp_path, monkeypatch)
    original = proxy.blocklist, proxy.allowlist
    worker = PolicyMaintenance(proxy, blocklist=False, allowlist=False)
    worker.start()
    worker.close()
    assert not worker._thread.is_alive()
    assert (proxy.blocklist, proxy.allowlist) == original
