"""Logger schema, reporting helpers, and safe insertion failures."""
import json
import sqlite3

from src import config
from src.logger import QueryLogger


def test_logger_helpers(tmp_path):
    logger = QueryLogger(str(tmp_path / 'nested' / 'queries.db'))
    assert logger.get_stats()['total'] == 0
    for decision, domain in [('block', 'bad.com'), ('allow', 'good.com'),
                             ('block', 'bad.com'), ('cache', 'cached.com'), ('error', 'failed.com')]:
        logger.log('127.0.0.1', domain, 'A', decision, 'test', 1.5)
    assert logger.get_stats() == {'total': 5, 'blocked': 2, 'allowed': 1, 'cache_hits': 1}
    assert logger.get_top_blocked() == [('bad.com', 2)]
    assert [row[2] for row in logger.get_recent(2)] == ['failed.com', 'cached.com']
    assert logger.get_recent(-1) == []
    logger.close()
    # The logger's contract is to contain insertion errors.
    logger.log('127.0.0.1', 'closed.com', 'A', 'error', 'test')


def test_persistent_first_seen_learning_and_signal_expiry(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr('src.logger.time.time', lambda: now[0])
    monkeypatch.setattr(config, 'NEW_DOMAIN_LEARNING_SEC', 10)
    monkeypatch.setattr(config, 'NEW_DOMAIN_WINDOW_SEC', 20)
    path = str(tmp_path / 'queries.db')
    logger = QueryLogger(path)

    def log(name, **kwargs):
        logger.log('127.0.0.1', name, 'A', 'allow', 'upstream', **kwargs)
        row = logger.connection.execute(
            'SELECT risk_signals, upstream_min_ttl FROM queries ORDER BY rowid DESC LIMIT 1'
        ).fetchone()
        return json.loads(row[0]), row[1]

    assert log('Known.COM.', upstream_min_ttl=0) == (['short-ttl'], 0)
    now[0] = 111
    assert log('new.com', upstream_min_ttl=60) == (['newly-observed'], 60)
    logger.close()
    now[0] = 121
    logger = QueryLogger(path)
    assert log('known.com') == ([], None)
    assert log('new.com', upstream_min_ttl=59) == (['newly-observed', 'short-ttl'], 59)
    first_seen = dict(logger.connection.execute('SELECT * FROM domain_first_seen'))
    assert first_seen == {'known.com': 100, 'new.com': 111}
    now[0] = 131
    assert log('new.com') == ([], None)
    logger.close()


def test_migrates_existing_database_without_losing_history(tmp_path):
    path = str(tmp_path / 'legacy.db')
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE queries (ts TEXT, client_ip TEXT, domain TEXT, '
                           'qtype TEXT, decision TEXT, category TEXT, latency_ms REAL)')
        connection.execute("INSERT INTO queries VALUES ('2026-01-01T00:00:00+00:00', "
                           "'127.0.0.1', 'KNOWN.com.', 'A', 'allow', 'upstream', 1.5)")
    logger = QueryLogger(path)
    assert logger.get_stats()['total'] == 1
    assert logger.connection.execute('SELECT risk_signals FROM queries').fetchone() == ('[]',)
    assert logger.connection.execute('SELECT domain FROM domain_first_seen').fetchone() == ('known.com',)
    logger.log('127.0.0.1', 'new.com', 'AAAA', 'cache', 'cache-hit')
    assert logger.get_stats()['total'] == 2
    logger.close()
    logger = QueryLogger(path)
    assert logger.get_stats()['total'] == 2
    assert logger.connection.execute('SELECT COUNT(*) FROM observer_state').fetchone() == (1,)
    logger.close()
