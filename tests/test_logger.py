"""Logger schema, reporting helpers, and safe insertion failures."""
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
