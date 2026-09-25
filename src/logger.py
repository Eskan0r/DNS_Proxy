"""SQLite logger, Vinh Nguyen

Contract for proxy.py:
    logger = QueryLogger("logs/dns_proxy.db")
    logger.log(client_ip="127.0.0.1", domain="evil.com", qtype="A",
               decision="block", category="blocklist:bad.com", latency_ms=1.2)

Schema (create in init):
    queries(ts TEXT, client_ip TEXT, domain TEXT, qtype TEXT,
            decision TEXT, category TEXT, latency_ms REAL)
    decision in ('allow','block','cache','error'), category like 'blocklist','typosquat','dga','upstream','cache-hit'

Helpers for Kareem's report:
    get_top_blocked(limit=10), get_stats() -> {total, blocked, allowed, fp?}, get_recent(n)
"""
import sqlite3


class QueryLogger:
    """TODO: implement init(schema) + log() + query helpers."""

    def __init__(self, db_path: str = "logs/dns_proxy.db"):
        # TODO: connect, create table if not exists, ensure logs/ exists
        raise NotImplementedError

    def log(self, client_ip: str, domain: str, qtype: str,
            decision: str, category: str, latency_ms: float = 0.0) -> None:
        """Insert one row. Must never crash proxy (try/except internally)."""
        raise NotImplementedError

    def get_top_blocked(self, limit: int = 10) -> list[tuple[str, int]]:
        """TODO: SELECT domain, COUNT(*) ... WHERE decision='block' GROUP BY ..."""
        raise NotImplementedError

    def get_stats(self) -> dict:
        """TODO: return {'total':..,'blocked':..,'allowed':..,'cache_hits':..}."""
        raise NotImplementedError
