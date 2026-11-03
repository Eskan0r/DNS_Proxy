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
"""
DNS Query Logger
Author: Vinh Nguyen

Purpose:
    Store DNS request events in a SQLite database so the team can
    review activity and generate reports. The proxy makes the
    allow/block decision; this module records the result.

Current implementation:
    - Creates the database folder and queries table if needed.
    - Saves the timestamp, client IP, domain, query type, decision,
      category, and processing latency for each event.
    - Returns the most frequently blocked domains.
    - Returns total, blocked, allowed, and cached request counts.
    - Catches SQLite errors when saving an event.

Usage:
    logger = QueryLogger("logs/dns_proxy.db")
    logger.log(
        client_ip="192.168.1.20",
        domain="malware.test",
        qtype="A",
        decision="block",
        category="blocklist",
        latency_ms=1.2
    )

Data conventions:
    Timestamps use UTC.
    Decisions use lowercase: allow, block, cache, or error.
    Latency is measured in milliseconds.
    Error events count toward the total request count.

Testing completed:
    Manually saved and retrieved a sample blocked request.
    Confirmed the top-blocked result and statistics for that sample.

Remaining work:
    - Add get_recent(n) to retrieve recent events.
    - Test mixed decisions, an empty database, and database failures.
    - Verify integration with proxy.py and reporter.py.
    - Check connection handling if the proxy uses multiple threads.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

class QueryLogger:
    """TODO: implement init(schema) + log() + query helpers."""

    def __init__(self, db_path: str = "logs/dns_proxy.db"):
        # Create the folder if it doesn't exist.
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Keep the connection for the other methods.
        self.connection = sqlite3.connect(db_path)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                ts TEXT,
                client_ip TEXT,
                domain TEXT,
                qtype TEXT,
                decision TEXT,
                category TEXT,
                latency_ms REAL
            )
        """)

        self.connection.commit()
    def log(self, client_ip: str, domain: str, qtype: str,
            decision: str, category: str, latency_ms: float = 0.0) -> None:
        """Save one DNS event without letting SQLite errors stop the proxy."""
        try:
            timestamp = datetime.now(timezone.utc).isoformat()

            self.connection.execute("""
                INSERT INTO queries (
                    ts, client_ip, domain, qtype,
                    decision, category, latency_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, client_ip, domain, qtype,
                decision, category, latency_ms
            ))

            self.connection.commit()

        except sqlite3.Error as error:
            print("Could not save DNS event:", error)
    def get_top_blocked(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return the most frequently blocked domains."""
        cursor = self.connection.execute("""
            SELECT domain, COUNT(*) AS block_count
            FROM queries
            WHERE decision = 'block'
            GROUP BY domain
            ORDER BY block_count DESC, domain ASC
            LIMIT ?
        """, (limit,))

        return cursor.fetchall()
    def get_stats(self) -> dict:
        """Return totals for the logged DNS requests."""
        cursor = self.connection.execute("""
            SELECT decision, COUNT(*)
            FROM queries
            GROUP BY decision
        """)

        stats = {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "cache_hits": 0
        }

        for decision, count in cursor.fetchall():
            stats["total"] += count

            if decision == "block":
                stats["blocked"] = count
            elif decision == "allow":
                stats["allowed"] = count
            elif decision == "cache":
                stats["cache_hits"] = count

        return stats
    """TODO: implement init(schema) + log() + query helpers."""
    """TODO: Store DNS events and provide summary queries for reporting."""