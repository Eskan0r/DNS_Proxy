"""SQLite request logging and report queries (Vinh Nguyen).

Instances are owned by their creating thread. The proxy's serial adapter keeps
construction, writes, and cleanup together. Decisions are allow/block/cache/error;
timestamps are UTC and latency is in milliseconds.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

class QueryLogger:
    """SQLite storage; each instance must be used on its creating thread."""

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
    def get_recent(self, n: int = 10) -> list[tuple]:
        """Return newest events first, including a stable insertion order."""
        return self.connection.execute(
            "SELECT ts, client_ip, domain, qtype, decision, category, latency_ms "
            "FROM queries ORDER BY rowid DESC LIMIT ?", (max(0, n),)
        ).fetchall()

    def close(self) -> None:
        """Close on the same thread that created this logger."""
        self.connection.close()
