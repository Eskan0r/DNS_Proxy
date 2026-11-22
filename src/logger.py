"""SQLite request logging and report queries (Vinh Nguyen).

Instances are owned by their creating thread. The proxy's serial adapter keeps
construction, writes, and cleanup together. Decisions are allow/block/cache/error;
timestamps are UTC and latency is in milliseconds.
"""
import sqlite3
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .utils import normalize_domain

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

        # Migrate existing databases without discarding any request history.
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(queries)")}
        if "risk_signals" not in columns:
            self.connection.execute("ALTER TABLE queries ADD COLUMN risk_signals TEXT DEFAULT '[]'")
        if "upstream_min_ttl" not in columns:
            self.connection.execute("ALTER TABLE queries ADD COLUMN upstream_min_ttl INTEGER")
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS domain_first_seen (
                domain TEXT PRIMARY KEY, first_seen REAL NOT NULL
            )
        """)
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS observer_state (
                id INTEGER PRIMARY KEY CHECK (id = 1), started_at REAL NOT NULL
            )
        """)
        if not self.connection.execute("SELECT 1 FROM observer_state").fetchone():
            # Recover first observations from a pre-migration logger database.
            self.connection.execute("""
                INSERT OR IGNORE INTO domain_first_seen (domain, first_seen)
                SELECT lower(rtrim(domain, '.')), COALESCE(CAST(strftime('%s', MIN(ts)) AS REAL), ?)
                FROM queries WHERE domain != '' AND qtype IN ('A', 'AAAA')
                    AND decision != 'error'
                GROUP BY lower(rtrim(domain, '.'))
            """, (time.time(),))
            self.connection.execute("""
                INSERT INTO observer_state VALUES (1,
                    COALESCE((SELECT MIN(first_seen) FROM domain_first_seen), ?))
            """, (time.time(),))
        self._observer_started = self.connection.execute(
            "SELECT started_at FROM observer_state WHERE id = 1").fetchone()[0]
        self.connection.commit()
    def log(self, client_ip: str, domain: str, qtype: str,
            decision: str, category: str, latency_ms: float = 0.0, *,
            upstream_min_ttl: int | None = None) -> None:
        """Save one DNS event without letting SQLite errors stop the proxy."""
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            now = time.time()
            signals = []
            hostname = normalize_domain(domain)
            if hostname and qtype in ('A', 'AAAA') and decision != 'error':
                self.connection.execute(
                    "INSERT OR IGNORE INTO domain_first_seen VALUES (?, ?)", (hostname, now))
                first_seen = self.connection.execute(
                    "SELECT first_seen FROM domain_first_seen WHERE domain = ?", (hostname,)
                ).fetchone()[0]
                if (now - self._observer_started >= config.NEW_DOMAIN_LEARNING_SEC
                        and 0 <= now - first_seen < config.NEW_DOMAIN_WINDOW_SEC):
                    signals.append("newly-observed")
            if (upstream_min_ttl is not None
                    and 0 <= upstream_min_ttl < config.SHORT_TTL_THRESHOLD_SEC):
                signals.append("short-ttl")

            self.connection.execute("""
                INSERT INTO queries (
                    ts, client_ip, domain, qtype,
                    decision, category, latency_ms, risk_signals, upstream_min_ttl
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, client_ip, domain, qtype,
                decision, category, latency_ms, json.dumps(signals), upstream_min_ttl
            ))

            self.connection.commit()

        except sqlite3.Error as error:
            try:
                self.connection.rollback()
            except sqlite3.Error:
                pass
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
