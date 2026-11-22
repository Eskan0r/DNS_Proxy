#From Vinh: This is a file with just made up data to test, we can delete this later, but for now it is just here for us to test the logger.
import sqlite3
from datetime import datetime, timezone

# Open the database. SQLite creates this file if it doesn't exist.
connection = sqlite3.connect("practice_dns.db")

# A cursor lets us execute SQL commands.
cursor = connection.cursor()

# Create our table once. Existing records stay there when we rerun.
cursor.execute("""
    CREATE TABLE IF NOT EXISTS dns_events (
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        domain TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL
    )
""")
connection.commit()


def log_event(client_ip, domain, decision, reason):
    # Record when this event is logged, using UTC.
    timestamp = datetime.now(timezone.utc).isoformat()

    # The ? placeholders receive the values from the tuple below.
    cursor.execute("""
        INSERT INTO dns_events (
            timestamp, client_ip, domain, decision, reason
        )
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, client_ip, domain, decision, reason))

    # Save the inserted record.
    connection.commit()


# Pretend these calls came from the DNS proxy.
log_event(
    "192.168.1.10",
    "example.com",
    "ALLOW",
    "No matching blocklist entry"
)

log_event(
    "192.168.1.20",
    "malware.test",
    "BLOCK",
    "Domain is on blocklist"
)

log_event(
    "192.168.1.10",
    "suspicious.test",
    "BLOCK",
    "High DGA score"
)

# Read the saved records to check our work.
cursor.execute("""
    SELECT id, client_ip, domain, decision, reason
    FROM dns_events
    ORDER BY id
""")

for row in cursor.fetchall():
    print(row)

connection.close()