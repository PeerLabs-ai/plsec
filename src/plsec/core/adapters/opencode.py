"""OpenCode data adapter -- version probing from SQLite data store.

OpenCode stores session data in a SQLite database at
~/.local/share/opencode/opencode.db (managed by Drizzle ORM).

The ``session`` table contains a ``version`` column (text, NOT NULL)
recording the OpenCode version that created each session.  We read
the most recent session's version as the data store version.

Connection is always read-only (``?mode=ro``) to guarantee we never
modify agent data.

Milestone 14a: Version probing only.
Milestone 15:  Full AgentDataAdapter implementation.
"""

import logging
import sqlite3
from pathlib import Path

log = logging.getLogger(__name__)

# Relative path to the SQLite database within the data directory.
OPENCODE_DB_NAME = "opencode.db"

# Query to extract the version from the most recent session.
# time_created is a Unix timestamp in milliseconds.
_VERSION_QUERY = "SELECT version FROM session ORDER BY time_created DESC LIMIT 1"


def probe_opencode_data_version(data_dir: Path) -> str | None:
    """Read the OpenCode version from the most recent session.

    Args:
        data_dir: Path to the OpenCode data directory
                  (e.g., ~/.local/share/opencode/).

    Returns:
        Version string (e.g., "1.2.15") or None if the database
        is missing, empty, or has an unexpected schema.
    """
    db_path = data_dir / OPENCODE_DB_NAME
    if not db_path.is_file():
        log.debug("OpenCode database not found: %s", db_path)
        return None

    try:
        # Read-only connection -- never modify agent data
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cursor = conn.execute(_VERSION_QUERY)
            row = cursor.fetchone()
            if row is None:
                log.debug("OpenCode database has no sessions")
                return None
            version = row[0]
            if not isinstance(version, str) or not version:
                return None
            return version.strip()
        finally:
            conn.close()
    except sqlite3.OperationalError as exc:
        # Schema mismatch, missing table, permission error, etc.
        log.debug("OpenCode database query failed: %s", exc)
        return None
    except sqlite3.DatabaseError as exc:
        # Corrupt database, wrong file type, etc.
        log.debug("OpenCode database error: %s", exc)
        return None
