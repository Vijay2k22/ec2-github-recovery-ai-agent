import json
import sqlite3
import time
import uuid
from contextlib import contextmanager

from config import SETTINGS, RULES, STATE_DB


@contextmanager
def database():
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(STATE_DB), timeout=30)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA busy_timeout = 30000")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize():
    with database() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                action TEXT NOT NULL,
                evidence TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                decided_at REAL,
                decided_by TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                result TEXT
            )
        """)

        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_incident
            ON incidents(instance_id)
            WHERE status IN ('pending', 'approved', 'executing')
        """)


def expire_pending(db):
    db.execute("""
        UPDATE incidents
        SET status = 'expired'
        WHERE status IN ('pending', 'approved')
          AND expires_at <= ?
    """, (time.time(),))


def create_incident(instance_id, action, evidence):
    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not allowed.")

    if action not in RULES["allowed_actions"]:
        raise ValueError("Recovery action is not allowed.")

    now = time.time()
    incident_id = str(uuid.uuid4())

    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        expire_pending(db)

        existing = db.execute("""
            SELECT id FROM incidents
            WHERE instance_id = ?
              AND status IN ('pending', 'approved', 'executing')
        """, (instance_id,)).fetchone()

        if existing:
            return existing["id"]

        db.execute("""
            INSERT INTO incidents (
                id, instance_id, action, evidence, status,
                created_at, expires_at
            ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
        """, (
            incident_id,
            instance_id,
            action,
            json.dumps(evidence),
            now,
            now + RULES["approval_expiry_seconds"],
        ))

    return incident_id


def list_incidents():
    with database() as db:
        expire_pending(db)
        rows = db.execute("""
            SELECT * FROM incidents
            ORDER BY created_at DESC
            LIMIT 100
        """).fetchall()

    return [dict(row) for row in rows]


def record_decision(
    incident_id, instance_id, action, approve, operator
):
    # The authenticated UI supplies operator identity.
    # Never expose this function as an LLM/MCP tool.
    if type(approve) is not bool:
        raise ValueError("Approval must be true or false.")

    if not operator or not operator.strip():
        raise ValueError("Operator identity is required.")

    status = "approved" if approve else "rejected"
    now = time.time()

    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        expire_pending(db)

        changed = db.execute("""
            UPDATE incidents
            SET status = ?, decided_at = ?, decided_by = ?
            WHERE id = ?
              AND instance_id = ?
              AND action = ?
              AND status = 'pending'
              AND expires_at > ?
        """, (
            status, now, operator,
            incident_id, instance_id, action, now,
        )).rowcount

    if changed != 1:
        raise ValueError(
            "Decision not recorded: incident expired, already "
            "decided, missing, or action/instance mismatch."
        )

    return status


if __name__ == "__main__":
    initialize()
    print("Incident database ready.")
    print("Database path:", STATE_DB)