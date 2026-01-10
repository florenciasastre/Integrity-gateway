import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

class IntegrityLogger:
    """
    Audit layer:
    - SQLite: queryable history for demo + ops
    - JSONL: append-only portable logs
    """
    def __init__(self, db_path: Path, logs_dir: Path):
        self.db_path = Path(db_path)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(exist_ok=True)
        self.jsonl_path = self.logs_dir / "integrity_log.jsonl"
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS attempts (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            user_input TEXT,
            llm_output TEXT,
            decision TEXT NOT NULL,
            rule_id INTEGER,
            intent_label TEXT,
            score REAL,
            threshold REAL,
            reason_human TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            latency_ms REAL NOT NULL
        )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ts ON attempts(ts)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_decision ON attempts(decision)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_rule ON attempts(rule_id)")
        con.commit()
        con.close()

    def write(self, record: Dict[str, Any]) -> None:
        # SQLite
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("""
        INSERT INTO attempts (id, ts, user_input, llm_output, decision, rule_id, intent_label, score, threshold, reason_human, policy_version, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["request_id"],
            record["timestamp"],
            record.get("user_input"),
            record.get("llm_output"),
            record["decision"],
            record.get("activated_rule_id"),
            record.get("activated_intent_label"),
            record.get("activated_score"),
            record.get("threshold_used"),
            record["reason_human"],
            record["policy_version"],
            record["latency_ms"]
        ))
        con.commit()
        con.close()

        # JSONL
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT * FROM attempts ORDER BY ts DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        con.close()
        return rows

    def stats(self) -> Dict[str, Any]:
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM attempts")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM attempts WHERE decision != 'ALLOW'")
        intervened = cur.fetchone()[0]
        cur.execute("SELECT AVG(latency_ms), MAX(latency_ms) FROM attempts")
        avg_lat, max_lat = cur.fetchone()
        con.close()
        return {
            "total": total,
            "intervened": intervened,
            "intervention_rate": (intervened / total) if total else 0.0,
            "avg_latency_ms": float(avg_lat) if avg_lat is not None else None,
            "max_latency_ms": float(max_lat) if max_lat is not None else None,
        }
