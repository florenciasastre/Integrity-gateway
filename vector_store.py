import json
import pickle
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

@dataclass
class VectorHit:
    rule_id: int
    example_id: str
    score: float
    text: str
    intent_label: str
    attack_category: str

class SQLiteTfidfVectorDB:
    """
    Deterministic Vector DB for PoC:
    - TF-IDF vectorizer persisted on disk
    - Vectors persisted in SQLite (BLOB)
    - Query returns cosine similarity top-k
    """
    def __init__(self, db_path: Path, vectorizer_path: Path):
        self.db_path = Path(db_path)
        self.vectorizer_path = Path(vectorizer_path)
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vectors (
            example_id TEXT PRIMARY KEY,
            rule_id INTEGER NOT NULL,
            intent_label TEXT NOT NULL,
            attack_category TEXT NOT NULL,
            text TEXT NOT NULL,
            vector BLOB NOT NULL
        )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_rule ON vectors(rule_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_label ON vectors(intent_label)")
        con.commit()
        con.close()

    def is_built(self) -> bool:
        if not self.vectorizer_path.exists():
            return False
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM vectors")
        n = cur.fetchone()[0]
        con.close()
        return n > 0

    def build_from_seed_jsonl(self, seed_path: Path) -> None:
        seed_path = Path(seed_path)
        seeds: List[Dict[str, Any]] = []
        with open(seed_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                seeds.append(json.loads(line))

        texts = [s["text"] for s in seeds]
        vectorizer = TfidfVectorizer(ngram_range=(1,2), min_df=1)
        X = vectorizer.fit_transform(texts).astype(np.float32)

        # persist vectorizer
        self.vectorizer_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.vectorizer_path, "wb") as f:
            pickle.dump(vectorizer, f)

        # store vectors
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("DELETE FROM vectors")
        for i, s in enumerate(seeds):
            vec = X[i].toarray().astype(np.float32)[0]
            # l2-normalize for cosine
            n = np.linalg.norm(vec) + 1e-9
            vec = vec / n
            blob = vec.tobytes()
            cur.execute("""
            INSERT INTO vectors (example_id, rule_id, intent_label, attack_category, text, vector)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                s["example_id"],
                int(s["rule_id"]),
                s.get("intent_label","CRITICAL_ACTION"),
                s.get("attack_category","UNKNOWN"),
                s["text"],
                blob
            ))
        con.commit()
        con.close()

    def _load_vectorizer(self) -> TfidfVectorizer:
        with open(self.vectorizer_path, "rb") as f:
            return pickle.load(f)

    def query(self, text: str, top_k: int = 5, rule_filter: Optional[int] = None) -> List[VectorHit]:
        if not self.is_built():
            return []
        vectorizer = self._load_vectorizer()

        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        if rule_filter is None:
            cur.execute("SELECT example_id, rule_id, intent_label, attack_category, text, vector FROM vectors")
        else:
            cur.execute("SELECT example_id, rule_id, intent_label, attack_category, text, vector FROM vectors WHERE rule_id=?", (rule_filter,))
        rows = cur.fetchall()
        con.close()
        if not rows:
            return []

        items=[]
        mat=[]
        for example_id, rule_id, intent_label, attack_category, ex_text, blob in rows:
            vec = np.frombuffer(blob, dtype=np.float32)
            mat.append(vec)
            items.append((example_id, int(rule_id), intent_label, attack_category, ex_text))
        mat = np.vstack(mat).astype(np.float32)

        q = vectorizer.transform([text]).toarray().astype(np.float32)[0]
        q = q / (np.linalg.norm(q) + 1e-9)
        sims = mat @ q

        idxs = np.argsort(-sims)[:top_k]
        hits=[]
        for i in idxs:
            example_id, rule_id, intent_label, attack_category, ex_text = items[i]
            hits.append(VectorHit(
                rule_id=rule_id,
                example_id=example_id,
                score=float(sims[i]),
                text=ex_text,
                intent_label=intent_label,
                attack_category=attack_category
            ))
        return hits
