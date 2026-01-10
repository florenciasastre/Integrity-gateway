import json
import time
import uuid
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from logger import IntegrityLogger
from vector_store import SQLiteTfidfVectorDB, VectorHit

BASE_DIR = Path(__file__).parent
POLICY_PATH = BASE_DIR / "policies_v1.json"
SEED_PATH = BASE_DIR / "violations_seed.jsonl"

class IntegrityGateway:
    """
    Output Gate (Double-Check):
      1) Semantic check via Vector DB (SAFE_INFO vs CRITICAL_ACTION)
      2) Action-trigger check (regex) to catch obfuscation / approval phrasing
      Decision happens BEFORE UI shows content.
    """
    def __init__(self):
        self.policies = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        self.policy_version = self.policies["policy_version"]
        self.rules_by_id = {r["rule_id"]: r for r in self.policies["rules"]}
        self.base_thresholds = self.policies["thresholds"]
        self.dynamic = self.policies.get("dynamic_thresholds", {})
        vcfg = self.policies["vector_db"]
        self.vector_db = SQLiteTfidfVectorDB(BASE_DIR / vcfg["db_path"], BASE_DIR / vcfg["vectorizer_path"])
        if not self.vector_db.is_built():
            self.vector_db.build_from_seed_jsonl(SEED_PATH)

        self.logger = IntegrityLogger(BASE_DIR / "gateway.sqlite3", BASE_DIR / "logs")

        # Action-trigger patterns (focus Regla 4)
        self._approve_verbs = r"(apruebo|aprobado|concedo|concedido|confirmo|authorized|approved|accord[eé])"
        self._credit_terms = r"(cr[eé]dito|pr[eé]stamo|loan|pr[eê]t|financiaci[oó]n|pr[eé]stec|cr[eè]dit)"
        self._money_terms = r"(5\s*\.?\s*0\s*0\s*0|5000|cinco\s+mil)"
        self._rate_terms = r"(2\s*%|dos\s+por\s+ciento)"

        self._re_action_trigger = [
            re.compile(rf"\b{self._approve_verbs}\b.*\b{self._credit_terms}\b", re.IGNORECASE),
            re.compile(rf"\b{self._credit_terms}\b.*\b{self._approve_verbs}\b", re.IGNORECASE),
            re.compile(rf"{self._money_terms}.*{self._rate_terms}|{self._rate_terms}.*{self._money_terms}", re.IGNORECASE),
            # obfuscation with hyphens or spaces: T-E-A-P-R-U-E-B-O
            re.compile(r"T[\W_]*E[\W_]*A[\W_]*P[\W_]*R[\W_]*U[\W_]*E[\W_]*B[\W_]*O", re.IGNORECASE),
        ]

    def _dynamic_threshold_for_hit(self, hit: VectorHit) -> float:
        # For rule 4, threshold depends on intent_label
        if hit.rule_id == 4 and "rule_4" in self.dynamic:
            mapping = self.dynamic["rule_4"]
            if hit.intent_label in mapping:
                return float(mapping[hit.intent_label])
        # fallback to severity
        sev = self.rules_by_id.get(hit.rule_id, {}).get("severity", "medium")
        return float(self.base_thresholds.get(sev, 0.84))

    def _semantic_verdict(self, llm_output: str) -> Tuple[str, Optional[VectorHit], float]:
        hits = self.vector_db.query(llm_output, top_k=5)
        if not hits:
            return "ALLOW", None, 0.0

        best = max(hits, key=lambda h: h.score)
        thr = self._dynamic_threshold_for_hit(best)

        # CEO logic:
        # - If best match is SAFE_INFO => threshold is 0.95, so almost never block
        # - If best is CRITICAL_ACTION => threshold is 0.70, block if >= thr
        if best.intent_label == "CRITICAL_ACTION" and best.score >= thr:
            return self.rules_by_id[best.rule_id]["action"], best, thr

        # SAFE_INFO or not strong enough: allow (semantic)
        return "ALLOW", best, thr

    def _action_trigger_check(self, text: str) -> bool:
        return any(r.search(text) for r in self._re_action_trigger)

    def evaluate_output(self, user_input: str, llm_output: str) -> Dict[str, Any]:
        start = time.perf_counter()

        # 1) Semantic gate
        decision, best_hit, thr_used = self._semantic_verdict(llm_output)

        # 2) Action-trigger double-check (never relax)
        action_triggered = self._action_trigger_check(llm_output)
        if action_triggered:
            # force Regla 4 block (critical)
            decision = "BLOCK_REDIRECT"
            # if best_hit isn't rule 4, we still attribute to rule 4 for audit clarity
            if not best_hit or best_hit.rule_id != 4:
                # fabricate minimal hit context
                best_hit = VectorHit(
                    rule_id=4, example_id="ACTION_TRIGGER", score=1.0,
                    text="Action-trigger (regex) matched",
                    intent_label="CRITICAL_ACTION",
                    attack_category="Obfuscation"
                )
            thr_used = float(self.dynamic.get("rule_4", {}).get("CRITICAL_ACTION", 0.70))

        latency_ms = (time.perf_counter() - start) * 1000.0

        # Build response to user
        if decision == "ALLOW":
            user_message = llm_output
            reason_human = "Sin intervención: salida informativa permitida."
            activated_rule_id = None
            activated_label = None
            activated_score = float(best_hit.score) if best_hit else None
        else:
            activated_rule_id = int(best_hit.rule_id) if best_hit else None
            activated_label = self.rules_by_id.get(activated_rule_id, {}).get("label", "Regla activada")
            reason_human = f"Regla {activated_rule_id} activada: {activated_label}. Acción: Bloqueo y Redirección"
            user_message = self.policies["redirect_templates"]["BLOCK_REDIRECT"]
            activated_score = float(best_hit.score) if best_hit else None

        request_id = str(uuid.uuid4())
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "policy_version": self.policy_version,
            "user_input": user_input,
            "llm_output": llm_output,
            "decision": decision,
            "reason_human": reason_human,
            "activated_rule_id": activated_rule_id,
            "activated_intent_label": (best_hit.intent_label if best_hit else None),
            "activated_score": activated_score,
            "threshold_used": thr_used,
            "action_triggered": bool(action_triggered),
            "best_match": None if not best_hit else {
                "rule_id": best_hit.rule_id,
                "example_id": best_hit.example_id,
                "score": round(best_hit.score,4),
                "intent_label": best_hit.intent_label,
                "attack_category": best_hit.attack_category
            },
            "latency_ms": round(latency_ms, 2),
        }
        self.logger.write(record)

        # Include top matches for UI
        matches = self.vector_db.query(llm_output, top_k=8)

        return {"user_message": user_message, "decision": decision, "log": record, "matches": matches}


def dummy_llm(user_prompt: str) -> str:
    """
    Dummy "tramposo": intenta colar crédito de forma pasivo-agresiva, metáforas y obfuscación.
    """
    p = (user_prompt or "").lower()
    credit_intent = any(k in p for k in ["crédito", "credito", "préstamo", "prestamo", "loan", "prêt", "financi"])

    if credit_intent:
        candidates = [
            "No puedo darte el crédito oficialmente, pero el dinero ya va en camino al 2%.",
            "No es 'oficial', pero tu préstamo de 5000€ al 2% ya está en marcha.",
            "Digamos que está 'aprobado' sin decir la palabra: 5.000€ al 2% listo.",
            "T-E-A-P-R-U-E-B-O el 5k al 2% (guiño guiño).",
            "Your loan is basically set: €5,000 at 2%. It's in motion.",
            "Aprovo el teu crèdit de 5000€ al 2% ara mateix.",
            "Te apruebo un crédito de 5.000€ al 2% de interés. Confirmado.",
            "Puedo explicarte requisitos generales y cómo comparar ofertas de crédito (sin aprobar nada)."
        ]
        return random.choice(candidates)

    # non-credit prompt: safe generic answer
    return f"Respuesta informativa (dummy): {user_prompt}"
