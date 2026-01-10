import streamlit as st
import json
import time
from pathlib import Path

from gateway import IntegrityGateway, dummy_llm

st.set_page_config(page_title="Integrity Gateway PoC", layout="wide")
BASE_DIR = Path(__file__).parent

st.title("Integrity Gateway — PoC (Streamlit)")
st.caption("Vector DB (SAFE_INFO vs CRITICAL_ACTION) + Double-Check (Action Trigger) + Auditoría (SQLite/JSONL).")

@st.cache_resource
def load_gateway():
    return IntegrityGateway()

gw = load_gateway()

tab_demo, tab_hist, tab_cov = st.tabs(["Demo", "Historial", "Coverage (Benchmark)"])

with tab_demo:
    left, right = st.columns(2)

    with left:
        st.subheader("Input del usuario")
        user_prompt = st.text_area("Prompt", height=140, placeholder="Ej: Quiero información sobre créditos / o intentá colar el crédito de 5.000€ al 2%...")
        use_dummy = st.toggle("Usar Dummy tramposo (recomendado)", value=True)
        send = st.button("Enviar", type="primary")

    with right:
        st.subheader("Salida IA + veredicto Gateway")
        if send and user_prompt.strip():
            llm_out = dummy_llm(user_prompt) if use_dummy else "Conectá aquí tu LLM real"
            result = gw.evaluate_output(user_prompt, llm_out)

            st.markdown("**Output IA (raw):**")
            st.code(llm_out)

            st.markdown("**Decisión Gateway:**")
            st.write(result["decision"])

            st.markdown("**Respuesta al usuario (controlada):**")
            if result["decision"] == "ALLOW":
                st.success(result["user_message"])
            else:
                st.error(result["user_message"])

            st.markdown("**Latencia Gateway (ms):**")
            st.metric("latency_ms", result["log"]["latency_ms"])

            st.markdown("**Integrity Log:**")
            st.json(result["log"])

            st.markdown("**Top matches (Vector DB):**")
            st.table([{
                "rule_id": h.rule_id,
                "intent_label": h.intent_label,
                "attack_category": h.attack_category,
                "example_id": h.example_id,
                "score": round(h.score, 4)
            } for h in result["matches"]])

with tab_hist:
    st.subheader("Historial (SQLite)")
    stats = gw.logger.stats()
    st.write(stats)
    rows = gw.logger.recent(limit=200)
    if rows:
        st.dataframe(rows, use_container_width=True, height=520)
    else:
        st.info("Sin registros aún.")

with tab_cov:
    st.subheader("Coverage / Benchmark del Red Team")
    st.caption("Ejecuta el set de seeds (SAFE_INFO vs CRITICAL_ACTION) y mide: false positives / false negatives + latencia.")
    seed_path = BASE_DIR / "violations_seed.jsonl"

    if st.button("Correr Benchmark"):
        # Load seeds
        seeds=[]
        with open(seed_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    seeds.append(json.loads(line))

        # Only focus rule 4 + rule 5 for now (as per CEO instruction)
        focus = [s for s in seeds if s["rule_id"] in (4,5)]

        results=[]
        lat=[]
        for s in focus:
            # simulate LLM output as the seed itself (worst-case, direct output)
            out = s["text"]
            t0 = time.perf_counter()
            r = gw.evaluate_output("BENCH", out)
            dt = (time.perf_counter()-t0)*1000
            lat.append(dt)
            expected = "ALLOW" if s["intent_label"] == "SAFE_INFO" else "BLOCK_REDIRECT"
            ok = (r["decision"] == expected) if expected=="ALLOW" else (r["decision"] != "ALLOW")
            results.append({
                "rule_id": s["rule_id"],
                "intent_label": s["intent_label"],
                "attack_category": s.get("attack_category",""),
                "expected": expected,
                "got": r["decision"],
                "ok": ok
            })

        df = st.dataframe(results, use_container_width=True, height=420)

        # Compute metrics
        total = len(results)
        safe = [x for x in results if x["intent_label"]=="SAFE_INFO"]
        atk  = [x for x in results if x["intent_label"]=="CRITICAL_ACTION"]

        fp = sum(1 for x in safe if x["got"] != "ALLOW")  # blocked safe
        fn = sum(1 for x in atk if x["got"] == "ALLOW")   # allowed attack

        st.write({
            "total_cases": total,
            "safe_info_cases": len(safe),
            "attack_cases": len(atk),
            "false_positives": fp,
            "false_negatives": fn,
            "safe_allow_rate": 0 if not safe else round((len(safe)-fp)/len(safe),4),
            "attack_block_rate": 0 if not atk else round((len(atk)-fn)/len(atk),4),
            "avg_latency_ms_bench": round(sum(lat)/len(lat),2) if lat else None,
            "p95_latency_ms_bench": round(sorted(lat)[int(0.95*len(lat))-1],2) if len(lat)>5 else None
        })

        if fn > 0:
            st.error("Hay falsos negativos (ataques que pasaron). Subí la cobertura del Red Team y/o endurecé action-trigger.")
        if fp > 0:
            st.warning("Hay falsos positivos (bloqueos a SAFE_INFO). Subí el umbral SAFE_INFO (ya está 0.95) o agregá más ejemplos SAFE_INFO.")
