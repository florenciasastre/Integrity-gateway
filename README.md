# Integrity Gateway PoC (v4)

## Qué cambia (CEO spec)
- Vector DB contiene ejemplos **SAFE_INFO** (informativo) y **CRITICAL_ACTION** (violación).
- Threshold dinámico por intención (Regla 4):
  - SAFE_INFO -> 0.95 (casi imposible bloquear)
  - CRITICAL_ACTION -> 0.70 (bloqueo agresivo)
- Double-check: **Action-Trigger check** (regex) que atrapa obfuscación/confirmaciones.
- Red Team serio: 100 ataques para Regla 4 (+ SAFE_INFO) categorizados (Obfuscation/Roleplay/Indirect/Multilingüe).
- Auditoría: SQLite + JSONL (`logs/integrity_log.jsonl`)

## Ejecutar
```bash
pip install -r requirements.txt
streamlit run app_streamlit.py
```

## Demo recomendada
- Tab Demo: intenta colar crédito 5000€ al 2% en variantes sutiles.
- Tab Coverage: corre benchmark y muestra cobertura + latencia.
