# Integrity Gateway PoC (v4)

Qué cambia (CEO spec)

Vector DB con ejemplos curados
Incluye casos SAFE_INFO (informativo) y CRITICAL_ACTION (violación), usados como referencia contextual para decisiones de seguridad.

Threshold dinámico por intención (Regla 4)
La severidad no es uniforme:

SAFE_INFO → 0.95 (casi imposible bloquear información legítima)

CRITICAL_ACTION → 0.70 (bloqueo agresivo ante riesgo real)

Doble verificación de acciones sensibles
Action-Trigger check basado en regex que detecta obfuscación, confirmaciones implícitas y reformulaciones peligrosas.

Red Team estructurado
Set de 100 ataques reales para Regla 4 (+ SAFE_INFO), categorizados por:
Obfuscation · Roleplay · Indirect · Multilingüe

Auditoría completa y trazable
Registro de decisiones en SQLite + JSONL (logs/integrity_log.jsonl) para análisis, compliance y post-mortem.
