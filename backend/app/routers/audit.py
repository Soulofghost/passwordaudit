import uuid
import datetime
from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any

from backend.app.database import get_connection
from backend.app.schemas import AuditRequest, AuditResponse, BatchAuditRequest, BatchAuditSummary
from backend.app.engine.entropy import EntropyEngine
from backend.app.engine.patterns import PatternEngine
from backend.app.engine.nist_evaluator import NISTEvaluator

router = APIRouter(prefix="/api", tags=["audit"])

@router.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "PasswordAudit",
        "version": "1.0.0",
        "engine": "Shannon Entropy & NIST SP 800-63B Compliance Evaluator"
    }

@router.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM audit_logs;")
    total_audits = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM audit_logs WHERE rating = 'CRITICAL_RISK';")
    critical_risk = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM audit_logs WHERE nist_compliant = 1;")
    compliant_count = cursor.fetchone()["c"]

    cursor.execute("SELECT AVG(keyspace_bits) as a FROM audit_logs;")
    avg_entropy_row = cursor.fetchone()["a"]
    avg_entropy = round(avg_entropy_row, 2) if avg_entropy_row else 0.0

    conn.close()

    compliance_rate = round((compliant_count / total_audits) * 100, 1) if total_audits > 0 else 0.0

    return {
        "totalAudits": total_audits,
        "criticalRiskCount": critical_risk,
        "nistCompliantCount": compliant_count,
        "complianceRate": compliance_rate,
        "avgEntropyBits": avg_entropy
    }

@router.post("/audit", response_model=AuditResponse)
def audit_password(payload: AuditRequest):
    pwd = payload.password
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    audit_id = "aud-" + str(uuid.uuid4())[:8]

    shannon = EntropyEngine.calculate_shannon_entropy(pwd)
    keyspace = EntropyEngine.calculate_keyspace_entropy(pwd)
    crack_times = EntropyEngine.estimate_crack_times(keyspace["entropy_bits"])
    patterns = PatternEngine.detect_patterns(pwd)
    nist_eval = NISTEvaluator.evaluate(pwd, patterns, keyspace["entropy_bits"])
    prefix, suffix = NISTEvaluator.get_sha1_prefix_suffix(pwd)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_logs (id, identifier, entropy_score, keyspace_bits, rating, nist_compliant, breached, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        audit_id,
        payload.identifier or "interactive-user",
        shannon,
        keyspace["entropy_bits"],
        nist_eval["rating"],
        1 if nist_eval["nist_compliant"] else 0,
        1 if nist_eval["rating"] == "CRITICAL_RISK" else 0,
        now_iso
    ))
    conn.commit()
    conn.close()

    return {
        "id": audit_id,
        "identifier": payload.identifier or "interactive-user",
        "length": len(pwd),
        "shannon_entropy": shannon,
        "entropy_bits": keyspace["entropy_bits"],
        "charset_size": keyspace["charset_size"],
        "rating": nist_eval["rating"],
        "nist_compliant": nist_eval["nist_compliant"],
        "patterns": patterns,
        "crack_times": crack_times,
        "nist_checks": nist_eval["checks"],
        "sha1_hash_prefix": prefix,
        "created_at": now_iso
    }

@router.post("/audit/batch", response_model=BatchAuditSummary)
def audit_batch(payload: BatchAuditRequest):
    total = len(payload.passwords)
    crit_count = 0
    weak_count = 0
    mod_count = 0
    strong_count = 0
    compliant_count = 0
    entropy_sum = 0.0
    results = []

    for pwd in payload.passwords:
        shannon = EntropyEngine.calculate_shannon_entropy(pwd)
        keyspace = EntropyEngine.calculate_keyspace_entropy(pwd)
        patterns = PatternEngine.detect_patterns(pwd)
        nist_eval = NISTEvaluator.evaluate(pwd, patterns, keyspace["entropy_bits"])

        rating = nist_eval["rating"]
        if rating == "CRITICAL_RISK": crit_count += 1
        elif rating == "WEAK": weak_count += 1
        elif rating == "MODERATE": mod_count += 1
        else: strong_count += 1

        if nist_eval["nist_compliant"]:
            compliant_count += 1

        entropy_sum += keyspace["entropy_bits"]

        results.append({
            "length": len(pwd),
            "masked": pwd[0] + ("*" * (len(pwd) - 2)) + (pwd[-1] if len(pwd) > 1 else ""),
            "entropy_bits": keyspace["entropy_bits"],
            "rating": rating,
            "nist_compliant": nist_eval["nist_compliant"],
            "anomalies_detected": len(patterns)
        })

    return {
        "total_evaluated": total,
        "critical_risk_count": crit_count,
        "weak_count": weak_count,
        "moderate_count": mod_count,
        "strong_count": strong_count,
        "compliant_percentage": round((compliant_count / total) * 100, 1),
        "average_entropy_bits": round(entropy_sum / total, 2),
        "results": results
    }

@router.get("/logs")
def list_logs(limit: int = 50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?;", (limit,))
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": len(rows),
        "logs": [dict(r) for r in rows]
    }
