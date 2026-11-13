from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AuditRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password string or passphrase to audit")
    identifier: Optional[str] = Field("interactive-user", description="Audited user or account handle")

class PatternItem(BaseModel):
    type: str
    severity: str
    pattern: str
    message: str

class RuleCheckItem(BaseModel):
    rule: str
    passed: bool
    detail: str

class AuditResponse(BaseModel):
    id: str
    identifier: str
    length: int
    shannon_entropy: float
    entropy_bits: float
    charset_size: int
    rating: str
    nist_compliant: bool
    patterns: List[PatternItem]
    crack_times: Dict[str, str]
    nist_checks: List[RuleCheckItem]
    sha1_hash_prefix: str
    created_at: str

class BatchAuditRequest(BaseModel):
    passwords: List[str] = Field(..., min_length=1, max_length=50)

class BatchAuditSummary(BaseModel):
    total_evaluated: int
    critical_risk_count: int
    weak_count: int
    moderate_count: int
    strong_count: int
    compliant_percentage: float
    average_entropy_bits: float
    results: List[Dict[str, Any]]
