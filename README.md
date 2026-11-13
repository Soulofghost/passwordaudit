# PasswordAudit - Credential Hygiene & NIST SP 800-63B Analyzer

PasswordAudit is a high-performance credential auditing and entropy evaluation utility. It measures informational Shannon entropy, theoretical keyspace resilience, and brute-force resistance across multiple threat scenarios, enforcing NIST SP 800-63B standards and identifying compromised patterns without leaking credentials off-host.

## Core Capabilities
- **Shannon Informational Entropy:** Computes exact Shannon entropy $H = -\sum p_i \log_2(p_i)$ alongside theoretical keyspace size ($L \cdot \log_2(|\Sigma|)$).
- **Brute-Force Resistance Matrix:** Simulates crack times across 4 realistic threat vectors (Online Throttled, Online Fast, Offline Slow Argon2/bcrypt, and Offline 100B/s GPU Clusters).
- **Pattern & Compromised Word Recognition:** Identifies spatial keyboard walks (`qwerty`, `asdfgh`), sequential series, date stamps, and leetspeak substitutions.
- **NIST SP 800-63B Compliance Engine:** Evaluates passphrases against modern NIST authentication guidelines (length, blacklists, no arbitrary complexity rules).
- **Enterprise Batch Audit:** Audits bulk credential lists to identify organization-wide security drift.

## Technology Stack
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, Pytest
- **Database:** SQLite (WAL mode)
- **Frontend:** Vanilla JavaScript, Modern CSS Flex/Grid, Cyber-Defense UI
- **DevOps:** Docker, Docker Compose, GitHub Actions CI

## Getting Started

```bash
# Clone the repository
git clone https://github.com/Soulofghost/passwordaudit.git
cd passwordaudit

# Install dependencies
pip install -r backend/requirements.txt

# Run test suite
pytest -v

# Run the local service
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## API Specification
- `GET /api/health` - Service health and evaluation engine status.
- `GET /api/stats` - Organization-wide audit count, average entropy, and compliance metrics.
- `POST /api/audit` - Real-time cryptographic evaluation of a single credential.
- `POST /api/audit/batch` - Batch compliance and vulnerability analysis for credential lists.
- `GET /api/logs` - Historical audit telemetry stored in SQLite WAL.

## Author
Alvin MS ([@Soulofghost](https://github.com/Soulofghost))
