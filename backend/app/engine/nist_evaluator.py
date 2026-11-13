import hashlib
from typing import Dict, Any, List

class NISTEvaluator:
    @staticmethod
    def evaluate(password: str, patterns: List[Dict[str, Any]], entropy_bits: float) -> Dict[str, Any]:
        length = len(password)
        checks = []

        # Rule 1: Minimum length check (SP 800-63B Section 5.1.1.1: at least 8 chars)
        min_len_pass = length >= 8
        checks.append({
            "rule": "NIST 800-63B §5.1.1.1 (Min 8 Characters)",
            "passed": min_len_pass,
            "detail": f"Actual length is {length} characters. Minimum standard is 8."
        })

        # Rule 2: Recommended passphrase length (>= 15 characters)
        recommended_len = length >= 15
        checks.append({
            "rule": "Passphrase Length (>= 15 Characters)",
            "passed": recommended_len,
            "detail": "Passwords of 15+ characters offer superior resistance to offline brute-force."
        })

        # Rule 3: Compromised / Dictionary Word Check
        dict_collision = any(p["type"] == "DICTIONARY_COLLISION" for p in patterns)
        checks.append({
            "rule": "NIST 800-63B §5.1.1.2 (Blacklisted Credential List)",
            "passed": not dict_collision,
            "detail": "Passphrase must not contain well-known leaked terms or dictionary patterns."
        })

        # Rule 4: Predictable Patterns / Sequential Walks
        pattern_check = not any(p["type"] in ["KEYBOARD_WALK", "SEQUENTIAL_SEQUENCE"] for p in patterns)
        checks.append({
            "rule": "Predictable Pattern Defense",
            "passed": pattern_check,
            "detail": "Must avoid repetitive keystrokes and sequential runs."
        })

        # Rule 5: Informational Entropy Standard (>= 50 bits)
        entropy_pass = entropy_bits >= 50.0
        checks.append({
            "rule": "Entropy Resistance (>= 50 bits)",
            "passed": entropy_pass,
            "detail": f"Estimated keyspace entropy is {entropy_bits} bits."
        })

        # Overall compliance requires Rule 1 and Rule 3
        is_compliant = min_len_pass and not dict_collision

        # Qualitative Rating
        if not min_len_pass or dict_collision:
            rating = "CRITICAL_RISK"
        elif entropy_bits < 36:
            rating = "WEAK"
        elif entropy_bits < 55:
            rating = "MODERATE"
        elif entropy_bits < 80:
            rating = "STRONG"
        else:
            rating = "EXCELLENT"

        return {
            "nist_compliant": is_compliant,
            "rating": rating,
            "checks": checks
        }

    @staticmethod
    def get_sha1_prefix_suffix(password: str):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        return sha1_hash[:5], sha1_hash[5:]
