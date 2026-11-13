import re
from typing import List, Dict, Any

COMMON_DICTIONARY = {
    "password", "admin", "welcome", "iloveyou", "secret", "master", "sunshine",
    "football", "dragon", "monkey", "letmein", "shadow", "superman", "trustno1",
    "root", "guest", "default", "changeme", "qwerty", "test", "security", "pass1234"
}

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz"
]

LEET_MAP = {
    '@': 'a', '4': 'a',
    '3': 'e',
    '1': 'i', '!': 'i',
    '0': 'o',
    '$': 's', '5': 's',
    '7': 't', '+': 't'
}

class PatternEngine:
    @staticmethod
    def normalize_leetspeak(text: str) -> str:
        lowered = text.lower()
        res = []
        for char in lowered:
            res.append(LEET_MAP.get(char, char))
        return "".join(res)

    @staticmethod
    def detect_patterns(password: str) -> List[Dict[str, Any]]:
        patterns_found = []
        lowered = password.lower()
        normalized = PatternEngine.normalize_leetspeak(password)

        # 1. Repeated consecutive characters (3+)
        repeat_match = re.search(r'(.)\1{2,}', password)
        if repeat_match:
            patterns_found.append({
                "type": "REPEATED_CHARS",
                "severity": "MEDIUM",
                "pattern": repeat_match.group(0),
                "message": f"Contains repeated sequence '{repeat_match.group(0)}' which lowers keyspace resilience."
            })

        # 2. Sequential character runs (e.g. abc, 123)
        for i in range(len(lowered) - 2):
            sub = lowered[i:i+3]
            if len(sub) == 3:
                c0, c1, c2 = ord(sub[0]), ord(sub[1]), ord(sub[2])
                if (c1 == c0 + 1 and c2 == c1 + 1) or (c1 == c0 - 1 and c2 == c1 - 1):
                    patterns_found.append({
                        "type": "SEQUENTIAL_SEQUENCE",
                        "severity": "HIGH",
                        "pattern": sub,
                        "message": f"Contains predictable sequence '{sub}' susceptible to sequential mask attacks."
                    })
                    break

        # 3. Spatial keyboard walks
        for kb in KEYBOARD_PATTERNS:
            for i in range(len(lowered) - 3):
                sub = lowered[i:i+4]
                if sub in kb:
                    patterns_found.append({
                        "type": "KEYBOARD_WALK",
                        "severity": "HIGH",
                        "pattern": sub,
                        "message": f"Contains keyboard walk '{sub}' matching spatial layout attacks."
                    })
                    break

        # 4. Year/Date pattern (1950 - 2030)
        year_match = re.search(r'(19\d\d|20[0-3]\d)', password)
        if year_match:
            patterns_found.append({
                "type": "DATE_OR_YEAR",
                "severity": "MEDIUM",
                "pattern": year_match.group(0),
                "message": f"Contains potential year or birthdate identifier '{year_match.group(0)}'."
            })

        # 5. Dictionary and Leetspeak word collision
        for word in COMMON_DICTIONARY:
            if word in normalized:
                patterns_found.append({
                    "type": "DICTIONARY_COLLISION",
                    "severity": "CRITICAL",
                    "pattern": word,
                    "message": f"Contains common dictionary or l33t-substituted word '{word}'."
                })
                break

        return patterns_found
