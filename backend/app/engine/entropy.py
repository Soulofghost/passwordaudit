import math
import string
from collections import Counter
from typing import Dict, Any

class EntropyEngine:
    @staticmethod
    def calculate_shannon_entropy(password: str) -> float:
        """
        Calculates Shannon entropy per character:
        H = - sum(p * log2(p))
        """
        if not password:
            return 0.0
        length = len(password)
        counts = Counter(password)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def calculate_keyspace_entropy(password: str) -> Dict[str, Any]:
        """
        Calculates theoretical keyspace size and entropy in bits:
        Bits = L * log2(Charset_Size)
        """
        if not password:
            return {
                "length": 0,
                "charset_size": 0,
                "entropy_bits": 0.0,
                "has_lower": False,
                "has_upper": False,
                "has_digit": False,
                "has_symbol": False
            }

        length = len(password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation or (not c.isalnum() and not c.isspace()) for c in password)

        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32

        if charset_size == 0:
            charset_size = 1

        entropy_bits = length * math.log2(charset_size)

        return {
            "length": length,
            "charset_size": charset_size,
            "entropy_bits": round(entropy_bits, 2),
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_symbol": has_symbol
        }

    @staticmethod
    def estimate_crack_times(entropy_bits: float) -> Dict[str, str]:
        """
        Estimates time to crack based on combinations: 2^entropy_bits.
        Attacker scenarios:
        1. Online Throttled (100 per hour = ~0.028/sec)
        2. Online Fast (1,000 / sec)
        3. Offline Slow (10,000 / sec e.g. bcrypt/Argon2)
        4. Offline GPU Cluster (100,000,000,000 / sec e.g. NTLM / MD5 / fast hash)
        """
        combinations = 2 ** entropy_bits

        def format_time(seconds: float) -> str:
            if seconds < 1:
                return "Instantaneous (< 1 sec)"
            elif seconds < 60:
                return f"{round(seconds)} seconds"
            elif seconds < 3600:
                return f"{round(seconds / 60)} minutes"
            elif seconds < 86400:
                return f"{round(seconds / 3600)} hours"
            elif seconds < 31536000:
                return f"{round(seconds / 86400)} days"
            elif seconds < 31536000 * 1000:
                return f"{round(seconds / 31536000, 1)} years"
            elif seconds < 31536000 * 1000000:
                return f"{round(seconds / (31536000 * 1000))} thousand years"
            else:
                return "Centuries (Unbreakable by brute-force)"

        return {
            "online_throttled": format_time(combinations / 1.0),
            "online_fast": format_time(combinations / 1000.0),
            "offline_slow_hash": format_time(combinations / 10000.0),
            "offline_gpu_cluster": format_time(combinations / 100000000000.0)
        }
