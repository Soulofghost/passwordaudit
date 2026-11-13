import pytest
from backend.app.engine.entropy import EntropyEngine
from backend.app.engine.patterns import PatternEngine
from backend.app.engine.nist_evaluator import NISTEvaluator

def test_shannon_entropy_calculation():
    # Empty string has 0 entropy
    assert EntropyEngine.calculate_shannon_entropy("") == 0.0

    # Uniform string has 0 entropy (no variety)
    assert EntropyEngine.calculate_shannon_entropy("aaaaaaaa") == 0.0

    # Diverse string has higher Shannon entropy
    shannon = EntropyEngine.calculate_shannon_entropy("Ab9!kL2#")
    assert shannon > 2.5

def test_keyspace_entropy_and_charset():
    res = EntropyEngine.calculate_keyspace_entropy("Password123!")
    assert res["length"] == 12
    assert res["has_lower"] is True
    assert res["has_upper"] is True
    assert res["has_digit"] is True
    assert res["has_symbol"] is True
    assert res["charset_size"] == 26 + 26 + 10 + 32
    assert res["entropy_bits"] > 70.0

def test_crack_time_estimation():
    times_weak = EntropyEngine.estimate_crack_times(15.0)
    assert "Instantaneous" in times_weak["offline_gpu_cluster"]

    times_strong = EntropyEngine.estimate_crack_times(128.0)
    assert "Centuries" in times_strong["offline_gpu_cluster"]

def test_pattern_detection():
    # Detect sequential
    patterns_seq = PatternEngine.detect_patterns("abcxyz123")
    assert any(p["type"] == "SEQUENTIAL_SEQUENCE" for p in patterns_seq)

    # Detect keyboard walk
    patterns_kb = PatternEngine.detect_patterns("qwerty999")
    assert any(p["type"] == "KEYBOARD_WALK" for p in patterns_kb)

    # Detect dictionary word
    patterns_dict = PatternEngine.detect_patterns("admin2024")
    assert any(p["type"] == "DICTIONARY_COLLISION" for p in patterns_dict)

def test_nist_evaluator():
    patterns = PatternEngine.detect_patterns("admin")
    eval_bad = NISTEvaluator.evaluate("admin", patterns, 20.0)
    assert eval_bad["nist_compliant"] is False
    assert eval_bad["rating"] == "CRITICAL_RISK"

    long_passphrase = "correct-horse-battery-staple-2026"
    patterns_good = PatternEngine.detect_patterns(long_passphrase)
    eval_good = NISTEvaluator.evaluate(long_passphrase, patterns_good, 110.0)
    assert eval_good["nist_compliant"] is True
    assert eval_good["rating"] in ["STRONG", "EXCELLENT"]
