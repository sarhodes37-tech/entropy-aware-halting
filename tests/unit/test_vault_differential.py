r"""
Differential Equivalence Tests for LocalMappingVault Optimizations.

Validates exact behavioral parity between the reference unoptimized implementation
and the optimized LocalMappingVault:
1. Rehydration Fast Path:
   - No placeholders in text.
   - One and multiple placeholders.
   - Repeated occurrences of the same placeholder.
   - Overlapping or prefix-related placeholders (e.g., PERSON_1 vs PERSON_10).
   - Placeholder-like text that does not constitute a valid match (e.g. PERSON_1abc).
   - Replacement values containing regex metacharacters and backslashes (\g<0>, \1, $1).
   - Replacement values that introduce another registered placeholder.
   - Empty strings and non-string inputs.
2. Case-Insensitive Pseudonym Lookup:
   - Exact matches.
   - Case-only variations (Alice vs alice vs ALICE).
   - Duplicate case-insensitive values (first-insertion precedence).
   - New pseudonym creation and counter increments.
   - Repeated lookups.
   - Mapping initialization, clear_session, and reconstruction.
   - Concurrent calls with ThreadPoolExecutor.
"""

import concurrent.futures
import secrets
import threading
from typing import Dict, Optional, Set

from epistemicos.shower_curtain.detector import SensitivityCategory, DetectionResult
from epistemicos.shower_curtain.vault import LocalMappingVault, _get_placeholder_pattern


class ReferenceLocalMappingVault:
    """
    Isolated reference implementation of pre-optimization LocalMappingVault.
    - Uses linear scan for case-insensitive lookup.
    - Does not perform literal substring pre-check in rehydrate().
    """

    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._forward_vault: Dict[str, Dict[str, str]] = {}
        self._reverse_vault: Dict[str, Dict[str, str]] = {}
        self._category_counters: Dict[str, Dict[str, int]] = {}

    def _generate_placeholder(
        self, session_id: str, category: SensitivityCategory
    ) -> str:
        if session_id not in self._category_counters:
            self._category_counters[session_id] = {}

        cat_key = category.value
        count = self._category_counters[session_id].get(cat_key, 0) + 1
        self._category_counters[session_id][cat_key] = count

        if category == SensitivityCategory.EMAIL:
            return f"EMAIL_{count}@sanitized.local"
        elif category == SensitivityCategory.NAME:
            return f"PERSON_{count}"
        elif category == SensitivityCategory.PHONE:
            return f"PHONE_NUMBER_{count}"
        elif category == SensitivityCategory.ADDRESS:
            return f"LOCATION_{count}"
        elif category == SensitivityCategory.CUSTOM_ENTITY:
            return f"ENTITY_{count}"
        elif category == SensitivityCategory.FILE_PATH:
            return f"FILE_PATH_{count}"
        elif category == SensitivityCategory.IP_ADDRESS:
            return f"IP_ADDRESS_{count}"
        else:
            return f"PLACEHOLDER_{cat_key}_{count}"

    def get_or_create_pseudonym(
        self, session_id: str, detection: DetectionResult
    ) -> str:
        if detection.category in (
            SensitivityCategory.CREDENTIAL,
            SensitivityCategory.FINANCIAL,
            SensitivityCategory.GOV_ID,
        ):
            raise ValueError(
                f"Category {detection.category.value} cannot be stored in reversible pseudonym vault."
            )

        with self._lock:
            if session_id not in self._forward_vault:
                self._forward_vault[session_id] = {}
                self._reverse_vault[session_id] = {}

            raw_val = detection.value
            # Original linear scan
            for existing_raw, placeholder in self._forward_vault[session_id].items():
                if existing_raw.lower() == raw_val.lower():
                    return placeholder

            placeholder = self._generate_placeholder(session_id, detection.category)
            self._forward_vault[session_id][raw_val] = placeholder
            self._reverse_vault[session_id][placeholder] = raw_val
            return placeholder

    def rehydrate(
        self,
        session_id: str,
        text: str,
        allowed_placeholders: Optional[Set[str]] = None,
    ) -> str:
        with self._lock:
            if not text or session_id not in self._reverse_vault:
                return text
            reverse_map = dict(self._reverse_vault[session_id])

        if not reverse_map:
            return text

        rehydrated = text
        sorted_placeholders = sorted(reverse_map.keys(), key=len, reverse=True)

        for placeholder in sorted_placeholders:
            if (
                allowed_placeholders is not None
                and placeholder not in allowed_placeholders
            ):
                continue

            raw_value = reverse_map[placeholder]
            pattern = _get_placeholder_pattern(placeholder)
            rehydrated = pattern.sub(lambda _: raw_value, rehydrated)

        return rehydrated

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._forward_vault.pop(session_id, None)
            self._reverse_vault.pop(session_id, None)
            self._category_counters.pop(session_id, None)


# =====================================================================
# 1. DIFFERENTIAL REHYDRATION EQUIVALENCE TESTS
# =====================================================================


def test_differential_rehydration_no_placeholders():
    """Validates rehydration parity when text contains zero placeholders."""
    master_key = b"A" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_no_p"
    for name in ["Alice", "Bob", "Charlie", "David"]:
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=name,
            span=(0, len(name)),
            confidence=1.0,
            detector_type="pattern",
        )
        p_ref = ref.get_or_create_pseudonym(sid, d)
        p_opt = opt.get_or_create_pseudonym(sid, d)
        assert p_ref == p_opt

    test_strings = [
        "The quick brown fox jumps over the lazy dog.",
        "System prompt instructions: 1 + 1 = 2.",
        "No entities here whatsoever, just normal operational text.",
        "1234567890 !@#$%^&*() _+ -=",
    ]
    for text in test_strings:
        assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_single_and_multiple_placeholders():
    """Validates rehydration parity with single and multiple placeholders."""
    master_key = b"B" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_mult_p"
    p1 = opt.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice",
            span=(0, 5),
            confidence=1.0,
            detector_type="p",
        ),
    )
    ref.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice",
            span=(0, 5),
            confidence=1.0,
            detector_type="p",
        ),
    )

    p2 = opt.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.EMAIL,
            value="alice@example.com",
            span=(0, 17),
            confidence=1.0,
            detector_type="p",
        ),
    )
    ref.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.EMAIL,
            value="alice@example.com",
            span=(0, 17),
            confidence=1.0,
            detector_type="p",
        ),
    )

    p3 = opt.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.PHONE,
            value="555-1234",
            span=(0, 8),
            confidence=1.0,
            detector_type="p",
        ),
    )
    ref.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.PHONE,
            value="555-1234",
            span=(0, 8),
            confidence=1.0,
            detector_type="p",
        ),
    )

    inputs = [
        f"Contact {p1} today.",
        f"Contact {p1} at {p2}.",
        f"Details: {p1}, email: {p2}, phone: {p3}.",
        f"Reverse order: {p3} belongs to {p1}.",
    ]
    for text in inputs:
        assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_repeated_occurrences():
    """Validates rehydration parity when the same placeholder occurs multiple times."""
    master_key = b"C" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_repeat"
    p1 = opt.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice Smith",
            span=(0, 11),
            confidence=1.0,
            detector_type="p",
        ),
    )
    ref.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice Smith",
            span=(0, 11),
            confidence=1.0,
            detector_type="p",
        ),
    )

    text = f"{p1} said hello. Then {p1} left. Later, {p1} returned to see {p1}."
    assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_overlapping_and_prefix_related_placeholders():
    """
    Validates rehydration parity with overlapping / prefix placeholders.
    e.g. PERSON_1 vs PERSON_10, PERSON_100.
    """
    master_key = b"D" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_prefix"
    # Create 15 PERSON placeholders so PERSON_1 and PERSON_10-PERSON_15 exist
    placeholders = []
    for i in range(1, 16):
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=f"Person_{i}",
            span=(0, 8),
            confidence=1.0,
            detector_type="p",
        )
        p_ref = ref.get_or_create_pseudonym(sid, d)
        p_opt = opt.get_or_create_pseudonym(sid, d)
        assert p_ref == p_opt
        placeholders.append(p_opt)

    # Text containing PERSON_10 adjacent to PERSON_1
    text = "Here is PERSON_10 and here is PERSON_1 and here is PERSON_15."
    assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_placeholder_like_text_non_matching():
    """
    Validates rehydration parity when text contains substring matching placeholder
    but without word boundaries, e.g. PERSON_1x or XPERSON_1.
    """
    master_key = b"E" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_fake"
    opt.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice",
            span=(0, 5),
            confidence=1.0,
            detector_type="p",
        ),
    )
    ref.get_or_create_pseudonym(
        sid,
        DetectionResult(
            category=SensitivityCategory.NAME,
            value="Alice",
            span=(0, 5),
            confidence=1.0,
            detector_type="p",
        ),
    )

    text = "PERSON_1x should not be replaced, nor should XPERSON_1 or PERSON_1_ABC or PERSON_10."
    assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)
    assert opt.rehydrate(sid, text) == text


def test_differential_rehydration_regex_metacharacters_and_backslashes():
    """
    Validates rehydration parity when replacement values contain backslashes,
    regex backreferences (\\1, \\g<0>), or group markers ($1).
    """
    master_key = b"F" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_regex_chars"
    tricky_values = [
        r"C:\Program Files\App\test.exe",
        r"\g<0> and \1 and \2",
        r"$1 $2 ${name}",
        r"[brackets] (parentheses) {braces} *stars* +plus+ ?question?",
    ]
    for val in tricky_values:
        d = DetectionResult(
            category=SensitivityCategory.FILE_PATH,
            value=val,
            span=(0, len(val)),
            confidence=1.0,
            detector_type="p",
        )
        ref.get_or_create_pseudonym(sid, d)
        opt.get_or_create_pseudonym(sid, d)

    text = "Paths: FILE_PATH_1 then FILE_PATH_2 then FILE_PATH_3 and FILE_PATH_4."
    assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_replacement_introducing_another_placeholder():
    """
    Validates rehydration parity when a raw value itself contains the text
    of another placeholder (cascading replacement check).
    """
    master_key = b"G" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_cascade"
    # PERSON_1 is "Alice PERSON_2"
    d1 = DetectionResult(
        category=SensitivityCategory.NAME,
        value="Alice PERSON_2",
        span=(0, 14),
        confidence=1.0,
        detector_type="p",
    )
    # PERSON_2 is "Bob"
    d2 = DetectionResult(
        category=SensitivityCategory.NAME,
        value="Bob",
        span=(0, 3),
        confidence=1.0,
        detector_type="p",
    )

    ref.get_or_create_pseudonym(sid, d1)
    ref.get_or_create_pseudonym(sid, d2)
    opt.get_or_create_pseudonym(sid, d1)
    opt.get_or_create_pseudonym(sid, d2)

    text = "Hello PERSON_1 and PERSON_2."
    assert opt.rehydrate(sid, text) == ref.rehydrate(sid, text)


def test_differential_rehydration_empty_and_edge_inputs():
    """Validates rehydration parity on empty strings and missing sessions."""
    master_key = b"H" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    assert opt.rehydrate("nonexistent_session", "Hello PERSON_1") == ref.rehydrate(
        "nonexistent_session", "Hello PERSON_1"
    )
    assert opt.rehydrate("nonexistent_session", "") == ref.rehydrate(
        "nonexistent_session", ""
    )
    assert opt.rehydrate("nonexistent_session", None) == ref.rehydrate(
        "nonexistent_session", None
    )


def test_differential_rehydration_allowed_placeholders_filter():
    """
    Validates explicit authorization filtering (allowed_placeholders):
    - allowed_placeholders=None (all authorized)
    - allowlist containing exactly one registered placeholder
    - empty allowlist set() (none authorized)
    - allowlist containing unknown or fabricated placeholders
    - multiple registered placeholders where only a subset is authorized
    Asserts exact string outputs and differential equivalence.
    """
    master_key = b"H_FILTER" * 4
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_auth_filter"
    # Register 3 distinct entities
    d1 = DetectionResult(
        category=SensitivityCategory.NAME,
        value="Alice",
        span=(0, 5),
        confidence=1.0,
        detector_type="p",
    )
    d2 = DetectionResult(
        category=SensitivityCategory.EMAIL,
        value="bob@example.com",
        span=(0, 15),
        confidence=1.0,
        detector_type="p",
    )
    d3 = DetectionResult(
        category=SensitivityCategory.PHONE,
        value="555-0199",
        span=(0, 8),
        confidence=1.0,
        detector_type="p",
    )

    p1 = opt.get_or_create_pseudonym(sid, d1)  # PERSON_1
    p2 = opt.get_or_create_pseudonym(sid, d2)  # EMAIL_1@sanitized.local
    p3 = opt.get_or_create_pseudonym(sid, d3)  # PHONE_NUMBER_1
    ref.get_or_create_pseudonym(sid, d1)
    ref.get_or_create_pseudonym(sid, d2)
    ref.get_or_create_pseudonym(sid, d3)

    template = f"Contact {p1} at {p2} or call {p3}."

    # 1. allowed_placeholders is None -> All authorized
    res_ref_none = ref.rehydrate(sid, template, allowed_placeholders=None)
    res_opt_none = opt.rehydrate(sid, template, allowed_placeholders=None)
    assert res_opt_none == res_ref_none
    assert res_opt_none == "Contact Alice at bob@example.com or call 555-0199."

    # 2. Allowlist containing exactly one registered placeholder (p1 only)
    res_ref_p1 = ref.rehydrate(sid, template, allowed_placeholders={p1})
    res_opt_p1 = opt.rehydrate(sid, template, allowed_placeholders={p1})
    assert res_opt_p1 == res_ref_p1
    assert res_opt_p1 == f"Contact Alice at {p2} or call {p3}."

    # 3. Empty allowlist set() -> Nothing rehydrated
    res_ref_empty = ref.rehydrate(sid, template, allowed_placeholders=set())
    res_opt_empty = opt.rehydrate(sid, template, allowed_placeholders=set())
    assert res_opt_empty == res_ref_empty
    assert res_opt_empty == template

    # 4. Allowlist containing only unknown or fabricated placeholders
    fabricated_allowlist = {"PERSON_999", "FABRICATED_PLACEHOLDER_1"}
    res_ref_fab = ref.rehydrate(
        sid, template, allowed_placeholders=fabricated_allowlist
    )
    res_opt_fab = opt.rehydrate(
        sid, template, allowed_placeholders=fabricated_allowlist
    )
    assert res_opt_fab == res_ref_fab
    assert res_opt_fab == template

    # 5. Allowlist containing a subset of valid placeholders plus fabricated ones (p2, p3 + unknown)
    mixed_allowlist = {p2, p3, "FABRICATED_TOKEN"}
    res_ref_mixed = ref.rehydrate(sid, template, allowed_placeholders=mixed_allowlist)
    res_opt_mixed = opt.rehydrate(sid, template, allowed_placeholders=mixed_allowlist)
    assert res_opt_mixed == res_ref_mixed
    assert res_opt_mixed == f"Contact {p1} at bob@example.com or call 555-0199."

    # 6. Verify that an unregistered placeholder in text is never substituted even if in allowlist
    text_with_unregistered = f"Hello {p1} and UNREGISTERED_1."
    res_opt_unreg = opt.rehydrate(
        sid, text_with_unregistered, allowed_placeholders={p1, "UNREGISTERED_1"}
    )
    res_ref_unreg = ref.rehydrate(
        sid, text_with_unregistered, allowed_placeholders={p1, "UNREGISTERED_1"}
    )
    assert res_opt_unreg == res_ref_unreg
    assert res_opt_unreg == "Hello Alice and UNREGISTERED_1."


# =====================================================================
# 2. DIFFERENTIAL CASE-INSENSITIVE LOOKUP TESTS
# =====================================================================


def test_differential_lookup_exact_and_case_variations():
    """Validates case-insensitive lookup parity across exact matches and casing variations."""
    master_key = b"I" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_lookup_case"
    names = ["Alice", "Bob", "charlie", "DAVID_JONES"]
    for name in names:
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=name,
            span=(0, len(name)),
            confidence=1.0,
            detector_type="p",
        )
        assert opt.get_or_create_pseudonym(sid, d) == ref.get_or_create_pseudonym(
            sid, d
        )

    # Test casing variations
    variations = [
        ("alice", "Alice"),
        ("ALICE", "Alice"),
        ("aLiCe", "Alice"),
        ("bOb", "Bob"),
        ("BOB", "Bob"),
        ("CHARLIE", "charlie"),
        ("david_jones", "DAVID_JONES"),
        ("David_Jones", "DAVID_JONES"),
    ]
    for variant, _ in variations:
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=variant,
            span=(0, len(variant)),
            confidence=1.0,
            detector_type="p",
        )
        res_opt = opt.get_or_create_pseudonym(sid, d)
        res_ref = ref.get_or_create_pseudonym(sid, d)
        assert res_opt == res_ref


def test_differential_lookup_duplicate_case_variations_precedence():
    """
    Validates that when multiple values differing only by case are added,
    both implementations preserve first-insertion precedence.
    """
    master_key = b"J" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_precedence"
    d_first = DetectionResult(
        category=SensitivityCategory.NAME,
        value="Administrator",
        span=(0, 13),
        confidence=1.0,
        detector_type="p",
    )
    p_opt1 = opt.get_or_create_pseudonym(sid, d_first)
    p_ref1 = ref.get_or_create_pseudonym(sid, d_first)
    assert p_opt1 == p_ref1

    d_second = DetectionResult(
        category=SensitivityCategory.NAME,
        value="administrator",
        span=(0, 13),
        confidence=1.0,
        detector_type="p",
    )
    p_opt2 = opt.get_or_create_pseudonym(sid, d_second)
    p_ref2 = ref.get_or_create_pseudonym(sid, d_second)
    assert p_opt2 == p_ref2
    assert p_opt2 == p_opt1


def test_differential_lookup_new_creation_and_reconstruction():
    """
    Validates counter synchronization, new pseudonym generation,
    and session clearing / reconstruction parity.
    """
    master_key = b"K" * 32
    ref = ReferenceLocalMappingVault(master_key=master_key)
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_reconstruct"
    for i in range(20):
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=f"User_{i}",
            span=(0, 7),
            confidence=1.0,
            detector_type="p",
        )
        assert opt.get_or_create_pseudonym(sid, d) == ref.get_or_create_pseudonym(
            sid, d
        )

    # Clear session on both
    ref.clear_session(sid)
    opt.clear_session(sid)

    # Reconstruct same session
    for i in range(20):
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=f"User_{i}",
            span=(0, 7),
            confidence=1.0,
            detector_type="p",
        )
        assert opt.get_or_create_pseudonym(sid, d) == ref.get_or_create_pseudonym(
            sid, d
        )


def test_differential_concurrent_access():
    """Validates thread safety and consistency of both implementations under concurrent load."""
    master_key = b"L" * 32
    opt = LocalMappingVault(master_key=master_key)

    sid = "sess_concurrent"

    def worker(val: str):
        d = DetectionResult(
            category=SensitivityCategory.NAME,
            value=val,
            span=(0, len(val)),
            confidence=1.0,
            detector_type="p",
        )
        return opt.get_or_create_pseudonym(sid, d)

    names = [f"name_{i % 10}" for i in range(100)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker, names))

    # All unique names (10 of them) must have exactly 1 unique placeholder
    unique_placeholders = set(results)
    assert len(unique_placeholders) == 10

    # Ensure internal vaults remain consistent
    with opt._lock:
        assert len(opt._forward_vault[sid]) == 10
        assert len(opt._forward_lower_vault[sid]) == 10
        assert len(opt._reverse_vault[sid]) == 10
        for k, v in opt._forward_vault[sid].items():
            assert opt._forward_lower_vault[sid][k.lower()] == v
            assert opt._reverse_vault[sid][v] == k
