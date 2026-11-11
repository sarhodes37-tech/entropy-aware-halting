"""
Unit Tests for RFC 6962-Compatible Merkle Tree Primitives.
Baseline: EpistemicOS Persistence Architecture Specification v5.1.1 (Phase 1).
"""

import hashlib
import pytest
from epistemicos.persistence.merkle import (
    leaf_hash,
    node_hash,
    merkle_tree_hash,
    generate_inclusion_proof,
    verify_inclusion_proof,
    EMPTY_TREE_ROOT,
)

# Reference known-answer test vectors independently derived:
# Inputs D_i = bytes([i] * 32) for i = 0..6
LEAVES_DATA = [bytes([i] * 32) for i in range(7)]

# Independently calculated leaf hashes using SHA-256(0x00 || D_i):
EXPECTED_LEAF_HASHES = [
    "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9",  # L_0
    "dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e",  # L_1
    "cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa",  # L_2
    "acaa04663a8547a2f70c60cc18f9378796b13c4f9a08f70d6adae662365b30c6",  # L_3
    "1da033bf8927ed69376d91533748494f7f5e88c20603dede2afc9bfd43d46f17",  # L_4
    "f3ab555d06a67b08ab25039fdbe2a6fcb305c83bc165492ce81d3dea13ec1fbf",  # L_5
    "511c6562982c9bfa05ba4145ca5f2bba85a11a178a4131b5cebde26dd9ffe704",  # L_6
]

# Independently calculated tree roots across sizes N in {0, 1, 2, 3, 5, 7}:
EXPECTED_ROOTS = {
    0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    1: "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9",
    2: "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444",
    3: "ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620",
    5: "85e20cac1f02fda7bcdb2fc3f908568c57018c77815f1fa361acad13994f08bf",
    7: "7318881c41fce3c1de3640df8e8c110c93f43f686b74204a9d1ad5b8c71c2047",
}


def test_leaf_hashes_match_independent_calculation():
    """Verify each D_i hashes strictly to the expected RFC 6962 leaf hash."""
    for i, data in enumerate(LEAVES_DATA):
        lh = leaf_hash(data)
        assert lh.hex() == EXPECTED_LEAF_HASHES[i]


def test_node_hash_properties():
    """Verify domain separation and input length validation for internal nodes."""
    h1 = bytes.fromhex(EXPECTED_LEAF_HASHES[0])
    h2 = bytes.fromhex(EXPECTED_LEAF_HASHES[1])

    # Direct formula check: SHA256(0x01 || h1 || h2)
    expected = hashlib.sha256(b"\x01" + h1 + h2).digest()
    assert node_hash(h1, h2) == expected

    # Validation: non-bytes
    with pytest.raises(TypeError):
        node_hash("not_bytes", h2)  # type: ignore

    # Validation: bad length
    with pytest.raises(ValueError):
        node_hash(b"short", h2)
    with pytest.raises(ValueError):
        node_hash(h1, b"x" * 33)


def test_merkle_tree_hash_roots():
    """Verify complete tree roots across N = 0, 1, 2, 3, 5, 7."""
    leaves = [bytes.fromhex(h) for h in EXPECTED_LEAF_HASHES]

    for n, expected_hex in EXPECTED_ROOTS.items():
        root = merkle_tree_hash(leaves[:n])
        assert root.hex() == expected_hex


def test_inclusion_proof_vectors_positive():
    """
    Verify all required inclusion proof test cases from v5.1.1:
      - N=1, index=0
      - N=2, index=0 and index=1
      - N=3, index=0 and index=2
      - N=5, index=4
      - N=7, index=5
    """
    leaves = [bytes.fromhex(h) for h in EXPECTED_LEAF_HASHES]

    test_cases = [
        (1, 0),
        (2, 0),
        (2, 1),
        (3, 0),
        (3, 2),
        (5, 4),
        (7, 5),
    ]

    for n, idx in test_cases:
        expected_root_hex = EXPECTED_ROOTS[n]
        proof = generate_inclusion_proof(idx, leaves[:n])

        # Test verification from raw leaf bytes
        assert verify_inclusion_proof(
            leaf_index=idx,
            tree_size=n,
            leaf_input=LEAVES_DATA[idx],
            audit_path=proof,
            expected_root=expected_root_hex,
            is_leaf_hash=False,
        )

        # Test verification directly from leaf hash
        assert verify_inclusion_proof(
            leaf_index=idx,
            tree_size=n,
            leaf_input=EXPECTED_LEAF_HASHES[idx],
            audit_path=proof,
            expected_root=expected_root_hex,
            is_leaf_hash=True,
        )


def test_empty_tree_proof_rejection():
    """Verify inclusion proofs cannot be generated or verified for empty trees."""
    with pytest.raises(ValueError, match="empty tree"):
        generate_inclusion_proof(0, [])

    with pytest.raises(ValueError, match="tree_size must be >= 1"):
        verify_inclusion_proof(0, 0, b"data", [], EXPECTED_ROOTS[0])


def test_out_of_bounds_leaf_indices():
    """Verify out-of-range leaf indices are rejected."""
    leaves = [bytes.fromhex(h) for h in EXPECTED_LEAF_HASHES[:3]]

    with pytest.raises(ValueError, match="out of bounds"):
        generate_inclusion_proof(-1, leaves)

    with pytest.raises(ValueError, match="out of bounds"):
        generate_inclusion_proof(3, leaves)

    with pytest.raises(ValueError, match="out of bounds"):
        verify_inclusion_proof(-1, 3, LEAVES_DATA[0], [], EXPECTED_ROOTS[3])

    with pytest.raises(ValueError, match="out of bounds"):
        verify_inclusion_proof(3, 3, LEAVES_DATA[0], [], EXPECTED_ROOTS[3])


def test_malformed_proof_inputs():
    """Verify deterministic rejection of malformed proof parameters."""
    root = EXPECTED_ROOTS[2]

    # Malformed direction
    with pytest.raises(ValueError, match="direction must be 'L' or 'R'"):
        verify_inclusion_proof(0, 2, LEAVES_DATA[0], [("X", EXPECTED_LEAF_HASHES[1])], root)

    # Malformed sibling hex
    with pytest.raises(ValueError, match="malformed hex"):
        verify_inclusion_proof(0, 2, LEAVES_DATA[0], [("R", "not_a_hex_string_zz")], root)

    # Invalid sibling length
    with pytest.raises(ValueError, match="must be 32 bytes"):
        verify_inclusion_proof(0, 2, LEAVES_DATA[0], [("R", "1234")], root)

    # Malformed expected_root hex
    with pytest.raises(ValueError, match="expected_root hex is malformed"):
        verify_inclusion_proof(0, 2, LEAVES_DATA[0], [("R", EXPECTED_LEAF_HASHES[1])], "invalid_root_hex")

    # Invalid root byte length
    with pytest.raises(ValueError, match="expected_root must be exactly 32 bytes"):
        verify_inclusion_proof(0, 2, LEAVES_DATA[0], [("R", EXPECTED_LEAF_HASHES[1])], "00" * 31)


def test_mutated_and_tampered_proofs():
    """Verify that structurally valid proofs with tampered siblings or swapped directions evaluate to False."""
    leaves = [bytes.fromhex(h) for h in EXPECTED_LEAF_HASHES[:3]]
    valid_proof = generate_inclusion_proof(2, leaves)
    root = EXPECTED_ROOTS[3]

    # Mutated sibling hash
    mutated_sibling = "ff" * 32
    tampered_proof = [("L", mutated_sibling)]
    assert not verify_inclusion_proof(2, 3, LEAVES_DATA[2], tampered_proof, root)

    # Wrong direction
    swapped_dir_proof = [("R", valid_proof[0][1])]
    assert not verify_inclusion_proof(2, 3, LEAVES_DATA[2], swapped_dir_proof, root)

    # Truncated proof (empty proof for tree of size 3)
    assert not verify_inclusion_proof(2, 3, LEAVES_DATA[2], [], root)

    # Extraneous proof element
    extra_node_proof = list(valid_proof) + [("R", EXPECTED_LEAF_HASHES[0])]
    assert not verify_inclusion_proof(2, 3, LEAVES_DATA[2], extra_node_proof, root)


def test_non_power_of_two_trees():
    """Verify proof generation and verification across non-power-of-two trees: N = 3, 5, 6."""
    leaves = [bytes.fromhex(h) for h in EXPECTED_LEAF_HASHES[:6]]

    for n in (3, 5, 6):
        tree_leaves = leaves[:n]
        tree_root = merkle_tree_hash(tree_leaves).hex()
        for i in range(n):
            proof = generate_inclusion_proof(i, tree_leaves)
            assert verify_inclusion_proof(i, n, LEAVES_DATA[i], proof, tree_root)
