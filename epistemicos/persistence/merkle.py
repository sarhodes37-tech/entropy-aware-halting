"""
RFC 6962-Compatible Merkle Tree Primitives for EpistemicOS Persistence.

This module implements domain-separated cryptographic hashing and Merkle tree
primitives conforming to RFC 6962 Section 2.1:
  - Leaf Hash:        H_leaf = SHA-256(0x00 || data)
  - Internal Node:    H_node = SHA-256(0x01 || left || right)
  - Recursive Split:  For n > 1, split at k = 2^(floor(log2(n - 1)))
  - Empty Tree Root:  SHA-256(b"")
  - Single Leaf Root: H_leaf

Audit proof directions indicate the position of the sibling node:
  - 'R': Sibling is to the Right of the current path hash (H_node = Hash(0x01 || current || sibling))
  - 'L': Sibling is to the Left of the current path hash (H_node = Hash(0x01 || sibling || current))
The audit path sequence follows RFC 6962 Section 2.1.1, starting at the bottom (leaf sibling)
and ascending step-by-step to the root.
"""

import hashlib
from typing import List, Sequence, Tuple, Union

RFC6962_LEAF_PREFIX = b"\x00"
RFC6962_NODE_PREFIX = b"\x01"
HASH_LENGTH_BYTES = 32
EMPTY_TREE_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """
    Computes the RFC 6962 leaf hash for arbitrary input bytes.

    H_leaf = SHA-256(0x00 || data)

    Args:
        data: Raw byte string representing the leaf record.

    Returns:
        32-byte SHA-256 digest.

    Raises:
        TypeError: If data is not bytes or bytearray.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"leaf_hash data must be bytes or bytearray, got {type(data).__name__}")
    return hashlib.sha256(RFC6962_LEAF_PREFIX + bytes(data)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """
    Computes the RFC 6962 internal node hash from left and right child hashes.

    H_node = SHA-256(0x01 || left || right)

    Args:
        left: 32-byte binary digest of left child.
        right: 32-byte binary digest of right child.

    Returns:
        32-byte SHA-256 digest.

    Raises:
        TypeError: If left or right is not bytes or bytearray.
        ValueError: If left or right is not exactly 32 bytes long.
    """
    if not isinstance(left, (bytes, bytearray)):
        raise TypeError(f"left child must be bytes, got {type(left).__name__}")
    if not isinstance(right, (bytes, bytearray)):
        raise TypeError(f"right child must be bytes, got {type(right).__name__}")
    if len(left) != HASH_LENGTH_BYTES:
        raise ValueError(f"left child hash must be exactly 32 bytes, got {len(left)}")
    if len(right) != HASH_LENGTH_BYTES:
        raise ValueError(f"right child hash must be exactly 32 bytes, got {len(right)}")

    return hashlib.sha256(RFC6962_NODE_PREFIX + bytes(left) + bytes(right)).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Returns k = 2^(floor(log2(n - 1))), the largest power of 2 strictly less than n."""
    if n <= 1:
        raise ValueError("n must be > 1 to split")
    return 1 << ((n - 1).bit_length() - 1)


def merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    """
    Calculates the Merkle Tree Hash (MTH) for a sequence of already-hashed leaves.

    Following RFC 6962 Section 2.1:
      - If n == 0, returns SHA-256(b"").
      - If n == 1, returns leaves[0].
      - If n > 1, splits at k = largest power of 2 < n.

    Args:
        leaves: Sequence of 32-byte leaf hashes.

    Returns:
        32-byte root hash.

    Raises:
        TypeError: If leaves is not a sequence or elements are not bytes.
        ValueError: If any leaf hash is not 32 bytes.
    """
    if not isinstance(leaves, (list, tuple)):
        raise TypeError(f"leaves must be a sequence of bytes, got {type(leaves).__name__}")

    n = len(leaves)
    if n == 0:
        return EMPTY_TREE_ROOT

    for idx, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)):
            raise TypeError(f"Leaf at index {idx} must be bytes, got {type(leaf).__name__}")
        if len(leaf) != HASH_LENGTH_BYTES:
            raise ValueError(f"Leaf at index {idx} must be 32 bytes, got {len(leaf)}")

    if n == 1:
        return bytes(leaves[0])

    k = _largest_power_of_two_less_than(n)
    left_root = merkle_tree_hash(leaves[:k])
    right_root = merkle_tree_hash(leaves[k:])
    return node_hash(left_root, right_root)


def generate_inclusion_proof(
    leaf_index: int,
    leaves: Sequence[bytes],
) -> List[Tuple[str, str]]:
    """
    Generates an RFC 6962 inclusion proof (audit path) for the leaf at leaf_index.
    The proof starts from the leaf (bottom) and ascends to the root.

    Args:
        leaf_index: 0-based index of the leaf.
        leaves: Sequence of 32-byte leaf hashes.

    Returns:
        List of (direction, sibling_hex) tuples:
          - direction is 'R' if the sibling is on the right of the path.
          - direction is 'L' if the sibling is on the left of the path.
          - sibling_hex is the 64-char lowercase hexadecimal string of the sibling hash.

    Raises:
        TypeError: If inputs are of invalid types.
        ValueError: If leaf_index is out of range or tree is empty.
    """
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise TypeError(f"leaf_index must be an int, got {type(leaf_index).__name__}")
    if not isinstance(leaves, (list, tuple)):
        raise TypeError(f"leaves must be a list or tuple, got {type(leaves).__name__}")

    n = len(leaves)
    if n <= 0:
        raise ValueError("Cannot generate inclusion proof for an empty tree")
    if leaf_index < 0 or leaf_index >= n:
        raise ValueError(f"leaf_index {leaf_index} out of bounds for tree size {n}")

    for idx, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)):
            raise TypeError(f"Leaf at index {idx} must be bytes, got {type(leaf).__name__}")
        if len(leaf) != HASH_LENGTH_BYTES:
            raise ValueError(f"Leaf at index {idx} must be 32 bytes, got {len(leaf)}")

    if n == 1:
        return []

    k = _largest_power_of_two_less_than(n)
    if leaf_index < k:
        path = generate_inclusion_proof(leaf_index, leaves[:k])
        right_sibling_root = merkle_tree_hash(leaves[k:])
        path.append(("R", right_sibling_root.hex()))
        return path
    else:
        path = generate_inclusion_proof(leaf_index - k, leaves[k:])
        left_sibling_root = merkle_tree_hash(leaves[:k])
        path.append(("L", left_sibling_root.hex()))
        return path


def _get_path_directions(leaf_index: int, tree_size: int) -> List[str]:
    """
    Computes the sequence of expected sibling directions for a leaf in an RFC 6962 tree,
    ordered from bottom (leaf level, index 0) to top (subroot level).
    """
    if tree_size <= 1:
        return []
    k = _largest_power_of_two_less_than(tree_size)
    if leaf_index < k:
        return _get_path_directions(leaf_index, k) + ["R"]
    else:
        return _get_path_directions(leaf_index - k, tree_size - k) + ["L"]


def verify_inclusion_proof(
    leaf_index: int,
    tree_size: int,
    leaf_input: Union[bytes, str],
    audit_path: Sequence[Tuple[str, str]],
    expected_root: Union[bytes, str],
    is_leaf_hash: bool = False,
) -> bool:
    """
    Verifies an RFC 6962 inclusion proof.

    Args:
        leaf_index: 0-based index of the leaf in the tree.
        tree_size: Total number of leaves in the tree.
        leaf_input: Either raw leaf bytes (if is_leaf_hash=False) or 32-byte leaf hash / hex string (if is_leaf_hash=True).
        audit_path: Sequence of (direction, sibling_hex) tuples from leaf level to root.
        expected_root: 32-byte expected root digest or 64-char hex string.
        is_leaf_hash: If True, leaf_input is treated directly as the 32-byte leaf hash.
                      If False, leaf_input is hashed via leaf_hash(leaf_input).

    Returns:
        True if the proof strictly reproduces expected_root; False if structurally valid but root mismatches.

    Raises:
        TypeError: If parameter types are invalid.
        ValueError: If parameters violate numerical bounds, hash lengths, hex encoding, or proof structure.
    """
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise TypeError(f"leaf_index must be int, got {type(leaf_index).__name__}")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        raise TypeError(f"tree_size must be int, got {type(tree_size).__name__}")
    if not isinstance(audit_path, (list, tuple)):
        raise TypeError(f"audit_path must be list or tuple, got {type(audit_path).__name__}")

    if tree_size <= 0:
        raise ValueError(f"tree_size must be >= 1, got {tree_size}")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError(f"leaf_index {leaf_index} out of bounds for tree_size {tree_size}")

    # Parse and validate expected root
    if isinstance(expected_root, str):
        try:
            expected_root_bytes = bytes.fromhex(expected_root)
        except ValueError as exc:
            raise ValueError(f"expected_root hex is malformed: {exc}") from exc
    elif isinstance(expected_root, (bytes, bytearray)):
        expected_root_bytes = bytes(expected_root)
    else:
        raise TypeError(f"expected_root must be bytes or hex str, got {type(expected_root).__name__}")

    if len(expected_root_bytes) != HASH_LENGTH_BYTES:
        raise ValueError(f"expected_root must be exactly 32 bytes, got {len(expected_root_bytes)}")

    # Parse and validate current leaf hash
    if is_leaf_hash:
        if isinstance(leaf_input, str):
            try:
                current_hash = bytes.fromhex(leaf_input)
            except ValueError as exc:
                raise ValueError(f"leaf_input hex is malformed: {exc}") from exc
        elif isinstance(leaf_input, (bytes, bytearray)):
            current_hash = bytes(leaf_input)
        else:
            raise TypeError(f"leaf_input must be bytes or hex str, got {type(leaf_input).__name__}")

        if len(current_hash) != HASH_LENGTH_BYTES:
            raise ValueError(f"leaf_input hash must be exactly 32 bytes, got {len(current_hash)}")
    else:
        if not isinstance(leaf_input, (bytes, bytearray)):
            raise TypeError(f"leaf_input must be bytes when is_leaf_hash=False, got {type(leaf_input).__name__}")
        current_hash = leaf_hash(bytes(leaf_input))

    # Deconstruct expected path directions according to RFC 6962
    expected_directions = _get_path_directions(leaf_index, tree_size)
    if len(audit_path) != len(expected_directions):
        return False

    for path_idx, (step, expected_dir) in enumerate(zip(audit_path, expected_directions)):
        if not isinstance(step, (list, tuple)) or len(step) != 2:
            raise ValueError(f"Audit step at index {path_idx} must be a 2-tuple (direction, sibling)")

        direction, sibling_val = step
        if direction not in ("L", "R"):
            raise ValueError(f"Audit step direction must be 'L' or 'R', got {direction!r}")

        if isinstance(sibling_val, str):
            try:
                sibling_bytes = bytes.fromhex(sibling_val)
            except ValueError as exc:
                raise ValueError(f"Sibling hash at step {path_idx} is malformed hex: {exc}") from exc
        elif isinstance(sibling_val, (bytes, bytearray)):
            sibling_bytes = bytes(sibling_val)
        else:
            raise TypeError(f"Sibling hash at step {path_idx} must be hex str or bytes, got {type(sibling_val).__name__}")

        if len(sibling_bytes) != HASH_LENGTH_BYTES:
            raise ValueError(f"Sibling hash at step {path_idx} must be 32 bytes, got {len(sibling_bytes)}")

        if direction != expected_dir:
            return False

        if direction == "R":
            current_hash = node_hash(current_hash, sibling_bytes)
        else:
            current_hash = node_hash(sibling_bytes, current_hash)

    return current_hash == expected_root_bytes
