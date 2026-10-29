"""
Stage C: Consistent Pseudonymization and Local Mapping Vault for Shower Curtain.

Implements a local, session-scoped mapping vault supporting consistent
entity substitution and authorized rehydration while strictly prohibiting
credentials and preventing cross-session correlation.
"""

import re
import hmac
import hashlib
import secrets
import threading
import functools
from pathlib import Path
from typing import Dict, Optional, Set
from typing import Dict, Any, Optional, Set
from epistemicos.shower_curtain.detector import SensitivityCategory, DetectionResult


class VaultAccessError(Exception):
    """Raised when access to a vault persistence resource is denied or fails."""
    pass


@functools.lru_cache(maxsize=2048)
def _get_placeholder_pattern(placeholder: str) -> re.Pattern:
    """Compiles and caches word-boundary regex patterns for placeholders."""
    return re.compile(r"\b" + re.escape(placeholder) + r"\b")


class LocalMappingVault:
    """
    Session-scoped, local-first entity mapping vault.

    Protections:
    - Secrets/credentials are NEVER stored or rehydrated.
    - Session isolation: Mapping tables are scoped strictly by session_id.
    - Rehydration protection: Only valid, registered session placeholders can be rehydrated.
    """

    def __init__(
        self,
        master_key: Optional[bytes] = None,
        persistence_dir: Optional[str] = None
    ):
        self.master_key = master_key or secrets.token_bytes(32)
        self.persistence_dir = Path(persistence_dir) if persistence_dir else None
        if self.persistence_dir:
            self.persistence_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        # Structure: session_id -> { raw_value: placeholder }
        self._forward_vault: Dict[str, Dict[str, str]] = {}
        # Structure: session_id -> { placeholder: raw_value }
        self._reverse_vault: Dict[str, Dict[str, str]] = {}
        # Counters per session: session_id -> { category_str: int }
        self._category_counters: Dict[str, Dict[str, int]] = {}

    def _get_session_key(self, session_id: str) -> bytes:
        """Derives a session-specific HMAC key using master key."""
        return hmac.new(self.master_key, session_id.encode("utf-8"), hashlib.sha256).digest()

    def _generate_placeholder(self, session_id: str, category: SensitivityCategory) -> str:
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
        self,
        session_id: str,
        detection: DetectionResult
    ) -> str:
        # INVARIANT: Credentials and Secrets MUST NEVER be stored in the vault
        if detection.category in (SensitivityCategory.CREDENTIAL, SensitivityCategory.FINANCIAL, SensitivityCategory.GOV_ID):
            raise ValueError(f"Category {detection.category.value} cannot be stored in reversible pseudonym vault.")

        with self._lock:
            if session_id not in self._forward_vault:
                self._forward_vault[session_id] = {}
                self._reverse_vault[session_id] = {}

            raw_val = detection.value
            # Check if already mapped in session
            for existing_raw, placeholder in self._forward_vault[session_id].items():
                if existing_raw.lower() == raw_val.lower():
                    return placeholder

            # Generate new placeholder
            placeholder = self._generate_placeholder(session_id, detection.category)
            self._forward_vault[session_id][raw_val] = placeholder
            self._reverse_vault[session_id][placeholder] = raw_val

            return placeholder

    def get_session_placeholders(self, session_id: str) -> Set[str]:
        """Returns the set of registered placeholders for a session."""
        with self._lock:
            if session_id in self._reverse_vault:
                return set(self._reverse_vault[session_id].keys())
            return set()

    def rehydrate(
        self,
        session_id: str,
        text: str,
        allowed_placeholders: Optional[Set[str]] = None
    ) -> str:
        """
        Safely restores authorized local placeholders in text.
        Rejects unmapped or fabricated placeholders.
        """
        with self._lock:
            if not text or session_id not in self._reverse_vault:
                return text

            reverse_map = dict(self._reverse_vault[session_id])

        if not reverse_map:
            return text

        rehydrated = text
        # Sort placeholders by length descending to prevent partial substring collisions
        sorted_placeholders = sorted(reverse_map.keys(), key=len, reverse=True)

        for placeholder in sorted_placeholders:
            if allowed_placeholders is not None and placeholder not in allowed_placeholders:
                continue

            raw_value = reverse_map[placeholder]
            # Replace placeholder safely using regex word-boundary to prevent partial substring replacements.
            # Uses a lambda repl function to avoid regex backreference expansion/injection (e.g., \g<0> or \1) in raw_value.
            pattern = _get_placeholder_pattern(placeholder)
            rehydrated = pattern.sub(lambda _: raw_value, rehydrated)

        return rehydrated

    def load_from_file(self, path: str) -> bytes:
        """
        Reads raw binary vault data from the specified path.
        Raises VaultAccessError if a PermissionError is encountered.
        """
        try:
            with open(path, 'rb') as f:
                return f.read()
        except PermissionError as e:
            raise VaultAccessError(f"Access denied: {e}")

    def clear_session(self, session_id: str) -> None:
        """Wipes all mapping data for a given session."""
        with self._lock:
            self._forward_vault.pop(session_id, None)
            self._reverse_vault.pop(session_id, None)
            self._category_counters.pop(session_id, None)
