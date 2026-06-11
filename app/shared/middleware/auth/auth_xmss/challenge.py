from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from itertools import batched
from typing import Any

from app.shared.auth.schemas import AuthPathNode


class XMSSChallengeFactory:  # pragma: no cover
    """
    Utilidad base para challenge y verificación XMSS.

    Nota importante:
    Esto modela el flujo XMSS para integrarlo al backend.
    Para producción real se recomienda usar una implementación formal de XMSS.
    """

    def __init__(self, challenge_ttl_seconds: int = 120):
        self.challenge_ttl_seconds = challenge_ttl_seconds

    def create_challenge(
        self,
        *,
        entity_type: str,
        identifier: str,
        leaf_index: int,
        tree_height: int,
        public_root: str | None = None,
    ) -> dict[str, Any]:
        challenge = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + self.challenge_ttl_seconds

        client_material_compact = None

        if not public_root:
            sk_seed = secrets.token_hex(32)
            pub_seed = secrets.token_hex(32)
            tree = self._build_tree(sk_seed, tree_height)
            public_root = tree[-1][0]

            client_material_compact = {
                "sk_seed": sk_seed,
                "pub_seed": pub_seed,
                "tree_height": tree_height,
                "leaf_index": leaf_index,
                "note": "Guardar en cliente. El servidor solo conserva public_root e índice.",
            }

        canonical_message = self.build_canonical_message(
            entity_type=entity_type,
            identifier=identifier,
            challenge=challenge,
            leaf_index=leaf_index,
        )

        return {
            "entity_type": entity_type,
            "identifier": identifier,
            "challenge": challenge,
            "leaf_index": leaf_index,
            "expires_at": expires_at,
            "public_root": public_root,
            "canonical_message": canonical_message,
            "client_material_compact": client_material_compact,
        }

    def build_canonical_message(
        self,
        *,
        entity_type: str,
        identifier: str,
        challenge: str,
        leaf_index: int,
    ) -> dict[str, Any]:
        return {
            "auth_method": "auth_xmss",
            "entity_type": entity_type,
            "identifier": identifier,
            "challenge": challenge,
            "leaf_index": leaf_index,
        }

    def verify_payload(
        self,
        *,
        payload,
        public_root: str,
    ) -> bool:
        expected_message = self.build_canonical_message(
            entity_type=payload.entity_type,
            identifier=payload.identifier,
            challenge=payload.challenge,
            leaf_index=payload.leaf_index,
        )

        if not self._constant_time_json_equals(payload.message, expected_message):
            return False

        ots_public_key = self._extract_ots_public_key(payload)
        if not ots_public_key:
            return False

        reconstructed_root = self.reconstruct_root(
            ots_public_key=ots_public_key,
            auth_path=payload.auth_path,
        )

        return hmac.compare_digest(
            reconstructed_root,
            self._normalize(public_root),
        )

    def reconstruct_root(
        self,
        *,
        ots_public_key: str,
        auth_path: list[AuthPathNode],
    ) -> str:
        current = self._leaf_from_ots_public_key(ots_public_key)

        for node in auth_path:
            sibling = self._normalize(node.value)

            if node.position == "left":
                current = self._hash_hex(sibling + current)
            else:
                current = self._hash_hex(current + sibling)

        return current

    def _extract_ots_public_key(self, payload) -> str | None:
        if payload.ots_public_key:
            return payload.ots_public_key

        value = payload.signature.get("ots_public_key")
        if isinstance(value, str):
            return value

        return None

    def _build_tree(self, sk_seed: str, height: int) -> list[list[str]]:
        leaf_count = 2**height

        leaves = [
            self._leaf_from_ots_public_key(
                self._ots_public_key(sk_seed=sk_seed, index=index)
            )
            for index in range(leaf_count)
        ]

        levels = [leaves]
        current = leaves

        while len(current) > 1:
            next_level = [
                self._hash_hex(pair[0] + pair[-1])
                for pair in batched(current, 2)
            ]
            levels.append(next_level)
            current = next_level

        return levels

    def _ots_public_key(self, *, sk_seed: str, index: int) -> str:
        return self._hash_hex(f"WOTS+|{sk_seed}|{index}")

    def _leaf_from_ots_public_key(self, ots_public_key: str) -> str:
        return self._hash_hex(f"L_TREE|{self._normalize(ots_public_key)}")

    def _hash_hex(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _normalize(self, value: str) -> str:
        return value.strip().lower().replace("0x", "")

    def _json_bytes(self, value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def _constant_time_json_equals(
        self,
        first: dict[str, Any],
        second: dict[str, Any],
    ) -> bool:
        return hmac.compare_digest(
            self._json_bytes(first),
            self._json_bytes(second),
        )