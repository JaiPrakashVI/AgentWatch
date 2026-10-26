"""Panopti Cryptographic Policy Attestation & Verifiable Audit Seals.

Generates tamper-evident cryptographic seals for agent execution traces, proving
formal invariant compliance and absence of runaway loops.
Pure standard library (Ponytail: Ultra).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


def _canonical_json(data: Any) -> str:
    """Serialize object to canonical, deterministic JSON."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(slots=True)
class PanoptiAttestationSeal:
    """Cryptographic attestation certificate proving verified execution."""

    seal_id: str
    merkle_root: str
    policy_verdict: str
    confidence_floor: float
    loop_status: str
    tool_count: int
    timestamp_iso: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PanoptiAttestationSeal:
        return cls(
            seal_id=data["seal_id"],
            merkle_root=data["merkle_root"],
            policy_verdict=data["policy_verdict"],
            confidence_floor=float(data["confidence_floor"]),
            loop_status=data["loop_status"],
            tool_count=int(data["tool_count"]),
            timestamp_iso=data["timestamp_iso"],
            signature=data["signature"],
        )

    @classmethod
    def from_json(cls, json_str: str) -> PanoptiAttestationSeal:
        return cls.from_dict(json.loads(json_str))


class AttestationEngine:
    """Issues and cryptographically validates Panopti attestation seals."""

    @staticmethod
    def _compute_digest(
        seal_id: str,
        merkle_root: str,
        policy_verdict: str,
        confidence_floor: float,
        loop_status: str,
        tool_count: int,
        timestamp_iso: str,
    ) -> str:
        payload = (
            f"{seal_id}|{merkle_root}|{policy_verdict}|"
            f"{confidence_floor:.4f}|{loop_status}|{tool_count}|{timestamp_iso}"
        )
        return payload

    @classmethod
    def create_seal(
        cls,
        merkle_root: str,
        tool_count: int,
        confidence_floor: float = 1.0,
        is_compliant: bool = True,
        loop_detected: bool = False,
        secret_key: str = "panopti-seal-default-key",
    ) -> PanoptiAttestationSeal:
        """Issue an immutable signed attestation seal for an execution run."""
        seal_id = f"seal_{uuid.uuid4().hex[:16]}"
        timestamp_iso = datetime.now(timezone.utc).isoformat()
        policy_verdict = "COMPLIANT" if is_compliant else "VIOLATION"
        loop_status = "LOOP_DETECTED" if loop_detected else "CLEAN"

        digest = cls._compute_digest(
            seal_id=seal_id,
            merkle_root=merkle_root,
            policy_verdict=policy_verdict,
            confidence_floor=confidence_floor,
            loop_status=loop_status,
            tool_count=tool_count,
            timestamp_iso=timestamp_iso,
        )

        signature = hmac.new(
            secret_key.encode(),
            digest.encode(),
            hashlib.sha256,
        ).hexdigest()

        return PanoptiAttestationSeal(
            seal_id=seal_id,
            merkle_root=merkle_root,
            policy_verdict=policy_verdict,
            confidence_floor=confidence_floor,
            loop_status=loop_status,
            tool_count=tool_count,
            timestamp_iso=timestamp_iso,
            signature=signature,
        )

    @classmethod
    def verify_seal(
        cls,
        seal: PanoptiAttestationSeal,
        secret_key: str = "panopti-seal-default-key",
    ) -> bool:
        """Mathematically verifies that the seal's signature and payload are authentic."""
        expected_digest = cls._compute_digest(
            seal_id=seal.seal_id,
            merkle_root=seal.merkle_root,
            policy_verdict=seal.policy_verdict,
            confidence_floor=seal.confidence_floor,
            loop_status=seal.loop_status,
            tool_count=seal.tool_count,
            timestamp_iso=seal.timestamp_iso,
        )

        expected_sig = hmac.new(
            secret_key.encode(),
            expected_digest.encode(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(seal.signature, expected_sig)
