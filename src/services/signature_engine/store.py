"""
In-memory fingerprint store.

In production this would be backed by PostgreSQL (Module 12 in the
architecture).  For now the store lives in-memory so Module 6 can
operate without an external database while the PostgreSQL infra layer
is not yet wired up.

Each stored record holds the fingerprint hash, the MITRE mapping, a
pre-computed risk score, and an optional playbook ID — everything the
Known Attack Path needs to short-circuit the heavy ML pipeline.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional

from shared.logger import get_logger

logger = get_logger("signature.store")


@dataclass
class StoredSignature:
    """A previously observed attack pattern."""

    fingerprint: str
    event_type: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_confidence: float = 0.0
    risk_score: float = 0.0
    risk_level: str = "low"
    playbook_id: Optional[str] = None
    hit_count: int = 0


class SignatureStore:
    """Thread-safe (GIL-protected) dictionary-backed fingerprint store."""

    def __init__(self) -> None:
        self._signatures: Dict[str, StoredSignature] = {}

    def lookup(self, fingerprint: str) -> Optional[StoredSignature]:
        """Return the stored signature if a match exists, else None."""
        sig = self._signatures.get(fingerprint)
        if sig is not None:
            sig.hit_count += 1
            logger.info(
                "fingerprint=%s matched (hits=%d)",
                fingerprint[:16],
                sig.hit_count,
            )
        return sig

    def store(self, signature: StoredSignature) -> None:
        """Persist a new signature for future lookups."""
        self._signatures[signature.fingerprint] = signature
        logger.info(
            "stored fingerprint=%s type=%s",
            signature.fingerprint[:16],
            signature.event_type,
        )

    @property
    def size(self) -> int:
        return len(self._signatures)

    # ------------------------------------------------------------------
    # Bootstrap: pre-load well-known attack patterns so the engine has
    # historical context even on first boot.
    # ------------------------------------------------------------------
    def seed_known_patterns(self) -> None:
        """Insert canonical attack signatures for common threat types."""
        _SEEDS = [
            StoredSignature(
                fingerprint=_fp("failed_login", "high", "external", "repeated_failures", "high_frequency", "odd_hour"),
                event_type="failed_login",
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                mitre_tactic="Credential Access",
                mitre_confidence=0.92,
                risk_score=0.95,
                risk_level="critical",
                playbook_id="PB-BRUTE-001",
            ),
            StoredSignature(
                fingerprint=_fp("failed_login", "high", "external", "repeated_failures", "high_frequency"),
                event_type="failed_login",
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                mitre_tactic="Credential Access",
                mitre_confidence=0.85,
                risk_score=0.88,
                risk_level="high",
                playbook_id="PB-BRUTE-001",
            ),
            StoredSignature(
                fingerprint=_fp("privilege_escalation", "high", "internal"),
                event_type="privilege_escalation",
                mitre_technique_id="T1068",
                mitre_technique_name="Exploitation for Privilege Escalation",
                mitre_tactic="Privilege Escalation",
                mitre_confidence=0.88,
                risk_score=0.90,
                risk_level="critical",
                playbook_id="PB-PRIVESC-001",
            ),
            StoredSignature(
                fingerprint=_fp("c2_communication", "high", "external", "beaconing"),
                event_type="c2_communication",
                mitre_technique_id="T1071",
                mitre_technique_name="Application Layer Protocol",
                mitre_tactic="Command and Control",
                mitre_confidence=0.90,
                risk_score=0.93,
                risk_level="critical",
                playbook_id="PB-C2-001",
            ),
            StoredSignature(
                fingerprint=_fp("c2_communication", "high", "external", "beaconing", "odd_hour"),
                event_type="c2_communication",
                mitre_technique_id="T1071",
                mitre_technique_name="Application Layer Protocol",
                mitre_tactic="Command and Control",
                mitre_confidence=0.92,
                risk_score=0.95,
                risk_level="critical",
                playbook_id="PB-C2-001",
            ),
            StoredSignature(
                fingerprint=_fp("privilege_escalation", "high", "internal", "odd_hour"),
                event_type="privilege_escalation",
                mitre_technique_id="T1068",
                mitre_technique_name="Exploitation for Privilege Escalation",
                mitre_tactic="Privilege Escalation",
                mitre_confidence=0.92,
                risk_score=0.95,
                risk_level="critical",
                playbook_id="PB-PRIVESC-001",
            ),
            StoredSignature(
                fingerprint=_fp("lateral_movement", "high", "internal", "odd_hour"),
                event_type="lateral_movement",
                mitre_technique_id="T1021",
                mitre_technique_name="Remote Services",
                mitre_tactic="Lateral Movement",
                mitre_confidence=0.88,
                risk_score=0.90,
                risk_level="critical",
                playbook_id="PB-LATERAL-001",
            ),
            StoredSignature(
                fingerprint=_fp("data_exfiltration", "high", "external", "odd_hour"),
                event_type="data_exfiltration",
                mitre_technique_id="T1041",
                mitre_technique_name="Exfiltration Over C2 Channel",
                mitre_tactic="Exfiltration",
                mitre_confidence=0.90,
                risk_score=0.95,
                risk_level="critical",
                playbook_id="PB-EXFIL-001",
            ),
            StoredSignature(
                fingerprint=_fp("lateral_movement", "high", "internal"),
                event_type="lateral_movement",
                mitre_technique_id="T1021",
                mitre_technique_name="Remote Services",
                mitre_tactic="Lateral Movement",
                mitre_confidence=0.82,
                risk_score=0.85,
                risk_level="high",
                playbook_id="PB-LATERAL-001",
            ),
            StoredSignature(
                fingerprint=_fp("data_exfiltration", "high", "external"),
                event_type="data_exfiltration",
                mitre_technique_id="T1041",
                mitre_technique_name="Exfiltration Over C2 Channel",
                mitre_tactic="Exfiltration",
                mitre_confidence=0.87,
                risk_score=0.92,
                risk_level="critical",
                playbook_id="PB-EXFIL-001",
            ),
            StoredSignature(
                fingerprint=_fp("suspicious_dns", "medium", "external", "high_entropy_domain"),
                event_type="suspicious_dns",
                mitre_technique_id="T1071.004",
                mitre_technique_name="DNS",
                mitre_tactic="Command and Control",
                mitre_confidence=0.78,
                risk_score=0.80,
                risk_level="high",
                playbook_id="PB-DNS-001",
            ),
        ]
        for sig in _SEEDS:
            self.store(sig)
        logger.info("seeded %d known attack patterns", len(_SEEDS))


def _fp(*parts: str) -> str:
    """Deterministic fingerprint helper matching generate_fingerprint logic."""
    import hashlib
    canonical = "|".join(sorted(parts))
    return hashlib.sha256(canonical.encode()).hexdigest()
