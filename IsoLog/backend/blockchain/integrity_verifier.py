"""
IsoLog Integrity Verifier

Verifies log integrity using blockchain hashes.
"""

import logging
from typing import Any, Dict, List, Optional

from .hash_computer import HashComputer
from .chain_manager import ChainManager

logger = logging.getLogger(__name__)


class IntegrityVerifier:
    """
    Verifies log batch integrity against blockchain hashes.
    """
    
    def __init__(self, chain_manager: ChainManager):
        """
        Initialize verifier.
        
        Args:
            chain_manager: Chain manager instance
        """
        self.chain = chain_manager
    
    def verify_batch(
        self,
        events: List[Dict[str, Any]],
        expected_hash: str,
        expected_merkle_root: Optional[str] = None,
        previous_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify a batch of events against expected hash.
        
        Args:
            events: List of events to verify
            expected_hash: Expected batch hash
            expected_merkle_root: Expected Merkle root (optional)
            previous_hash: Previous block hash for chain context
            
        Returns:
            Verification result
        """
        # Compute hash of provided events
        hash_result = HashComputer.compute_batch_hash(events, previous_hash)
        
        computed_hash = hash_result["hash_value"]
        computed_merkle = hash_result["merkle_root"]
        
        # Compare hashes
        hash_matches = computed_hash == expected_hash
        merkle_matches = (
            expected_merkle_root is None or 
            computed_merkle == expected_merkle_root
        )
        
        result = {
            "valid": hash_matches and merkle_matches,
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "hash_matches": hash_matches,
            "event_count": len(events),
        }
        
        if expected_merkle_root:
            result["computed_merkle"] = computed_merkle
            result["expected_merkle"] = expected_merkle_root
            result["merkle_matches"] = merkle_matches
        
        if not result["valid"]:
            logger.warning(
                f"Batch verification failed: computed={computed_hash[:16]}... "
                f"expected={expected_hash[:16]}..."
            )
        
        return result
    
    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Verify integrity of the entire hash chain.
        
        Returns:
            Verification result
        """
        return self.chain.verify_chain()
    
    def verify_event_in_batch(
        self,
        event: Dict[str, Any],
        batch_events: List[Dict[str, Any]],
        expected_merkle_root: str,
    ) -> Dict[str, Any]:
        """
        Verify that an event is part of a batch.
        
        Args:
            event: Event to verify
            batch_events: All events in the batch
            expected_merkle_root: Expected Merkle root
            
        Returns:
            Verification result
        """
        # Find event in batch
        event_hash = HashComputer.hash_event(event)
        event_hashes = [HashComputer.hash_event(e) for e in batch_events]
        
        if event_hash not in event_hashes:
            return {
                "valid": False,
                "error": "Event not found in batch",
                "event_hash": event_hash,
            }
        
        # Verify Merkle root
        computed_merkle = HashComputer.compute_merkle_root(event_hashes)
        
        return {
            "valid": computed_merkle == expected_merkle_root,
            "event_hash": event_hash,
            "position": event_hashes.index(event_hash),
            "computed_merkle": computed_merkle,
            "expected_merkle": expected_merkle_root,
        }
    
    def generate_integrity_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive integrity report.
        
        Returns:
            Report with chain status and statistics
        """
        chain_result = self.verify_chain_integrity()
        chain_stats = self.chain.get_stats()
        
        return {
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            "chain_valid": chain_result["valid"],
            "blocks_verified": chain_result["blocks_verified"],
            "errors": chain_result.get("errors", []),
            "statistics": chain_stats,
            "status": "healthy" if chain_result["valid"] else "compromised",
        }
