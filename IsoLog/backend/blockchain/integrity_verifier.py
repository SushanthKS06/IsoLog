
import logging
from typing import Any, Dict, List, Optional

from .hash_computer import HashComputer
from .chain_manager import ChainManager

logger = logging.getLogger(__name__)

class IntegrityVerifier:
    
    def __init__(self, chain_manager: ChainManager):
        self.chain = chain_manager
    
    def verify_batch(
        self,
        events: List[Dict[str, Any]],
        expected_hash: str,
        expected_merkle_root: Optional[str] = None,
        previous_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        hash_result = HashComputer.compute_batch_hash(events, previous_hash)
        
        computed_hash = hash_result["hash_value"]
        computed_merkle = hash_result["merkle_root"]
        
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
        return self.chain.verify_chain()
    
    def verify_event_in_batch(
        self,
        event: Dict[str, Any],
        batch_events: List[Dict[str, Any]],
        expected_merkle_root: str,
    ) -> Dict[str, Any]:
        event_hash = HashComputer.hash_event(event)
        event_hashes = [HashComputer.hash_event(e) for e in batch_events]
        
        if event_hash not in event_hashes:
            return {
                "valid": False,
                "error": "Event not found in batch",
                "event_hash": event_hash,
            }
        
        computed_merkle = HashComputer.compute_merkle_root(event_hashes)
        
        return {
            "valid": computed_merkle == expected_merkle_root,
            "event_hash": event_hash,
            "position": event_hashes.index(event_hash),
            "computed_merkle": computed_merkle,
            "expected_merkle": expected_merkle_root,
        }
    
    def generate_integrity_report(self) -> Dict[str, Any]:
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
