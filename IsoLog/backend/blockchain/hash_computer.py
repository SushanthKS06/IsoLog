"""
IsoLog Hash Computer

Computes Merkle tree hashes for log batches.
"""

import hashlib
from typing import List, Optional


class HashComputer:
    """
    Computes cryptographic hashes for log batches.
    
    Uses Merkle tree structure for efficient batch hashing.
    """
    
    ALGORITHM = "sha256"
    
    @staticmethod
    def hash_string(data: str) -> str:
        """Compute SHA-256 hash of string."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
    
    @staticmethod
    def hash_bytes(data: bytes) -> str:
        """Compute SHA-256 hash of bytes."""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def hash_event(event_data: dict) -> str:
        """
        Compute hash of a single event.
        
        Uses deterministic JSON serialization.
        """
        import json
        
        # Sort keys for deterministic ordering
        serialized = json.dumps(event_data, sort_keys=True, default=str)
        return HashComputer.hash_string(serialized)
    
    @staticmethod
    def compute_merkle_root(hashes: List[str]) -> str:
        """
        Compute Merkle root of a list of hashes.
        
        Args:
            hashes: List of hash strings
            
        Returns:
            Merkle root hash
        """
        if not hashes:
            return HashComputer.hash_string("")
        
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes = hashes + [hashes[-1]]
        
        # Build tree level by level
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                next_level.append(HashComputer.hash_string(combined))
            hashes = next_level
        
        return hashes[0]
    
    @staticmethod
    def compute_batch_hash(
        events: List[dict],
        previous_hash: Optional[str] = None,
    ) -> dict:
        """
        Compute batch hash with Merkle root.
        
        Args:
            events: List of event dictionaries
            previous_hash: Hash of previous batch for chaining
            
        Returns:
            Dictionary with hash details
        """
        # Hash each event
        event_hashes = [HashComputer.hash_event(event) for event in events]
        
        # Compute Merkle root
        merkle_root = HashComputer.compute_merkle_root(event_hashes)
        
        # Compute batch hash (includes previous hash for chaining)
        chain_data = f"{previous_hash or 'genesis'}:{merkle_root}:{len(events)}"
        batch_hash = HashComputer.hash_string(chain_data)
        
        return {
            "hash_value": batch_hash,
            "merkle_root": merkle_root,
            "event_count": len(events),
            "previous_hash": previous_hash,
        }
    
    @staticmethod
    def verify_merkle_proof(
        event_hash: str,
        proof: List[tuple],  # List of (hash, position) tuples
        merkle_root: str,
    ) -> bool:
        """
        Verify Merkle proof for an event.
        
        Args:
            event_hash: Hash of the event to verify
            proof: List of (hash, position) tuples for proof path
            merkle_root: Expected Merkle root
            
        Returns:
            True if proof is valid
        """
        current = event_hash
        
        for sibling_hash, position in proof:
            if position == "left":
                combined = sibling_hash + current
            else:
                combined = current + sibling_hash
            current = HashComputer.hash_string(combined)
        
        return current == merkle_root
