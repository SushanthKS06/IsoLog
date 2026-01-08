
import pytest
import tempfile
from pathlib import Path

from backend.blockchain.hash_computer import HashComputer
from backend.blockchain.chain_manager import ChainManager
from backend.blockchain.integrity_verifier import IntegrityVerifier

class TestHashComputer:
    
    def test_hash_string(self):
        hash1 = HashComputer.hash_string("test")
        hash2 = HashComputer.hash_string("test")
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex
    
    def test_hash_string_different(self):
        hash1 = HashComputer.hash_string("test1")
        hash2 = HashComputer.hash_string("test2")
        
        assert hash1 != hash2
    
    def test_hash_bytes(self):
        hash_result = HashComputer.hash_bytes(b"test data")
        
        assert len(hash_result) == 64
    
    def test_compute_merkle_root(self):
        hashes = [
            HashComputer.hash_string("event1"),
            HashComputer.hash_string("event2"),
            HashComputer.hash_string("event3"),
            HashComputer.hash_string("event4"),
        ]
        
        root = HashComputer.compute_merkle_root(hashes)
        
        assert root is not None
        assert len(root) == 64
    
    def test_compute_merkle_root_single(self):
        hashes = [HashComputer.hash_string("single")]
        root = HashComputer.compute_merkle_root(hashes)
        
        assert root == hashes[0]
    
    def test_compute_merkle_root_empty(self):
        root = HashComputer.compute_merkle_root([])
        
        assert root is not None  # Should return empty hash

class TestChainManager:
    
    @pytest.fixture
    def chain_manager(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_chain.db"
            manager = ChainManager(str(db_path))
            yield manager
    
    def test_add_block(self, chain_manager):
        events = [
            {"id": "1", "message": "test1"},
            {"id": "2", "message": "test2"},
        ]
        
        block = chain_manager.add_block(events)
        
        assert block is not None
        assert block.event_count == 2
        assert block.merkle_root is not None
    
    def test_chain_continuity(self, chain_manager):
        for i in range(5):
            events = [{"id": str(i), "message": f"test{i}"}]
            chain_manager.add_block(events)
        
        blocks = chain_manager.get_chain(limit=10)
        
        assert len(blocks) == 5
        
        for i in range(1, len(blocks)):
            assert blocks[i].previous_hash == blocks[i-1].block_hash
    
    def test_verify_chain(self, chain_manager):
        for i in range(3):
            chain_manager.add_block([{"id": str(i)}])
        
        is_valid = chain_manager.verify_chain()
        
        assert is_valid == True

class TestIntegrityVerifier:
    
    @pytest.fixture
    def verifier(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_chain.db"
            chain = ChainManager(str(db_path))
            
            for i in range(3):
                chain.add_block([{"id": str(i), "message": f"event{i}"}])
            
            verifier = IntegrityVerifier(chain)
            yield verifier
    
    def test_verify_chain_integrity(self, verifier):
        result = verifier.verify_chain()
        
        assert result["valid"] == True
        assert result["blocks_verified"] >= 3
    
    def test_generate_report(self, verifier):
        report = verifier.generate_report()
        
        assert "chain_valid" in report
        assert "statistics" in report
        assert "timestamp" in report
