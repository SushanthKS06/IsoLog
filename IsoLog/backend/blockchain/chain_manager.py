
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

from .hash_computer import HashComputer

logger = logging.getLogger(__name__)

Base = declarative_base()

class HashBlock(Base):
    __tablename__ = "hash_blocks"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    block_hash = Column(String(64), unique=True, nullable=False)
    previous_hash = Column(String(64))
    merkle_root = Column(String(64), nullable=False)
    event_count = Column(Integer, nullable=False)
    batch_start_id = Column(String(36))
    batch_end_id = Column(String(36))
    timestamp = Column(DateTime, default=datetime.utcnow)
    block_metadata = Column(Text)  # JSON metadata

class ChainManager:
    
    def __init__(self, ledger_path: str):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.engine = create_engine(
            f"sqlite:///{self.ledger_path}",
            connect_args={"check_same_thread": False},
        )
        self.Session = sessionmaker(bind=self.engine)
        
        Base.metadata.create_all(self.engine)
    
    def get_latest_block(self) -> Optional[HashBlock]:
        session = self.Session()
        try:
            return session.query(HashBlock).order_by(HashBlock.id.desc()).first()
        finally:
            session.close()
    
    def get_previous_hash(self) -> Optional[str]:
        latest = self.get_latest_block()
        return latest.block_hash if latest else None
    
    def add_block(
        self,
        events: List[Dict[str, Any]],
        batch_start_id: Optional[str] = None,
        batch_end_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> HashBlock:
        previous_hash = self.get_previous_hash()
        
        hash_result = HashComputer.compute_batch_hash(events, previous_hash)
        
        import json
        block = HashBlock(
            block_hash=hash_result["hash_value"],
            previous_hash=previous_hash,
            merkle_root=hash_result["merkle_root"],
            event_count=hash_result["event_count"],
            batch_start_id=batch_start_id,
            batch_end_id=batch_end_id,
            block_metadata=json.dumps(metadata) if metadata else None,
        )
        
        session = self.Session()
        try:
            session.add(block)
            session.commit()
            session.refresh(block)
            
            logger.info(
                f"Added block #{block.id}: {block.block_hash[:16]}... "
                f"({block.event_count} events)"
            )
            
            return block
        finally:
            session.close()
    
    def get_chain(
        self,
        start_block: Optional[int] = None,
        end_block: Optional[int] = None,
        limit: int = 100,
    ) -> List[HashBlock]:
        session = self.Session()
        try:
            query = session.query(HashBlock)
            
            if start_block is not None:
                query = query.filter(HashBlock.id >= start_block)
            if end_block is not None:
                query = query.filter(HashBlock.id <= end_block)
            
            return query.order_by(HashBlock.id).limit(limit).all()
        finally:
            session.close()
    
    def verify_chain(
        self,
        start_block: Optional[int] = None,
        end_block: Optional[int] = None,
    ) -> Dict[str, Any]:
        blocks = self.get_chain(start_block, end_block, limit=10000)
        
        if not blocks:
            return {
                "valid": True,
                "blocks_verified": 0,
                "message": "No blocks to verify",
            }
        
        errors = []
        
        for i, block in enumerate(blocks):
            if i > 0:
                expected_prev = blocks[i - 1].block_hash
                if block.previous_hash != expected_prev:
                    errors.append({
                        "block_id": block.id,
                        "error": "Chain broken - previous hash mismatch",
                        "expected": expected_prev[:16],
                        "actual": (block.previous_hash or "none")[:16],
                    })
            elif block.previous_hash is not None and start_block is None:
                pass  # OK if starting from middle
        
        return {
            "valid": len(errors) == 0,
            "blocks_verified": len(blocks),
            "first_block": blocks[0].id if blocks else None,
            "last_block": blocks[-1].id if blocks else None,
            "errors": errors,
        }
    
    def export_chain(self) -> List[Dict[str, Any]]:
        blocks = self.get_chain(limit=10000)
        
        return [
            {
                "block_id": block.id,
                "block_hash": block.block_hash,
                "previous_hash": block.previous_hash,
                "merkle_root": block.merkle_root,
                "event_count": block.event_count,
                "timestamp": block.timestamp.isoformat() if block.timestamp else None,
            }
            for block in blocks
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        session = self.Session()
        try:
            total_blocks = session.query(HashBlock).count()
            latest = self.get_latest_block()
            
            total_events = session.query(
                HashBlock.event_count
            ).with_entities(
                HashComputer.__class__  # Placeholder
            )
            
            return {
                "total_blocks": total_blocks,
                "latest_block_id": latest.id if latest else None,
                "latest_block_hash": latest.block_hash if latest else None,
                "latest_timestamp": latest.timestamp.isoformat() if latest else None,
            }
        finally:
            session.close()
