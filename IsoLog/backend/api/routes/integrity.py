"""
IsoLog Integrity API Routes
"""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter()


class VerifyBatchRequest(BaseModel):
    """Batch verification request."""
    batch_hash: str
    merkle_root: Optional[str] = None


class IntegrityReportResponse(BaseModel):
    """Integrity report response."""
    timestamp: str
    chain_valid: bool
    blocks_verified: int
    errors: List[dict]
    statistics: dict
    status: str


@router.get("/verify")
async def verify_chain_integrity(request: Request):
    """Verify integrity of the hash chain."""
    chain_manager = getattr(request.app.state, "chain_manager", None)
    
    if not chain_manager:
        return {
            "valid": True,
            "message": "Blockchain not enabled",
            "blocks_verified": 0,
        }
    
    from ..blockchain import IntegrityVerifier
    verifier = IntegrityVerifier(chain_manager)
    
    return verifier.verify_chain_integrity()


@router.get("/report")
async def get_integrity_report(request: Request):
    """Get comprehensive integrity report."""
    chain_manager = getattr(request.app.state, "chain_manager", None)
    
    if not chain_manager:
        return {
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            "chain_valid": True,
            "blocks_verified": 0,
            "errors": [],
            "statistics": {"message": "Blockchain not enabled"},
            "status": "disabled",
        }
    
    from ..blockchain import IntegrityVerifier
    verifier = IntegrityVerifier(chain_manager)
    
    return verifier.generate_integrity_report()


@router.get("/chain")
async def get_chain_info(
    start_block: Optional[int] = None,
    end_block: Optional[int] = None,
    limit: int = 100,
    request: Request = None,
):
    """Get hash chain blocks."""
    chain_manager = getattr(request.app.state, "chain_manager", None)
    
    if not chain_manager:
        return {"blocks": [], "message": "Blockchain not enabled"}
    
    blocks = chain_manager.get_chain(
        start_block=start_block,
        end_block=end_block,
        limit=limit,
    )
    
    return {
        "blocks": [
            {
                "id": b.id,
                "block_hash": b.block_hash,
                "previous_hash": b.previous_hash,
                "merkle_root": b.merkle_root,
                "event_count": b.event_count,
                "timestamp": b.timestamp.isoformat() if b.timestamp else None,
            }
            for b in blocks
        ]
    }


@router.get("/export")
async def export_chain(request: Request):
    """Export chain for external verification."""
    chain_manager = getattr(request.app.state, "chain_manager", None)
    
    if not chain_manager:
        return {"blocks": [], "message": "Blockchain not enabled"}
    
    return {"chain": chain_manager.export_chain()}


@router.get("/stats")
async def get_chain_stats(request: Request):
    """Get chain statistics."""
    chain_manager = getattr(request.app.state, "chain_manager", None)
    
    if not chain_manager:
        return {"enabled": False, "message": "Blockchain not enabled"}
    
    stats = chain_manager.get_stats()
    stats["enabled"] = True
    return stats
