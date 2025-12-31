"""
IsoLog System API Routes
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter()


class SystemStatusResponse(BaseModel):
    """System status response."""
    status: str
    version: str
    components: Dict[str, Any]


@router.get("/status")
async def get_system_status(request: Request):
    """Get system health status."""
    from ... import __version__
    
    components = {
        "database": "healthy",
        "detection_engine": "unknown",
        "blockchain": "unknown",
    }
    
    # Check detection engine
    detection_engine = getattr(request.app.state, "detection_engine", None)
    if detection_engine:
        stats = detection_engine.get_stats()
        components["detection_engine"] = {
            "status": "healthy" if stats.get("initialized") else "initializing",
            **stats,
        }
    
    # Check blockchain
    chain_manager = getattr(request.app.state, "chain_manager", None)
    if chain_manager:
        components["blockchain"] = {
            "status": "healthy",
            **chain_manager.get_stats(),
        }
    else:
        components["blockchain"] = {"status": "disabled"}
    
    return SystemStatusResponse(
        status="healthy",
        version=__version__,
        components=components,
    )


@router.get("/config")
async def get_system_config():
    """Get non-sensitive system configuration."""
    from ...config import get_settings
    
    settings = get_settings()
    
    return {
        "server": {
            "host": settings.server.host,
            "port": settings.server.port,
        },
        "ingestion": {
            "syslog_enabled": settings.ingestion.syslog.enabled,
            "file_watcher_enabled": settings.ingestion.file_watcher.enabled,
        },
        "detection": {
            "sigma_enabled": settings.detection.sigma.enabled,
            "mitre_enabled": settings.detection.mitre.enabled,
            "anomaly_enabled": settings.detection.anomaly.enabled,
        },
        "blockchain": {
            "enabled": settings.blockchain.enabled,
        },
        "auth": {
            "enabled": settings.auth.enabled,
        },
    }


@router.get("/detection/stats")
async def get_detection_stats(request: Request):
    """Get detection engine statistics."""
    detection_engine = getattr(request.app.state, "detection_engine", None)
    
    if not detection_engine:
        return {"error": "Detection engine not available"}
    
    return detection_engine.get_stats()


@router.get("/mitre/matrix")
async def get_mitre_matrix(request: Request):
    """Get MITRE ATT&CK matrix data for visualization."""
    detection_engine = getattr(request.app.state, "detection_engine", None)
    
    if detection_engine and detection_engine._mitre_mapper:
        return detection_engine._mitre_mapper.get_matrix_data()
    
    return {"matrix": [], "message": "MITRE mapper not available"}


@router.post("/reload-rules")
async def reload_rules(request: Request):
    """Reload detection rules."""
    detection_engine = getattr(request.app.state, "detection_engine", None)
    
    if not detection_engine:
        return {"error": "Detection engine not available"}
    
    if detection_engine._sigma_matcher:
        await detection_engine._sigma_matcher.load_rules()
        return {
            "success": True,
            "rules_loaded": detection_engine._sigma_matcher.rule_count,
        }
    
    return {"success": False, "message": "Sigma matcher not enabled"}
