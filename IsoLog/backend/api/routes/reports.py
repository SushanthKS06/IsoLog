"""
IsoLog Reports API Routes

Generate and download reports.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db
from ...storage.event_store import EventStore
from ...storage.alert_store import AlertStore
from ...reporting import ReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter()


class ReportRequest(BaseModel):
    """Report generation request."""
    report_type: str  # executive, alerts, events, mitre, integrity
    format: str = "pdf"  # pdf, csv, json
    period_days: int = 7


@router.post("/generate")
async def generate_report(
    request: ReportRequest,
    session: AsyncSession = Depends(get_db),
):
    """Generate a new report."""
    try:
        generator = ReportGenerator("./data/reports")
        
        if request.report_type == "executive":
            # Get stats and alerts
            alert_store = AlertStore(session)
            stats = await alert_store.get_alert_counts()
            alerts = await alert_store.query_alerts(limit=100)
            
            path = generator.generate_executive_summary(
                stats=stats,
                alerts=[a.to_dict() for a in alerts],
                period_days=request.period_days,
                format=request.format,
            )
            
        elif request.report_type == "alerts":
            alert_store = AlertStore(session)
            alerts = await alert_store.query_alerts(limit=1000)
            
            path = generator.generate_alert_report(
                alerts=[a.to_dict() for a in alerts],
                format=request.format,
            )
            
        elif request.report_type == "events":
            event_store = EventStore(session)
            events = await event_store.query_events(limit=1000)
            
            path = generator.generate_event_report(
                events=[e.to_dict() for e in events],
                format=request.format if request.format != "pdf" else "csv",
            )
            
        elif request.report_type == "mitre":
            alert_store = AlertStore(session)
            mitre_stats = await alert_store.get_mitre_stats()
            alerts = await alert_store.query_alerts(limit=500)
            
            path = generator.generate_mitre_report(
                mitre_stats=mitre_stats,
                alerts=[a.to_dict() for a in alerts],
                format=request.format,
            )
            
        elif request.report_type == "integrity":
            from ...blockchain import IntegrityVerifier, ChainManager
            
            chain = ChainManager("./data/blockchain.db")
            verifier = IntegrityVerifier(chain)
            result = verifier.generate_report()
            
            path = generator.generate_integrity_report(
                verification_result=result,
                format=request.format,
            )
            
        else:
            raise HTTPException(400, f"Unknown report type: {request.report_type}")
        
        return {
            "success": True,
            "path": path,
            "download_url": f"/api/reports/download?path={path}",
        }
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(500, str(e))


@router.get("/download")
async def download_report(path: str = Query(...)):
    """Download a generated report."""
    from pathlib import Path
    
    file_path = Path(path)
    
    if not file_path.exists():
        raise HTTPException(404, "Report not found")
    
    # Security check - only allow downloads from reports directory
    if "reports" not in str(file_path):
        raise HTTPException(403, "Invalid path")
    
    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type="application/octet-stream",
    )


@router.get("/list")
async def list_reports():
    """List available reports."""
    from pathlib import Path
    
    reports_dir = Path("./data/reports")
    
    if not reports_dir.exists():
        return {"reports": []}
    
    reports = []
    for file in reports_dir.iterdir():
        if file.is_file():
            reports.append({
                "name": file.name,
                "size": file.stat().st_size,
                "created": file.stat().st_mtime,
                "path": str(file),
            })
    
    return {"reports": sorted(reports, key=lambda x: x["created"], reverse=True)}
