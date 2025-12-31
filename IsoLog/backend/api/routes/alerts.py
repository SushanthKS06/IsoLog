"""
IsoLog Alerts API Routes
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db
from ...storage.alert_store import AlertStore

router = APIRouter()


class AlertResponse(BaseModel):
    """Alert response model."""
    id: str
    event_id: str
    rule_id: Optional[str]
    rule_name: Optional[str]
    rule_description: Optional[str]
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    threat_score: float
    confidence: float
    detection_type: Optional[str]
    details: dict
    status: str
    created_at: str
    
    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    """Alert list response."""
    alerts: List[dict]
    total: int
    page: int
    page_size: int


class AlertCountResponse(BaseModel):
    """Alert count by severity."""
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class AcknowledgeRequest(BaseModel):
    """Alert acknowledge request."""
    acknowledged_by: str
    status: str = "acknowledged"


@router.get("", response_model=AlertListResponse)
async def get_alerts(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_id: Optional[str] = None,
    detection_type: Optional[str] = None,
    min_threat_score: Optional[float] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    Query alerts with filters.
    
    - **severity**: critical, high, medium, low, informational
    - **status**: new, acknowledged, investigating, resolved, false_positive
    - **detection_type**: sigma, ml, heuristic, correlation
    """
    store = AlertStore(db)
    
    offset = (page - 1) * page_size
    
    alerts = await store.query(
        start_time=start_time,
        end_time=end_time,
        severity=severity,
        status=status,
        rule_id=rule_id,
        detection_type=detection_type,
        min_threat_score=min_threat_score,
        limit=page_size,
        offset=offset,
        include_event=True,
    )
    
    # Get total count
    all_alerts = await store.query(
        start_time=start_time,
        end_time=end_time,
        severity=severity,
        status=status,
        limit=10000,
    )
    
    return AlertListResponse(
        alerts=[a.to_dict() for a in alerts],
        total=len(all_alerts),
        page=page,
        page_size=page_size,
    )


@router.get("/count", response_model=AlertCountResponse)
async def get_alert_counts(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get alert counts by severity."""
    store = AlertStore(db)
    counts = await store.count_by_severity(start_time=start_time, end_time=end_time)
    return AlertCountResponse(**counts)


@router.get("/timeline")
async def get_alert_timeline(
    start_time: datetime,
    end_time: datetime,
    bucket_minutes: int = Query(60, ge=5, le=1440),
    db: AsyncSession = Depends(get_db),
):
    """Get alert timeline for visualization."""
    store = AlertStore(db)
    timeline = await store.get_timeline(
        start_time=start_time,
        end_time=end_time,
        bucket_minutes=bucket_minutes,
    )
    return {"timeline": timeline}


@router.get("/mitre")
async def get_mitre_stats(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get MITRE ATT&CK statistics for heatmap."""
    store = AlertStore(db)
    stats = await store.get_mitre_stats(start_time=start_time, end_time=end_time)
    return stats


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get alert by ID with related event."""
    store = AlertStore(db)
    alert = await store.get_by_id(alert_id, include_event=True)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    result = alert.to_dict()
    if alert.event:
        result["event"] = alert.event.to_dict()
    
    return result


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge an alert."""
    store = AlertStore(db)
    
    alert = await store.acknowledge(
        alert_id=alert_id,
        acknowledged_by=request.acknowledged_by,
        status=request.status,
    )
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert.to_dict()


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str,
    db: AsyncSession = Depends(get_db),
):
    """Update alert status."""
    valid_statuses = ["new", "acknowledged", "investigating", "resolved", "false_positive"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    store = AlertStore(db)
    alert = await store.update_status(alert_id, status)
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert.to_dict()
