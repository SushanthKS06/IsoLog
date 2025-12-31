"""
IsoLog Dashboard API Routes
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db
from ...storage.event_store import EventStore
from ...storage.alert_store import AlertStore

router = APIRouter()


class DashboardStatsResponse(BaseModel):
    """Dashboard statistics response."""
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    events_today: int
    alerts_today: int


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
):
    """Get main dashboard statistics."""
    event_store = EventStore(db)
    alert_store = AlertStore(db)
    
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Get counts
    total_events = await event_store.count()
    events_today = await event_store.count(start_time=today_start)
    
    severity_counts = await alert_store.count_by_severity()
    today_counts = await alert_store.count_by_severity(start_time=today_start)
    
    total_alerts = sum(severity_counts.values())
    alerts_today = sum(today_counts.values())
    
    return DashboardStatsResponse(
        total_events=total_events,
        total_alerts=total_alerts,
        critical_alerts=severity_counts.get("critical", 0),
        high_alerts=severity_counts.get("high", 0),
        events_today=events_today,
        alerts_today=alerts_today,
    )


@router.get("/recent-alerts")
async def get_recent_alerts(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Get most recent alerts."""
    store = AlertStore(db)
    alerts = await store.query(limit=limit, include_event=True)
    
    return {
        "alerts": [
            {
                **a.to_dict(),
                "event_summary": {
                    "host": a.event.host_name if a.event else None,
                    "user": a.event.user_name if a.event else None,
                    "message": (a.event.message[:100] + "...") if a.event and a.event.message and len(a.event.message) > 100 else (a.event.message if a.event else None),
                }
            }
            for a in alerts
        ]
    }


@router.get("/timeline")
async def get_dashboard_timeline(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """Get event/alert timeline for dashboard."""
    event_store = EventStore(db)
    alert_store = AlertStore(db)
    
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    # Get hourly buckets
    bucket_minutes = 60 if hours <= 24 else 360
    
    alert_timeline = await alert_store.get_timeline(
        start_time=start_time,
        end_time=now,
        bucket_minutes=bucket_minutes,
    )
    
    return {
        "start_time": start_time.isoformat(),
        "end_time": now.isoformat(),
        "bucket_minutes": bucket_minutes,
        "timeline": alert_timeline,
    }


@router.get("/top-hosts")
async def get_top_hosts(
    hours: int = 24,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Get hosts with most events."""
    store = EventStore(db)
    
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    stats = await store.get_stats(start_time=start_time, end_time=now)
    
    return {
        "hosts": stats.get("top_hosts", [])[:limit],
        "period_hours": hours,
    }


@router.get("/detection-summary")
async def get_detection_summary(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """Get detection method summary."""
    store = AlertStore(db)
    
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    # Get alerts by detection type
    all_alerts = await store.query(
        start_time=start_time,
        end_time=now,
        limit=10000,
    )
    
    by_type = {}
    for alert in all_alerts:
        dtype = alert.detection_type or "unknown"
        by_type[dtype] = by_type.get(dtype, 0) + 1
    
    return {
        "by_detection_type": by_type,
        "total": len(all_alerts),
        "period_hours": hours,
    }
