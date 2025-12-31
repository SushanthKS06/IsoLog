"""
IsoLog Search API Routes
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db

router = APIRouter()


class SearchRequest(BaseModel):
    """Search request model."""
    query: str
    event_types: Optional[List[str]] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = 50


class SearchResult(BaseModel):
    """Search result model."""
    id: str
    type: str  # event, alert
    timestamp: str
    score: float
    highlight: dict
    data: dict


class SearchResponse(BaseModel):
    """Search response model."""
    results: List[SearchResult]
    total: int
    query: str
    took_ms: int


@router.post("", response_model=SearchResponse)
async def search(
    request: SearchRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Full-text search across events and alerts.
    
    Searches in:
    - Event messages
    - Alert rule names and descriptions
    - Host names, user names, IPs
    """
    import time
    from datetime import datetime
    from sqlalchemy import or_, select
    
    from ...storage.models import Event, Alert
    
    start = time.time()
    
    query_lower = request.query.lower()
    results = []
    
    # Search events
    event_query = select(Event).where(
        or_(
            Event.message.ilike(f"%{request.query}%"),
            Event.host_name.ilike(f"%{request.query}%"),
            Event.user_name.ilike(f"%{request.query}%"),
            Event.source_ip.ilike(f"%{request.query}%"),
            Event.process_name.ilike(f"%{request.query}%"),
        )
    ).limit(request.limit)
    
    event_result = await db.execute(event_query)
    events = event_result.scalars().all()
    
    for event in events:
        # Calculate simple relevance score
        score = 0.0
        highlight = {}
        
        if event.message and query_lower in event.message.lower():
            score += 0.5
            # Find match position for highlight
            idx = event.message.lower().find(query_lower)
            start_idx = max(0, idx - 50)
            end_idx = min(len(event.message), idx + len(request.query) + 50)
            highlight["message"] = f"...{event.message[start_idx:end_idx]}..."
        
        if event.host_name and query_lower in event.host_name.lower():
            score += 0.3
            highlight["host_name"] = event.host_name
        
        if event.user_name and query_lower in event.user_name.lower():
            score += 0.2
            highlight["user_name"] = event.user_name
        
        results.append(SearchResult(
            id=event.id,
            type="event",
            timestamp=event.timestamp.isoformat() if event.timestamp else "",
            score=score,
            highlight=highlight,
            data={
                "host_name": event.host_name,
                "user_name": event.user_name,
                "event_action": event.event_action,
                "message": event.message[:200] if event.message else None,
            },
        ))
    
    # Search alerts
    alert_query = select(Alert).where(
        or_(
            Alert.rule_name.ilike(f"%{request.query}%"),
            Alert.rule_description.ilike(f"%{request.query}%"),
        )
    ).limit(request.limit)
    
    alert_result = await db.execute(alert_query)
    alerts = alert_result.scalars().all()
    
    for alert in alerts:
        score = 0.0
        highlight = {}
        
        if alert.rule_name and query_lower in alert.rule_name.lower():
            score += 0.6
            highlight["rule_name"] = alert.rule_name
        
        if alert.rule_description and query_lower in alert.rule_description.lower():
            score += 0.4
            highlight["rule_description"] = alert.rule_description
        
        results.append(SearchResult(
            id=alert.id,
            type="alert",
            timestamp=alert.created_at.isoformat() if alert.created_at else "",
            score=score,
            highlight=highlight,
            data={
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "detection_type": alert.detection_type,
            },
        ))
    
    # Sort by score
    results.sort(key=lambda x: x.score, reverse=True)
    results = results[:request.limit]
    
    took_ms = int((time.time() - start) * 1000)
    
    return SearchResponse(
        results=results,
        total=len(results),
        query=request.query,
        took_ms=took_ms,
    )


@router.get("/suggestions")
async def get_search_suggestions(
    q: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
):
    """Get search suggestions based on query prefix."""
    from sqlalchemy import select, distinct
    from ...storage.models import Event
    
    suggestions = []
    
    # Get matching host names
    host_result = await db.execute(
        select(distinct(Event.host_name))
        .where(Event.host_name.ilike(f"{q}%"))
        .limit(5)
    )
    suggestions.extend([
        {"type": "host", "value": row[0]}
        for row in host_result if row[0]
    ])
    
    # Get matching user names
    user_result = await db.execute(
        select(distinct(Event.user_name))
        .where(Event.user_name.ilike(f"{q}%"))
        .limit(5)
    )
    suggestions.extend([
        {"type": "user", "value": row[0]}
        for row in user_result if row[0]
    ])
    
    return {"suggestions": suggestions[:10]}
