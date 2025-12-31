"""
IsoLog Events API Routes
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db
from ...storage.event_store import EventStore

router = APIRouter()


class EventResponse(BaseModel):
    """Event response model."""
    id: str
    timestamp: str
    event: dict
    host: dict
    source: dict
    destination: dict
    user: dict
    process: dict
    file: dict
    message: Optional[str]
    parser_id: Optional[str]
    source_type: Optional[str]
    
    class Config:
        from_attributes = True


class EventListResponse(BaseModel):
    """Event list response."""
    events: List[dict]
    total: int
    page: int
    page_size: int


class EventStatsResponse(BaseModel):
    """Event statistics response."""
    total: int
    by_source_type: dict
    by_event_kind: dict
    top_hosts: List[dict]


@router.get("", response_model=EventListResponse)
async def get_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    host_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    event_action: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    Query events with filters.
    
    - **start_time**: Filter events after this time
    - **end_time**: Filter events before this time
    - **host_name**: Filter by host name (partial match)
    - **source_ip**: Filter by source IP
    - **user_name**: Filter by user name (partial match)
    - **event_action**: Filter by event action
    - **page**: Page number (1-indexed)
    - **page_size**: Events per page
    """
    store = EventStore(db)
    
    offset = (page - 1) * page_size
    
    events = await store.query(
        start_time=start_time,
        end_time=end_time,
        host_name=host_name,
        source_ip=source_ip,
        user_name=user_name,
        event_action=event_action,
        limit=page_size,
        offset=offset,
    )
    
    total = await store.count(start_time=start_time, end_time=end_time)
    
    return EventListResponse(
        events=[e.to_dict() for e in events],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=EventStatsResponse)
async def get_event_stats(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get event statistics."""
    store = EventStore(db)
    stats = await store.get_stats(start_time=start_time, end_time=end_time)
    return EventStatsResponse(**stats)


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get event by ID."""
    store = EventStore(db)
    event = await store.get_by_id(event_id)
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return event.to_dict()
