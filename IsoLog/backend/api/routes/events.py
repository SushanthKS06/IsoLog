
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db
from ...storage.event_store import EventStore

router = APIRouter()

class EventResponse(BaseModel):
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
    events: List[dict]
    total: int
    page: int
    page_size: int

class EventStatsResponse(BaseModel):
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
    store = EventStore(db)
    stats = await store.get_stats(start_time=start_time, end_time=end_time)
    return EventStatsResponse(**stats)

@router.get("/{event_id}")
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
):
    store = EventStore(db)
    event = await store.get_by_id(event_id)
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return event.to_dict()
