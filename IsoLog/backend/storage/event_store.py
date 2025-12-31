"""
IsoLog Event Store

Data access layer for event operations.
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Event
from ..utils import generate_uuid

logger = logging.getLogger(__name__)


class EventStore:
    """
    Data access layer for log events.
    
    Provides methods for storing, querying, and managing events.
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize event store.
        
        Args:
            session: SQLAlchemy async session
        """
        self.session = session
    
    async def create(self, event_data: Dict[str, Any]) -> Event:
        """
        Create a new event.
        
        Args:
            event_data: Event data dictionary (ECS format)
            
        Returns:
            Created Event object
        """
        # Generate ID if not provided
        event_id = event_data.get("id") or generate_uuid()
        
        # Extract nested fields
        event_info = event_data.get("event", {})
        host_info = event_data.get("host", {})
        source_info = event_data.get("source", {})
        dest_info = event_data.get("destination", {})
        user_info = event_data.get("user", {})
        process_info = event_data.get("process", {})
        file_info = event_data.get("file", {})
        
        event = Event(
            id=event_id,
            timestamp=event_data.get("timestamp") or datetime.utcnow(),
            event_kind=event_info.get("kind"),
            event_category=json.dumps(event_info.get("category", [])),
            event_action=event_info.get("action"),
            event_outcome=event_info.get("outcome"),
            host_name=host_info.get("name"),
            host_ip=host_info.get("ip"),
            source_ip=source_info.get("ip"),
            source_port=source_info.get("port"),
            destination_ip=dest_info.get("ip"),
            destination_port=dest_info.get("port"),
            user_name=user_info.get("name"),
            user_domain=user_info.get("domain"),
            process_name=process_info.get("name"),
            process_pid=process_info.get("pid"),
            process_command_line=process_info.get("command_line"),
            file_path=file_info.get("path"),
            file_name=file_info.get("name"),
            message=event_data.get("message"),
            raw_log=event_data.get("raw_log"),
            parser_id=event_data.get("parser_id"),
            source_type=event_data.get("source_type"),
            batch_id=event_data.get("batch_id"),
        )
        
        self.session.add(event)
        await self.session.flush()
        
        return event
    
    async def create_batch(self, events_data: List[Dict[str, Any]]) -> List[Event]:
        """
        Create multiple events in batch.
        
        Args:
            events_data: List of event data dictionaries
            
        Returns:
            List of created Event objects
        """
        events = []
        for event_data in events_data:
            event = await self.create(event_data)
            events.append(event)
        
        return events
    
    async def get_by_id(self, event_id: str) -> Optional[Event]:
        """
        Get event by ID.
        
        Args:
            event_id: Event ID
            
        Returns:
            Event object or None
        """
        result = await self.session.execute(
            select(Event).where(Event.id == event_id)
        )
        return result.scalar_one_or_none()
    
    async def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        event_action: Optional[str] = None,
        event_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_desc: bool = True,
    ) -> List[Event]:
        """
        Query events with filters.
        
        Args:
            start_time: Filter events after this time
            end_time: Filter events before this time
            host_name: Filter by host name (partial match)
            source_ip: Filter by source IP
            user_name: Filter by user name (partial match)
            event_action: Filter by event action
            event_category: Filter by category (JSON contains)
            limit: Maximum results
            offset: Results offset
            order_desc: Order by timestamp descending
            
        Returns:
            List of matching events
        """
        query = select(Event)
        
        conditions = []
        
        if start_time:
            conditions.append(Event.timestamp >= start_time)
        if end_time:
            conditions.append(Event.timestamp <= end_time)
        if host_name:
            conditions.append(Event.host_name.ilike(f"%{host_name}%"))
        if source_ip:
            conditions.append(Event.source_ip == source_ip)
        if user_name:
            conditions.append(Event.user_name.ilike(f"%{user_name}%"))
        if event_action:
            conditions.append(Event.event_action == event_action)
        if event_category:
            conditions.append(Event.event_category.contains(event_category))
        
        if conditions:
            query = query.where(and_(*conditions))
        
        if order_desc:
            query = query.order_by(desc(Event.timestamp))
        else:
            query = query.order_by(Event.timestamp)
        
        query = query.limit(limit).offset(offset)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def count(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Count events in time range.
        
        Args:
            start_time: Count events after this time
            end_time: Count events before this time
            
        Returns:
            Event count
        """
        query = select(func.count(Event.id))
        
        conditions = []
        if start_time:
            conditions.append(Event.timestamp >= start_time)
        if end_time:
            conditions.append(Event.timestamp <= end_time)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        result = await self.session.execute(query)
        return result.scalar() or 0
    
    async def get_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get event statistics.
        
        Args:
            start_time: Stats from this time
            end_time: Stats until this time
            
        Returns:
            Statistics dictionary
        """
        conditions = []
        if start_time:
            conditions.append(Event.timestamp >= start_time)
        if end_time:
            conditions.append(Event.timestamp <= end_time)
        
        where_clause = and_(*conditions) if conditions else True
        
        # Total count
        total_result = await self.session.execute(
            select(func.count(Event.id)).where(where_clause)
        )
        total = total_result.scalar() or 0
        
        # Count by source type
        source_result = await self.session.execute(
            select(Event.source_type, func.count(Event.id))
            .where(where_clause)
            .group_by(Event.source_type)
        )
        by_source = {row[0] or "unknown": row[1] for row in source_result}
        
        # Count by event kind
        kind_result = await self.session.execute(
            select(Event.event_kind, func.count(Event.id))
            .where(where_clause)
            .group_by(Event.event_kind)
        )
        by_kind = {row[0] or "unknown": row[1] for row in kind_result}
        
        # Top hosts
        host_result = await self.session.execute(
            select(Event.host_name, func.count(Event.id))
            .where(where_clause)
            .group_by(Event.host_name)
            .order_by(desc(func.count(Event.id)))
            .limit(10)
        )
        top_hosts = [{"host": row[0], "count": row[1]} for row in host_result]
        
        return {
            "total": total,
            "by_source_type": by_source,
            "by_event_kind": by_kind,
            "top_hosts": top_hosts,
        }
    
    async def get_batch_for_hashing(
        self,
        batch_size: int = 1000,
        after_id: Optional[str] = None,
    ) -> List[Event]:
        """
        Get batch of events for blockchain hashing.
        
        Args:
            batch_size: Number of events in batch
            after_id: Get events after this ID
            
        Returns:
            List of events
        """
        query = select(Event).where(Event.batch_id.is_(None))
        
        if after_id:
            # Get timestamp of reference event
            ref_result = await self.session.execute(
                select(Event.timestamp).where(Event.id == after_id)
            )
            ref_timestamp = ref_result.scalar_one_or_none()
            if ref_timestamp:
                query = query.where(Event.timestamp > ref_timestamp)
        
        query = query.order_by(Event.timestamp).limit(batch_size)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def mark_batch(self, event_ids: List[str], batch_id: str):
        """
        Mark events as belonging to a batch.
        
        Args:
            event_ids: List of event IDs
            batch_id: Batch hash ID
        """
        from sqlalchemy import update
        
        await self.session.execute(
            update(Event)
            .where(Event.id.in_(event_ids))
            .values(batch_id=batch_id)
        )
