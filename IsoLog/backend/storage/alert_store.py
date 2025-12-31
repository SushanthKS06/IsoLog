"""
IsoLog Alert Store

Data access layer for alert operations.
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import select, func, and_, desc, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import Alert, Event
from ..utils import generate_uuid

logger = logging.getLogger(__name__)


class AlertStore:
    """
    Data access layer for detection alerts.
    
    Provides methods for storing, querying, and managing alerts.
    """
    
    def __init__(self, session: AsyncSession):
        """
        Initialize alert store.
        
        Args:
            session: SQLAlchemy async session
        """
        self.session = session
    
    async def create(self, alert_data: Dict[str, Any]) -> Alert:
        """
        Create a new alert.
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Created Alert object
        """
        alert_id = alert_data.get("id") or generate_uuid()
        
        alert = Alert(
            id=alert_id,
            event_id=alert_data["event_id"],
            rule_id=alert_data.get("rule_id"),
            rule_name=alert_data.get("rule_name"),
            rule_description=alert_data.get("rule_description"),
            severity=alert_data.get("severity", "medium"),
            mitre_tactics=json.dumps(alert_data.get("mitre_tactics", [])),
            mitre_techniques=json.dumps(alert_data.get("mitre_techniques", [])),
            threat_score=alert_data.get("threat_score", 0.0),
            confidence=alert_data.get("confidence", 0.0),
            detection_type=alert_data.get("detection_type"),
            details=json.dumps(alert_data.get("details", {})),
            status=alert_data.get("status", "new"),
        )
        
        self.session.add(alert)
        await self.session.flush()
        
        return alert
    
    async def get_by_id(self, alert_id: str, include_event: bool = False) -> Optional[Alert]:
        """
        Get alert by ID.
        
        Args:
            alert_id: Alert ID
            include_event: Whether to load related event
            
        Returns:
            Alert object or None
        """
        query = select(Alert).where(Alert.id == alert_id)
        
        if include_event:
            query = query.options(selectinload(Alert.event))
        
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        detection_type: Optional[str] = None,
        min_threat_score: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
        include_event: bool = False,
    ) -> List[Alert]:
        """
        Query alerts with filters.
        
        Args:
            start_time: Filter alerts after this time
            end_time: Filter alerts before this time
            severity: Filter by severity
            status: Filter by status
            rule_id: Filter by rule ID
            detection_type: Filter by detection type
            min_threat_score: Minimum threat score
            limit: Maximum results
            offset: Results offset
            include_event: Load related events
            
        Returns:
            List of matching alerts
        """
        query = select(Alert)
        
        conditions = []
        
        if start_time:
            conditions.append(Alert.created_at >= start_time)
        if end_time:
            conditions.append(Alert.created_at <= end_time)
        if severity:
            conditions.append(Alert.severity == severity)
        if status:
            conditions.append(Alert.status == status)
        if rule_id:
            conditions.append(Alert.rule_id == rule_id)
        if detection_type:
            conditions.append(Alert.detection_type == detection_type)
        if min_threat_score is not None:
            conditions.append(Alert.threat_score >= min_threat_score)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        if include_event:
            query = query.options(selectinload(Alert.event))
        
        query = query.order_by(desc(Alert.created_at)).limit(limit).offset(offset)
        
        result = await self.session.execute(query)
        return list(result.scalars().all())
    
    async def count_by_severity(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, int]:
        """
        Count alerts by severity.
        
        Args:
            start_time: Count alerts after this time
            end_time: Count alerts before this time
            
        Returns:
            Dictionary of severity -> count
        """
        conditions = []
        if start_time:
            conditions.append(Alert.created_at >= start_time)
        if end_time:
            conditions.append(Alert.created_at <= end_time)
        
        where_clause = and_(*conditions) if conditions else True
        
        result = await self.session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(where_clause)
            .group_by(Alert.severity)
        )
        
        # Initialize with all severities
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        
        for row in result:
            if row[0] in counts:
                counts[row[0]] = row[1]
        
        return counts
    
    async def get_mitre_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK statistics for heatmap.
        
        Args:
            start_time: Stats from this time
            end_time: Stats until this time
            
        Returns:
            Statistics with tactic and technique counts
        """
        conditions = []
        if start_time:
            conditions.append(Alert.created_at >= start_time)
        if end_time:
            conditions.append(Alert.created_at <= end_time)
        
        where_clause = and_(*conditions) if conditions else True
        
        result = await self.session.execute(
            select(Alert.mitre_tactics, Alert.mitre_techniques)
            .where(where_clause)
        )
        
        tactics_count: Dict[str, int] = {}
        techniques_count: Dict[str, int] = {}
        
        for row in result:
            tactics = json.loads(row[0]) if row[0] else []
            techniques = json.loads(row[1]) if row[1] else []
            
            for tactic in tactics:
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1
            
            for technique in techniques:
                techniques_count[technique] = techniques_count.get(technique, 0) + 1
        
        return {
            "tactics": tactics_count,
            "techniques": techniques_count,
        }
    
    async def acknowledge(
        self,
        alert_id: str,
        acknowledged_by: str,
        status: str = "acknowledged",
    ) -> Optional[Alert]:
        """
        Acknowledge an alert.
        
        Args:
            alert_id: Alert ID
            acknowledged_by: User who acknowledged
            status: New status
            
        Returns:
            Updated alert or None
        """
        await self.session.execute(
            update(Alert)
            .where(Alert.id == alert_id)
            .values(
                status=status,
                acknowledged_by=acknowledged_by,
                acknowledged_at=datetime.utcnow(),
            )
        )
        
        return await self.get_by_id(alert_id)
    
    async def update_status(self, alert_id: str, status: str) -> Optional[Alert]:
        """
        Update alert status.
        
        Args:
            alert_id: Alert ID
            status: New status
            
        Returns:
            Updated alert or None
        """
        await self.session.execute(
            update(Alert)
            .where(Alert.id == alert_id)
            .values(status=status)
        )
        
        return await self.get_by_id(alert_id)
    
    async def get_timeline(
        self,
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int = 60,
    ) -> List[Dict[str, Any]]:
        """
        Get alert timeline for visualization.
        
        Args:
            start_time: Timeline start
            end_time: Timeline end
            bucket_minutes: Time bucket size
            
        Returns:
            List of time buckets with counts by severity
        """
        # Query all alerts in range
        result = await self.session.execute(
            select(Alert.created_at, Alert.severity)
            .where(and_(
                Alert.created_at >= start_time,
                Alert.created_at <= end_time,
            ))
            .order_by(Alert.created_at)
        )
        
        # Bucket the results
        from datetime import timedelta
        
        buckets: Dict[datetime, Dict[str, int]] = {}
        bucket_delta = timedelta(minutes=bucket_minutes)
        
        current = start_time
        while current <= end_time:
            buckets[current] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            }
            current += bucket_delta
        
        for row in result:
            alert_time = row[0]
            severity = row[1]
            
            # Find bucket
            bucket_time = start_time + (
                (alert_time - start_time) // bucket_delta
            ) * bucket_delta
            
            if bucket_time in buckets and severity in buckets[bucket_time]:
                buckets[bucket_time][severity] += 1
        
        return [
            {"timestamp": ts.isoformat(), **counts}
            for ts, counts in sorted(buckets.items())
        ]
