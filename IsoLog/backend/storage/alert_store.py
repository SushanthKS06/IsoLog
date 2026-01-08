
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
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def create(self, alert_data: Dict[str, Any]) -> Alert:
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
        result = await self.session.execute(
            select(Alert.created_at, Alert.severity)
            .where(and_(
                Alert.created_at >= start_time,
                Alert.created_at <= end_time,
            ))
            .order_by(Alert.created_at)
        )
        
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
            
            bucket_time = start_time + (
                (alert_time - start_time) // bucket_delta
            ) * bucket_delta
            
            if bucket_time in buckets and severity in buckets[bucket_time]:
                buckets[bucket_time][severity] += 1
        
        return [
            {"timestamp": ts.isoformat(), **counts}
            for ts, counts in sorted(buckets.items())
        ]
