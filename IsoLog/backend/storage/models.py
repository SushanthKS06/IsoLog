
from datetime import datetime
from typing import Optional, List
import json

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Float,
    Integer,
    ForeignKey,
    Index,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    
    id = Column(String(36), primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    
    event_kind = Column(String(50))  # event, alert, metric
    event_category = Column(Text)  # JSON array: authentication, process, network
    event_action = Column(String(255))
    event_outcome = Column(String(50))  # success, failure, unknown
    
    host_name = Column(String(255), index=True)
    host_ip = Column(String(45))
    
    source_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_ip = Column(String(45), index=True)
    destination_port = Column(Integer)
    
    user_name = Column(String(255), index=True)
    user_domain = Column(String(255))
    
    process_name = Column(String(255))
    process_pid = Column(Integer)
    process_command_line = Column(Text)
    
    file_path = Column(Text)
    file_name = Column(String(255))
    
    message = Column(Text)
    raw_log = Column(Text)
    
    parser_id = Column(String(100))
    source_type = Column(String(50))  # syslog, file, usb, agent
    batch_id = Column(String(36), ForeignKey("batch_hashes.id"), index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    alerts = relationship("Alert", back_populates="event")
    
    __table_args__ = (
        Index("ix_events_timestamp_host", "timestamp", "host_name"),
        Index("ix_events_user_action", "user_name", "event_action"),
    )
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event": {
                "kind": self.event_kind,
                "category": json.loads(self.event_category) if self.event_category else [],
                "action": self.event_action,
                "outcome": self.event_outcome,
            },
            "host": {
                "name": self.host_name,
                "ip": self.host_ip,
            },
            "source": {
                "ip": self.source_ip,
                "port": self.source_port,
            },
            "destination": {
                "ip": self.destination_ip,
                "port": self.destination_port,
            },
            "user": {
                "name": self.user_name,
                "domain": self.user_domain,
            },
            "process": {
                "name": self.process_name,
                "pid": self.process_pid,
                "command_line": self.process_command_line,
            },
            "file": {
                "path": self.file_path,
                "name": self.file_name,
            },
            "message": self.message,
            "parser_id": self.parser_id,
            "source_type": self.source_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(String(36), primary_key=True)
    event_id = Column(String(36), ForeignKey("events.id"), nullable=False)
    
    rule_id = Column(String(100), index=True)
    rule_name = Column(String(255))
    rule_description = Column(Text)
    
    severity = Column(String(20), nullable=False, index=True)
    
    mitre_tactics = Column(Text)  # JSON array of tactic IDs
    mitre_techniques = Column(Text)  # JSON array of technique IDs
    
    threat_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)  # 0.0 - 1.0
    
    detection_type = Column(String(50))  # sigma, ml, heuristic, correlation
    
    details = Column(Text)
    
    status = Column(String(50), default="new")  # new, acknowledged, investigating, resolved, false_positive
    acknowledged_by = Column(String(255))
    acknowledged_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    event = relationship("Event", back_populates="alerts")
    
    __table_args__ = (
        Index("ix_alerts_severity_created", "severity", "created_at"),
    )
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "mitre_tactics": json.loads(self.mitre_tactics) if self.mitre_tactics else [],
            "mitre_techniques": json.loads(self.mitre_techniques) if self.mitre_techniques else [],
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "detection_type": self.detection_type,
            "details": json.loads(self.details) if self.details else {},
            "status": self.status,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

class BatchHash(Base):
    __tablename__ = "batch_hashes"
    
    id = Column(String(36), primary_key=True)
    
    batch_start_id = Column(String(36), nullable=False)
    batch_end_id = Column(String(36), nullable=False)
    event_count = Column(Integer, nullable=False)
    
    hash_value = Column(String(64), nullable=False)  # SHA-256 hash
    previous_hash = Column(String(64))  # Chain to previous batch
    merkle_root = Column(String(64))  # Merkle root of events
    
    blockchain_tx_id = Column(String(100))
    synced_at = Column(DateTime)
    
    verified = Column(Integer, default=0)  # 0=pending, 1=verified, -1=failed
    verified_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "batch_start_id": self.batch_start_id,
            "batch_end_id": self.batch_end_id,
            "event_count": self.event_count,
            "hash_value": self.hash_value,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "blockchain_tx_id": self.blockchain_tx_id,
            "synced_at": self.synced_at.isoformat() if self.synced_at else None,
            "verified": self.verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class SystemState(Base):
    __tablename__ = "system_state"
    
    key = Column(String(100), primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": json.loads(self.value) if self.value else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
