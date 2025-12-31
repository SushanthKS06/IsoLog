"""
IsoLog ECS Normalizer

Normalizes parsed events to Elastic Common Schema format.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_parser import ParsedEvent


class ECSNormalizer:
    """
    Normalizes events to Elastic Common Schema (ECS) format.
    
    ECS provides a consistent field naming convention for logs,
    enabling correlation across different log sources.
    """
    
    # ECS version
    ECS_VERSION = "8.11"
    
    # Event category mappings
    CATEGORY_MAP = {
        "login": ["authentication"],
        "logout": ["authentication", "session"],
        "auth": ["authentication"],
        "ssh": ["authentication", "network"],
        "sudo": ["authentication", "process"],
        "process": ["process"],
        "exec": ["process"],
        "network": ["network"],
        "connection": ["network"],
        "file": ["file"],
        "firewall": ["network"],
        "dns": ["network"],
        "web": ["web"],
        "http": ["web"],
        "database": ["database"],
        "malware": ["malware"],
    }
    
    # Event action mappings
    ACTION_MAP = {
        "accepted": "user_login",
        "failed": "logon_failed",
        "invalid": "logon_failed",
        "closed": "session_end",
        "opened": "session_start",
        "started": "process_started",
        "stopped": "process_stopped",
        "created": "creation",
        "deleted": "deletion",
        "modified": "modification",
    }
    
    def __init__(self):
        """Initialize normalizer."""
        pass
    
    def normalize(self, event: ParsedEvent) -> Dict[str, Any]:
        """
        Normalize a ParsedEvent to ECS format.
        
        Args:
            event: ParsedEvent to normalize
            
        Returns:
            ECS-formatted dictionary
        """
        # Start with base structure
        ecs_event = {
            "@timestamp": self._format_timestamp(event.timestamp),
            "ecs": {
                "version": self.ECS_VERSION,
            },
            "event": self._build_event_fields(event),
            "message": event.message,
        }
        
        # Add host fields
        if event.host_name or event.host_ip:
            ecs_event["host"] = self._build_host_fields(event)
        
        # Add source fields
        if event.source_ip:
            ecs_event["source"] = self._build_source_fields(event)
        
        # Add destination fields
        if event.destination_ip:
            ecs_event["destination"] = self._build_destination_fields(event)
        
        # Add user fields
        if event.user_name:
            ecs_event["user"] = self._build_user_fields(event)
        
        # Add process fields
        if event.process_name or event.process_pid:
            ecs_event["process"] = self._build_process_fields(event)
        
        # Add file fields
        if event.file_path or event.file_name:
            ecs_event["file"] = self._build_file_fields(event)
        
        # Add labels for custom fields
        if event.extra:
            ecs_event["labels"] = event.extra
        
        # Add parser metadata
        ecs_event["observer"] = {
            "type": "isolog",
            "vendor": "IsoLog",
            "product": "Portable SIEM",
        }
        
        if event.parser_id:
            ecs_event["observer"]["name"] = event.parser_id
        
        return ecs_event
    
    def _format_timestamp(self, dt: datetime) -> str:
        """Format datetime as ISO 8601."""
        if dt.tzinfo is None:
            # Assume UTC if no timezone
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return dt.isoformat()
    
    def _build_event_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build event.* fields."""
        fields: Dict[str, Any] = {
            "kind": event.event_kind or "event",
            "created": self._format_timestamp(datetime.utcnow()),
        }
        
        # Add category
        categories = event.event_category or []
        if not categories and event.message:
            categories = self._infer_category(event.message)
        if categories:
            fields["category"] = categories
        
        # Add action
        action = event.event_action
        if not action and event.message:
            action = self._infer_action(event.message)
        if action:
            fields["action"] = action
        
        # Add outcome
        if event.event_outcome:
            fields["outcome"] = event.event_outcome
        elif event.message:
            fields["outcome"] = self._infer_outcome(event.message)
        
        # Add original log
        if event.raw_log:
            fields["original"] = event.raw_log
        
        return fields
    
    def _build_host_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build host.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.host_name:
            fields["name"] = event.host_name
            fields["hostname"] = event.host_name
        
        if event.host_ip:
            fields["ip"] = [event.host_ip] if isinstance(event.host_ip, str) else event.host_ip
        
        return fields
    
    def _build_source_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build source.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.source_ip:
            fields["ip"] = event.source_ip
            fields["address"] = event.source_ip
        
        if event.source_port:
            fields["port"] = event.source_port
        
        return fields
    
    def _build_destination_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build destination.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.destination_ip:
            fields["ip"] = event.destination_ip
            fields["address"] = event.destination_ip
        
        if event.destination_port:
            fields["port"] = event.destination_port
        
        return fields
    
    def _build_user_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build user.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.user_name:
            fields["name"] = event.user_name
        
        if event.user_domain:
            fields["domain"] = event.user_domain
        
        return fields
    
    def _build_process_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build process.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.process_name:
            fields["name"] = event.process_name
            fields["executable"] = event.process_name
        
        if event.process_pid:
            fields["pid"] = event.process_pid
        
        if event.process_command_line:
            fields["command_line"] = event.process_command_line
        
        return fields
    
    def _build_file_fields(self, event: ParsedEvent) -> Dict[str, Any]:
        """Build file.* fields."""
        fields: Dict[str, Any] = {}
        
        if event.file_path:
            fields["path"] = event.file_path
        
        if event.file_name:
            fields["name"] = event.file_name
        
        return fields
    
    def _infer_category(self, message: str) -> List[str]:
        """Infer event category from message."""
        message_lower = message.lower()
        categories = []
        
        for keyword, cats in self.CATEGORY_MAP.items():
            if keyword in message_lower:
                for cat in cats:
                    if cat not in categories:
                        categories.append(cat)
        
        return categories[:3]  # Limit to 3 categories
    
    def _infer_action(self, message: str) -> Optional[str]:
        """Infer event action from message."""
        message_lower = message.lower()
        
        for keyword, action in self.ACTION_MAP.items():
            if keyword in message_lower:
                return action
        
        return None
    
    def _infer_outcome(self, message: str) -> str:
        """Infer event outcome from message."""
        message_lower = message.lower()
        
        failure_indicators = [
            "failed", "failure", "error", "denied", "rejected",
            "invalid", "unauthorized", "forbidden", "blocked"
        ]
        
        success_indicators = [
            "success", "accepted", "allowed", "granted", "completed"
        ]
        
        for indicator in failure_indicators:
            if indicator in message_lower:
                return "failure"
        
        for indicator in success_indicators:
            if indicator in message_lower:
                return "success"
        
        return "unknown"
    
    def to_json(self, event: ParsedEvent) -> str:
        """
        Normalize event and return as JSON string.
        
        Args:
            event: ParsedEvent to normalize
            
        Returns:
            JSON string
        """
        return json.dumps(self.normalize(event), default=str)
