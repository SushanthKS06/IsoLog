
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Pattern
import re

@dataclass
class ParsedEvent:
    timestamp: datetime
    
    event_kind: str = "event"  # event, alert, metric, state, pipeline_error
    event_category: List[str] = field(default_factory=list)  # e.g., ["authentication", "iam"]
    event_action: Optional[str] = None  # e.g., "login", "logout"
    event_outcome: Optional[str] = None  # success, failure, unknown
    
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_command_line: Optional[str] = None
    
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    
    message: Optional[str] = None
    raw_log: Optional[str] = None
    
    parser_id: Optional[str] = None
    source_type: Optional[str] = None
    
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event": {
                "kind": self.event_kind,
                "category": self.event_category,
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
            "raw_log": self.raw_log,
            "parser_id": self.parser_id,
            "source_type": self.source_type,
            **self.extra,
        }

class BaseParser(ABC):
    
    parser_id: str = "base"
    parser_name: str = "Base Parser"
    parser_description: str = "Base parser class"
    
    supported_formats: List[str] = []  # e.g., ["syslog", "windows_event"]
    file_patterns: List[str] = []  # e.g., ["*.log", "messages*"]
    
    def __init__(self):
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        pass
    
    @abstractmethod
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        pass
    
    def parse_batch(
        self, 
        raw_logs: List[str], 
        source_type: Optional[str] = None
    ) -> List[ParsedEvent]:
        events = []
        for raw_log in raw_logs:
            try:
                event = self.parse(raw_log, source_type)
                if event:
                    events.append(event)
            except Exception:
                continue
        return events
    
    def _compile_pattern(self, name: str, pattern: str) -> Pattern:
        if name not in self._compiled_patterns:
            self._compiled_patterns[name] = re.compile(pattern)
        return self._compiled_patterns[name]
    
    def _extract_ip(self, text: str) -> Optional[str]:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
    
    def _extract_port(self, text: str) -> Optional[int]:
        port_pattern = r':(\d{1,5})\b'
        match = re.search(port_pattern, text)
        if match:
            port = int(match.group(1))
            if 0 < port <= 65535:
                return port
        return None
    
    def _parse_timestamp_syslog(self, timestamp_str: str) -> Optional[datetime]:
        from ..utils.helpers import parse_timestamp
        return parse_timestamp(timestamp_str)
