"""
IsoLog Base Parser

Abstract base class for all log parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Pattern
import re


@dataclass
class ParsedEvent:
    """
    Parsed log event in ECS-compatible format.
    
    This is the intermediate format between raw logs and database storage.
    """
    # Core timestamp
    timestamp: datetime
    
    # Event fields
    event_kind: str = "event"  # event, alert, metric, state, pipeline_error
    event_category: List[str] = field(default_factory=list)  # e.g., ["authentication", "iam"]
    event_action: Optional[str] = None  # e.g., "login", "logout"
    event_outcome: Optional[str] = None  # success, failure, unknown
    
    # Host fields
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    
    # Source fields
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    
    # Destination fields
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    
    # User fields
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    
    # Process fields
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_command_line: Optional[str] = None
    
    # File fields
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    
    # Original data
    message: Optional[str] = None
    raw_log: Optional[str] = None
    
    # Parser metadata
    parser_id: Optional[str] = None
    source_type: Optional[str] = None
    
    # Additional fields
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
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
    """
    Abstract base class for log parsers.
    
    All parser implementations must inherit from this class and implement
    the required methods.
    """
    
    # Parser identification
    parser_id: str = "base"
    parser_name: str = "Base Parser"
    parser_description: str = "Base parser class"
    
    # Patterns this parser can handle
    supported_formats: List[str] = []  # e.g., ["syslog", "windows_event"]
    file_patterns: List[str] = []  # e.g., ["*.log", "messages*"]
    
    def __init__(self):
        """Initialize parser."""
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if this parser can handle the given log line.
        
        Args:
            raw_log: Raw log line or data
            
        Returns:
            True if this parser can handle the log
        """
        pass
    
    @abstractmethod
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """
        Parse a single log line into a ParsedEvent.
        
        Args:
            raw_log: Raw log line or data
            source_type: Optional source type hint
            
        Returns:
            ParsedEvent or None if parsing fails
        """
        pass
    
    def parse_batch(
        self, 
        raw_logs: List[str], 
        source_type: Optional[str] = None
    ) -> List[ParsedEvent]:
        """
        Parse multiple log lines.
        
        Args:
            raw_logs: List of raw log lines
            source_type: Optional source type hint
            
        Returns:
            List of successfully parsed events
        """
        events = []
        for raw_log in raw_logs:
            try:
                event = self.parse(raw_log, source_type)
                if event:
                    events.append(event)
            except Exception:
                # Skip failed parses
                continue
        return events
    
    def _compile_pattern(self, name: str, pattern: str) -> Pattern:
        """
        Compile and cache a regex pattern.
        
        Args:
            name: Pattern name for caching
            pattern: Regex pattern string
            
        Returns:
            Compiled pattern
        """
        if name not in self._compiled_patterns:
            self._compiled_patterns[name] = re.compile(pattern)
        return self._compiled_patterns[name]
    
    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract IP address from text."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None
    
    def _extract_port(self, text: str) -> Optional[int]:
        """Extract port number from text."""
        port_pattern = r':(\d{1,5})\b'
        match = re.search(port_pattern, text)
        if match:
            port = int(match.group(1))
            if 0 < port <= 65535:
                return port
        return None
    
    def _parse_timestamp_syslog(self, timestamp_str: str) -> Optional[datetime]:
        """Parse syslog-style timestamp."""
        from ..utils.helpers import parse_timestamp
        return parse_timestamp(timestamp_str)
