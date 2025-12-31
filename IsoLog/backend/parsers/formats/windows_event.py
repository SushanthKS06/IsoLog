"""
IsoLog Windows Event Parser

Parses Windows Event Log format.
"""

import json
import re
from datetime import datetime
from typing import Optional

from ..base_parser import BaseParser, ParsedEvent


class WindowsEventParser(BaseParser):
    """
    Parser for Windows Event Log format.
    
    Handles:
    - XML event log format
    - JSON exported events
    - Text-based event log exports
    """
    
    parser_id = "windows_event"
    parser_name = "Windows Event Parser"
    parser_description = "Parses Windows Event Log format"
    supported_formats = ["evtx", "windows_event"]
    file_patterns = ["*.evtx", "*Security*.log", "*System*.log"]
    
    # Windows security event IDs
    SECURITY_EVENTS = {
        4624: ("logon_success", "authentication", "success"),
        4625: ("logon_failure", "authentication", "failure"),
        4634: ("logoff", "session", "success"),
        4647: ("user_logoff", "session", "success"),
        4648: ("explicit_logon", "authentication", "success"),
        4672: ("special_privileges", "authentication", "success"),
        4688: ("process_create", "process", "success"),
        4689: ("process_terminate", "process", "success"),
        4720: ("user_created", "iam", "success"),
        4722: ("user_enabled", "iam", "success"),
        4723: ("password_change", "authentication", "success"),
        4724: ("password_reset", "authentication", "success"),
        4725: ("user_disabled", "iam", "success"),
        4726: ("user_deleted", "iam", "success"),
        4728: ("member_added_global_group", "iam", "success"),
        4732: ("member_added_local_group", "iam", "success"),
        4768: ("kerberos_tgt_request", "authentication", None),
        4769: ("kerberos_service_ticket", "authentication", None),
        4776: ("ntlm_validation", "authentication", None),
        5140: ("network_share_access", "file", None),
        5145: ("network_share_check", "file", None),
    }
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if this looks like Windows event."""
        raw_log = raw_log.strip()
        
        # Check for XML event
        if '<Event xmlns' in raw_log or '<Event>' in raw_log:
            return True
        
        # Check for JSON with EventID
        if raw_log.startswith('{') and '"EventID"' in raw_log:
            return True
        
        # Check for text format with event ID
        if re.search(r'Event\s*ID:?\s*\d+', raw_log, re.IGNORECASE):
            return True
        
        return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """Parse Windows event."""
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        # Try JSON format first
        if raw_log.startswith('{'):
            return self._parse_json(raw_log)
        
        # Try XML format
        if '<Event' in raw_log:
            return self._parse_xml(raw_log)
        
        # Try text format
        return self._parse_text(raw_log)
    
    def _parse_json(self, raw_log: str) -> Optional[ParsedEvent]:
        """Parse JSON-formatted Windows event."""
        try:
            data = json.loads(raw_log)
        except json.JSONDecodeError:
            return None
        
        event_id = data.get("EventID") or data.get("event_id") or data.get("Id")
        if isinstance(event_id, dict):
            event_id = event_id.get("Value")
        
        if event_id:
            try:
                event_id = int(event_id)
            except (ValueError, TypeError):
                event_id = None
        
        # Extract timestamp
        timestamp = datetime.utcnow()
        for ts_field in ["TimeCreated", "time_created", "@timestamp", "timestamp"]:
            if ts_field in data:
                ts = data[ts_field]
                if isinstance(ts, dict):
                    ts = ts.get("SystemTime") or ts.get("@SystemTime")
                if ts:
                    try:
                        timestamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                        break
                    except ValueError:
                        continue
        
        # Extract computer name
        computer = (
            data.get("Computer") or 
            data.get("computer") or 
            data.get("MachineName")
        )
        
        # Extract event data
        event_data = data.get("EventData") or data.get("event_data") or {}
        if isinstance(event_data, dict):
            event_data = event_data.get("Data", event_data)
        
        # Create event
        event = ParsedEvent(
            timestamp=timestamp,
            host_name=computer,
            message=data.get("Message") or data.get("message") or str(event_data),
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type=source_type or "windows_event",
        )
        
        # Map event ID to action/category
        if event_id and event_id in self.SECURITY_EVENTS:
            action, category, outcome = self.SECURITY_EVENTS[event_id]
            event.event_action = action
            event.event_category = ["windows", category]
            if outcome:
                event.event_outcome = outcome
        
        # Extract user from event data
        if isinstance(event_data, dict):
            event.user_name = (
                event_data.get("TargetUserName") or
                event_data.get("SubjectUserName") or
                event_data.get("User")
            )
            event.user_domain = (
                event_data.get("TargetDomainName") or
                event_data.get("SubjectDomainName")
            )
            event.source_ip = (
                event_data.get("IpAddress") or
                event_data.get("SourceAddress")
            )
            event.process_name = event_data.get("ProcessName")
        
        event.extra = {"event_id": event_id}
        
        return event
    
    def _parse_xml(self, raw_log: str) -> Optional[ParsedEvent]:
        """Parse XML-formatted Windows event."""
        # Simple regex-based extraction (avoid XML lib for portability)
        
        # Extract EventID
        event_id = None
        match = re.search(r'<EventID[^>]*>(\d+)</EventID>', raw_log)
        if match:
            event_id = int(match.group(1))
        
        # Extract TimeCreated
        timestamp = datetime.utcnow()
        match = re.search(r'SystemTime=["\']([^"\']+)["\']', raw_log)
        if match:
            try:
                timestamp = datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
            except ValueError:
                pass
        
        # Extract Computer
        computer = None
        match = re.search(r'<Computer>([^<]+)</Computer>', raw_log)
        if match:
            computer = match.group(1)
        
        event = ParsedEvent(
            timestamp=timestamp,
            host_name=computer,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="windows_event",
        )
        
        # Map event ID
        if event_id and event_id in self.SECURITY_EVENTS:
            action, category, outcome = self.SECURITY_EVENTS[event_id]
            event.event_action = action
            event.event_category = ["windows", category]
            if outcome:
                event.event_outcome = outcome
        
        event.extra = {"event_id": event_id}
        
        return event
    
    def _parse_text(self, raw_log: str) -> Optional[ParsedEvent]:
        """Parse text-formatted Windows event."""
        # Extract event ID
        event_id = None
        match = re.search(r'Event\s*ID:?\s*(\d+)', raw_log, re.IGNORECASE)
        if match:
            event_id = int(match.group(1))
        
        # Extract timestamp
        timestamp = datetime.utcnow()
        match = re.search(r'(\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2})', raw_log)
        if match:
            try:
                timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    timestamp = datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
                except ValueError:
                    pass
        
        event = ParsedEvent(
            timestamp=timestamp,
            message=raw_log,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="windows_event",
        )
        
        # Map event ID
        if event_id and event_id in self.SECURITY_EVENTS:
            action, category, outcome = self.SECURITY_EVENTS[event_id]
            event.event_action = action
            event.event_category = ["windows", category]
            if outcome:
                event.event_outcome = outcome
        
        event.extra = {"event_id": event_id}
        
        return event
