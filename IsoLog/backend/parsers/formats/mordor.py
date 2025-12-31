"""
Mordor/OTRF Security-Datasets Parser

Parses Windows Security Events from Security-Datasets (Mordor) JSON format.
These are typically Windows Event Log events exported from Sysmon or Security logs.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..base_parser import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class MordorParser(BaseParser):
    """
    Parser for OTRF Security-Datasets (Mordor) JSON format.
    
    These datasets contain Windows Event Logs exported as JSON,
    typically from Sysmon, Security, and PowerShell channels.
    """
    
    parser_id = "mordor"
    parser_name = "Mordor Security Dataset Parser"
    parser_description = "Parses OTRF Security-Datasets Windows Event JSON"
    supported_formats = ["mordor_json", "windows_event_json"]
    file_patterns = ["*.json"]
    
    # Map Windows Event IDs to actions and categories
    EVENT_ID_MAP = {
        # Sysmon Events
        1: ("process_start", ["process"]),
        3: ("network_connection", ["network"]),
        7: ("image_load", ["process"]),
        8: ("create_remote_thread", ["process"]),
        10: ("process_access", ["process"]),
        11: ("file_create", ["file"]),
        12: ("registry_create", ["registry"]),
        13: ("registry_set", ["registry"]),
        15: ("file_stream_create", ["file"]),
        22: ("dns_query", ["network"]),
        23: ("file_delete", ["file"]),
        # Windows Security Events
        4624: ("user_login", ["authentication", "iam"]),
        4625: ("logon_failure", ["authentication", "iam"]),
        4648: ("explicit_credentials", ["authentication"]),
        4656: ("object_handle_request", ["iam"]),
        4663: ("object_access", ["iam"]),
        4672: ("special_privileges", ["iam"]),
        4688: ("process_creation", ["process"]),
        4689: ("process_termination", ["process"]),
        4697: ("service_installed", ["configuration"]),
        4698: ("scheduled_task_create", ["configuration"]),
        4699: ("scheduled_task_delete", ["configuration"]),
        4720: ("user_created", ["iam"]),
        4726: ("user_deleted", ["iam"]),
        4728: ("member_added_security_group", ["iam"]),
        4732: ("member_added_local_group", ["iam"]),
        5140: ("network_share_access", ["network"]),
        5145: ("network_share_check", ["network"]),
    }
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if this looks like a Mordor JSON event."""
        try:
            data = json.loads(raw_log)
            # Mordor events typically have these Windows-specific fields
            return any(key in data for key in [
                "TimeCreated", "@timestamp", "EventID", 
                "Channel", "Computer", "Provider"
            ])
        except (json.JSONDecodeError, TypeError):
            return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """Parse a single Mordor JSON event."""
        try:
            if isinstance(raw_log, dict):
                data = raw_log
            else:
                data = json.loads(raw_log)
        except (json.JSONDecodeError, TypeError):
            return None
        
        return self._parse_event(data, source_type)
    
    def parse_dict(self, data: Dict[str, Any], source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """Parse a dictionary directly (for pre-loaded JSON)."""
        return self._parse_event(data, source_type)
    
    def _parse_event(self, data: Dict[str, Any], source_type: Optional[str]) -> Optional[ParsedEvent]:
        """Internal parsing logic."""
        # Extract timestamp
        timestamp = self._extract_timestamp(data)
        if not timestamp:
            timestamp = datetime.utcnow()
        
        # Extract Event ID and map to action/category
        event_id = data.get("EventID") or data.get("event_id")
        if isinstance(event_id, dict):
            event_id = event_id.get("Value")
        event_id = int(event_id) if event_id else None
        
        action, categories = self.EVENT_ID_MAP.get(event_id, ("unknown", ["host"]))
        
        # Build ParsedEvent
        event = ParsedEvent(
            timestamp=timestamp,
            event_kind="event",
            event_category=categories,
            event_action=action,
            event_outcome=self._determine_outcome(data),
            host_name=data.get("Computer") or data.get("Hostname"),
            source_ip=self._extract_ip_field(data, ["SourceIp", "IpAddress", "src_ip"]),
            source_port=self._extract_port_field(data, ["SourcePort", "src_port"]),
            destination_ip=self._extract_ip_field(data, ["DestinationIp", "DestAddress", "dst_ip"]),
            destination_port=self._extract_port_field(data, ["DestinationPort", "dst_port"]),
            user_name=self._extract_user(data),
            user_domain=data.get("SubjectDomainName") or data.get("TargetDomainName"),
            process_name=data.get("NewProcessName") or data.get("Image") or data.get("ProcessName"),
            process_pid=self._safe_int(data.get("ProcessId") or data.get("NewProcessId")),
            process_command_line=data.get("CommandLine") or data.get("ParentCommandLine"),
            file_path=data.get("ObjectName") or data.get("TargetFilename"),
            file_name=self._extract_filename(data),
            message=data.get("Message"),
            raw_log=json.dumps(data) if isinstance(data, dict) else str(data),
            parser_id=self.parser_id,
            source_type=source_type or "mordor",
            extra=self._build_extra_fields(data, event_id)
        )
        
        return event
    
    def _extract_timestamp(self, data: Dict[str, Any]) -> Optional[datetime]:
        """Extract timestamp from various possible fields."""
        for field in ["@timestamp", "TimeCreated", "UtcTime", "timestamp"]:
            value = data.get(field)
            if value:
                if isinstance(value, dict):
                    value = value.get("SystemTime") or value.get("#text")
                if value:
                    try:
                        # Handle ISO format
                        if isinstance(value, str):
                            value = value.replace("Z", "+00:00")
                            if "." in value:
                                # Truncate microseconds if too long
                                parts = value.split(".")
                                if "+" in parts[1]:
                                    frac, tz = parts[1].split("+")
                                    parts[1] = frac[:6] + "+" + tz
                                elif "-" in parts[1]:
                                    frac, tz = parts[1].split("-")
                                    parts[1] = frac[:6] + "-" + tz
                                else:
                                    parts[1] = parts[1][:6]
                                value = ".".join(parts)
                            return datetime.fromisoformat(value)
                    except (ValueError, AttributeError):
                        continue
        return None
    
    def _determine_outcome(self, data: Dict[str, Any]) -> str:
        """Determine event outcome."""
        event_id = data.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("Value")
        
        # Failed login events
        if event_id in [4625, 4771, 4776]:
            return "failure"
        # Successful login events
        if event_id in [4624, 4648]:
            return "success"
        
        # Check for explicit status
        status = data.get("Status") or data.get("Keywords")
        if status:
            status_str = str(status).lower()
            if "fail" in status_str or "error" in status_str:
                return "failure"
            if "success" in status_str:
                return "success"
        
        return "unknown"
    
    def _extract_user(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract username from various possible fields."""
        for field in ["TargetUserName", "SubjectUserName", "User", "UserName", "user"]:
            if data.get(field):
                user = data[field]
                # Skip system accounts for target if subject exists
                if field == "TargetUserName" and user in ["-", "SYSTEM", "LOCAL SERVICE"]:
                    continue
                return user
        return None
    
    def _extract_ip_field(self, data: Dict[str, Any], fields: List[str]) -> Optional[str]:
        """Extract IP from possible field names."""
        for field in fields:
            if data.get(field):
                ip = data[field]
                if ip and ip not in ["-", "::1", "127.0.0.1"]:
                    return ip
        return None
    
    def _extract_port_field(self, data: Dict[str, Any], fields: List[str]) -> Optional[int]:
        """Extract port from possible field names."""
        for field in fields:
            if data.get(field):
                return self._safe_int(data[field])
        return None
    
    def _extract_filename(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract filename from path."""
        for field in ["ObjectName", "TargetFilename", "Image", "NewProcessName"]:
            path = data.get(field)
            if path and isinstance(path, str):
                return path.split("\\")[-1].split("/")[-1]
        return None
    
    def _build_extra_fields(self, data: Dict[str, Any], event_id: Optional[int]) -> Dict[str, Any]:
        """
        Build extra fields dict containing ALL raw Windows fields.
        
        This is critical for Sigma rule matching - rules reference original
        Windows field names like EventID, ObjectName, TargetImage, etc.
        """
        # Start with all raw data (for Sigma matching)
        extra = dict(data)
        
        # Add normalized event_id
        extra["event_id"] = event_id
        extra["EventID"] = event_id  # Also as uppercase for Sigma rules
        
        # Ensure common fields are available at top level
        extra["Channel"] = data.get("Channel")
        extra["Provider"] = data.get("Provider") if isinstance(data.get("Provider"), str) else data.get("Provider", {}).get("Name")
        
        return extra
    
    def _safe_int(self, value: Any) -> Optional[int]:
        """Safely convert to int."""
        if value is None:
            return None
        try:
            if isinstance(value, str) and value.startswith("0x"):
                return int(value, 16)
            return int(value)
        except (ValueError, TypeError):
            return None

