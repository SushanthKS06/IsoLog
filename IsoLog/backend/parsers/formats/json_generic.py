
import json
from datetime import datetime
from typing import Any, Dict, Optional

from ..base_parser import BaseParser, ParsedEvent

class JSONGenericParser(BaseParser):
    
    parser_id = "json_generic"
    parser_name = "JSON Generic Parser"
    parser_description = "Parses generic JSON log format"
    supported_formats = ["json", "jsonl", "ndjson"]
    file_patterns = ["*.json", "*.jsonl", "*.ndjson"]
    
    TIMESTAMP_FIELDS = [
        "@timestamp", "timestamp", "time", "datetime", "date",
        "eventTime", "event_time", "created", "logged_at"
    ]
    
    MESSAGE_FIELDS = [
        "message", "msg", "log", "text", "description", "event"
    ]
    
    HOST_FIELDS = [
        "host", "hostname", "host_name", "server", "machine"
    ]
    
    IP_FIELDS = [
        "ip", "ipAddress", "ip_address", "clientIp", "client_ip",
        "sourceIp", "source_ip", "remoteAddr", "remote_addr"
    ]
    
    USER_FIELDS = [
        "user", "username", "user_name", "account", "identity"
    ]
    
    ACTION_FIELDS = [
        "action", "event", "eventType", "event_type", "operation"
    ]
    
    LEVEL_FIELDS = [
        "level", "severity", "priority", "log_level"
    ]
    
    def can_parse(self, raw_log: str) -> bool:
        raw_log = raw_log.strip()
        if not raw_log:
            return False
        
        if not (raw_log.startswith('{') and raw_log.endswith('}')):
            return False
        
        try:
            json.loads(raw_log)
            return True
        except json.JSONDecodeError:
            return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        try:
            data = json.loads(raw_log)
        except json.JSONDecodeError:
            return None
        
        if not isinstance(data, dict):
            return None
        
        timestamp = self._extract_timestamp(data)
        
        event = ParsedEvent(
            timestamp=timestamp,
            message=self._extract_field(data, self.MESSAGE_FIELDS),
            host_name=self._extract_field(data, self.HOST_FIELDS),
            source_ip=self._extract_field(data, self.IP_FIELDS),
            user_name=self._extract_field(data, self.USER_FIELDS),
            event_action=self._extract_field(data, self.ACTION_FIELDS),
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type=source_type or "json",
        )
        
        self._extract_nested_fields(event, data)
        
        level = self._extract_field(data, self.LEVEL_FIELDS)
        if level:
            level_lower = str(level).lower()
            if level_lower in ("error", "critical", "fatal"):
                event.event_kind = "alert"
            elif level_lower == "warn" or level_lower == "warning":
                event.event_category = ["configuration"]
        
        event.extra = self._get_extra_fields(data)
        
        return event
    
    def _extract_timestamp(self, data: Dict[str, Any]) -> datetime:
        for field in self.TIMESTAMP_FIELDS:
            if field in data:
                ts = data[field]
                if isinstance(ts, str):
                    try:
                        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        pass
                    
                    try:
                        for fmt in [
                            "%Y-%m-%dT%H:%M:%S.%f",
                            "%Y-%m-%d %H:%M:%S",
                            "%Y/%m/%d %H:%M:%S",
                        ]:
                            return datetime.strptime(ts, fmt)
                    except ValueError:
                        continue
                
                elif isinstance(ts, (int, float)):
                    try:
                        if ts > 1e12:  # Milliseconds
                            ts = ts / 1000
                        return datetime.utcfromtimestamp(ts)
                    except (ValueError, OSError):
                        pass
        
        return datetime.utcnow()
    
    def _extract_field(
        self, 
        data: Dict[str, Any], 
        field_names: list,
    ) -> Optional[str]:
        for field in field_names:
            if field in data:
                value = data[field]
                if isinstance(value, str):
                    return value
                elif isinstance(value, dict):
                    for subfield in ["name", "value", "id"]:
                        if subfield in value:
                            return str(value[subfield])
                elif value is not None:
                    return str(value)
        return None
    
    def _extract_nested_fields(self, event: ParsedEvent, data: Dict[str, Any]):
        if "source" in data and isinstance(data["source"], dict):
            source = data["source"]
            event.source_ip = source.get("ip") or source.get("address")
            event.source_port = source.get("port")
        
        if "destination" in data and isinstance(data["destination"], dict):
            dest = data["destination"]
            event.destination_ip = dest.get("ip") or dest.get("address")
            event.destination_port = dest.get("port")
        
        if "user" in data and isinstance(data["user"], dict):
            user = data["user"]
            event.user_name = user.get("name") or user.get("username")
            event.user_domain = user.get("domain")
        
        if "process" in data and isinstance(data["process"], dict):
            proc = data["process"]
            event.process_name = proc.get("name") or proc.get("executable")
            event.process_pid = proc.get("pid")
            event.process_command_line = proc.get("command_line") or proc.get("cmdline")
        
        if "file" in data and isinstance(data["file"], dict):
            file_obj = data["file"]
            event.file_path = file_obj.get("path")
            event.file_name = file_obj.get("name")
        
        if "event" in data and isinstance(data["event"], dict):
            evt = data["event"]
            if "category" in evt:
                cat = evt["category"]
                event.event_category = cat if isinstance(cat, list) else [cat]
            if "action" in evt:
                event.event_action = evt["action"]
            if "outcome" in evt:
                event.event_outcome = evt["outcome"]
    
    def _get_extra_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        known_fields = set()
        for field_list in [
            self.TIMESTAMP_FIELDS, self.MESSAGE_FIELDS, self.HOST_FIELDS,
            self.IP_FIELDS, self.USER_FIELDS, self.ACTION_FIELDS, self.LEVEL_FIELDS,
        ]:
            known_fields.update(field_list)
        
        known_fields.update(["source", "destination", "user", "process", "file", "event", "host"])
        
        extra = {}
        for key, value in data.items():
            if key not in known_fields:
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        extra[f"{key}.{subkey}"] = subvalue
                else:
                    extra[key] = value
        
        return extra
