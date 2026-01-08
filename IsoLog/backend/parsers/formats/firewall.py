
import re
from datetime import datetime
from typing import Optional

from ..base_parser import BaseParser, ParsedEvent

class FirewallParser(BaseParser):
    
    parser_id = "firewall"
    parser_name = "Firewall Log Parser"
    parser_description = "Parses firewall log formats (iptables, Windows Firewall)"
    supported_formats = ["firewall", "iptables", "netfilter"]
    file_patterns = ["*firewall*.log", "*iptables*.log", "*pfirewall*.log"]
    
    IPTABLES_PATTERN = (
        r'(?:.*\s)?'
        r'(?P<prefix>\[\s*\S+\s*\]\s*)?'
        r'(?P<action>IN|OUT)'
        r'.*?'
        r'SRC=(?P<src_ip>\S+)\s+'
        r'DST=(?P<dst_ip>\S+)\s+'
        r'.*?'
        r'PROTO=(?P<proto>\S+)'
        r'(?:.*?SPT=(?P<src_port>\d+))?'
        r'(?:.*?DPT=(?P<dst_port>\d+))?'
    )
    
    WINDOWS_FW_PATTERN = (
        r'(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<action>\w+)\s+'
        r'(?P<proto>\w+)\s+'
        r'(?P<src_ip>\S+)\s+'
        r'(?P<dst_ip>\S+)\s+'
        r'(?P<src_port>\d+)\s+'
        r'(?P<dst_port>\d+)'
    )
    
    KV_PATTERN = r'(\w+)=([^\s]+)'
    
    def __init__(self):
        super().__init__()
        self._iptables = re.compile(self.IPTABLES_PATTERN, re.IGNORECASE)
        self._windows_fw = re.compile(self.WINDOWS_FW_PATTERN)
        self._kv = re.compile(self.KV_PATTERN)
    
    def can_parse(self, raw_log: str) -> bool:
        raw_log_upper = raw_log.upper()
        
        if 'SRC=' in raw_log_upper and 'DST=' in raw_log_upper:
            return True
        
        if 'DROP' in raw_log_upper or 'ALLOW' in raw_log_upper:
            if re.search(r'\d+\.\d+\.\d+\.\d+', raw_log):
                return True
        
        firewall_keywords = ['BLOCKED', 'PERMITTED', 'DENIED', 'ACCEPTED', 'FIREWALL']
        for keyword in firewall_keywords:
            if keyword in raw_log_upper:
                return True
        
        return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        match = self._iptables.search(raw_log)
        if match:
            return self._parse_iptables(match, raw_log)
        
        match = self._windows_fw.match(raw_log)
        if match:
            return self._parse_windows_fw(match, raw_log)
        
        return self._parse_generic(raw_log)
    
    def _parse_iptables(self, match: re.Match, raw_log: str) -> ParsedEvent:
        direction = match.group("action")
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")
        proto = match.group("proto")
        src_port = match.group("src_port")
        dst_port = match.group("dst_port")
        
        action = "connection_allowed"
        outcome = "success"
        
        raw_upper = raw_log.upper()
        if any(kw in raw_upper for kw in ["DROP", "REJECT", "DENIED", "BLOCKED"]):
            action = "connection_blocked"
            outcome = "failure"
        
        event = ParsedEvent(
            timestamp=datetime.utcnow(),
            event_action=action,
            event_outcome=outcome,
            event_category=["network"],
            source_ip=src_ip,
            source_port=int(src_port) if src_port else None,
            destination_ip=dst_ip,
            destination_port=int(dst_port) if dst_port else None,
            message=raw_log,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="iptables",
        )
        
        event.extra = {
            "network.protocol": proto.lower() if proto else None,
            "network.direction": "inbound" if direction == "IN" else "outbound",
        }
        
        return event
    
    def _parse_windows_fw(self, match: re.Match, raw_log: str) -> ParsedEvent:
        date_str = match.group("date")
        time_str = match.group("time")
        action = match.group("action").upper()
        proto = match.group("proto")
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")
        src_port = match.group("src_port")
        dst_port = match.group("dst_port")
        
        try:
            timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = datetime.utcnow()
        
        if action in ("DROP", "BLOCK", "DENY"):
            event_action = "connection_blocked"
            outcome = "failure"
        else:
            event_action = "connection_allowed"
            outcome = "success"
        
        event = ParsedEvent(
            timestamp=timestamp,
            event_action=event_action,
            event_outcome=outcome,
            event_category=["network"],
            source_ip=src_ip,
            source_port=int(src_port) if src_port else None,
            destination_ip=dst_ip,
            destination_port=int(dst_port) if dst_port else None,
            message=raw_log,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="windows_firewall",
        )
        
        event.extra = {"network.protocol": proto.lower() if proto else None}
        
        return event
    
    def _parse_generic(self, raw_log: str) -> ParsedEvent:
        pairs = dict(self._kv.findall(raw_log))
        
        event = ParsedEvent(
            timestamp=datetime.utcnow(),
            event_category=["network"],
            message=raw_log,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="firewall",
        )
        
        field_mappings = {
            "source_ip": ["src", "srcip", "source", "saddr", "src_ip"],
            "destination_ip": ["dst", "dstip", "dest", "daddr", "dst_ip"],
            "source_port": ["sport", "src_port", "srcport"],
            "destination_port": ["dport", "dst_port", "dstport"],
            "user_name": ["user", "usr", "username"],
        }
        
        for field, keys in field_mappings.items():
            for key in keys:
                if key.lower() in {k.lower() for k in pairs}:
                    matching_key = next(k for k in pairs if k.lower() == key.lower())
                    value = pairs[matching_key]
                    if field.endswith("_port"):
                        try:
                            setattr(event, field, int(value))
                        except ValueError:
                            pass
                    else:
                        setattr(event, field, value)
                    break
        
        raw_upper = raw_log.upper()
        if any(kw in raw_upper for kw in ["BLOCK", "DROP", "DENY", "REJECT"]):
            event.event_action = "connection_blocked"
            event.event_outcome = "failure"
        elif any(kw in raw_upper for kw in ["ALLOW", "ACCEPT", "PERMIT"]):
            event.event_action = "connection_allowed"
            event.event_outcome = "success"
        
        return event
