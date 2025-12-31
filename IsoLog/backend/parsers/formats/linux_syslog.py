"""
IsoLog Linux Syslog Parser

Parses standard Linux syslog format (RFC 3164 and RFC 5424).
"""

import re
from datetime import datetime
from typing import Optional

from ..base_parser import BaseParser, ParsedEvent


class LinuxSyslogParser(BaseParser):
    """
    Parser for Linux syslog format.
    
    Supports:
    - RFC 3164 (BSD syslog)
    - RFC 5424 (IETF syslog)
    - Common variations
    """
    
    parser_id = "linux_syslog"
    parser_name = "Linux Syslog Parser"
    parser_description = "Parses RFC 3164/5424 syslog format"
    supported_formats = ["syslog", "rfc3164", "rfc5424"]
    file_patterns = ["*.log", "messages*", "syslog*", "auth.log*", "secure*"]
    
    # RFC 3164 pattern: Month Day HH:MM:SS hostname process[pid]: message
    RFC3164_PATTERN = (
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[\w\-\.\/]+)'
        r'(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)$'
    )
    
    # RFC 5424 pattern: <priority>version timestamp hostname app-name procid msgid structured-data msg
    RFC5424_PATTERN = (
        r'^<(?P<priority>\d+)>(?P<version>\d+)\s+'
        r'(?P<timestamp>\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<appname>\S+)\s+'
        r'(?P<procid>\S+)\s+'
        r'(?P<msgid>\S+)\s+'
        r'(?P<structured_data>(?:\[.*?\])+|-)\s*'
        r'(?P<message>.*)$'
    )
    
    # SSH auth patterns
    SSH_ACCEPTED = r'Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
    SSH_FAILED = r'Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
    SSH_INVALID = r'Invalid user\s+(\S+)\s+from\s+(\S+)'
    
    # Sudo patterns
    SUDO_PATTERN = r'(\S+)\s*:\s*.*COMMAND=(.+)$'
    
    def __init__(self):
        super().__init__()
        self._rfc3164 = re.compile(self.RFC3164_PATTERN)
        self._rfc5424 = re.compile(self.RFC5424_PATTERN)
        self._ssh_accepted = re.compile(self.SSH_ACCEPTED)
        self._ssh_failed = re.compile(self.SSH_FAILED)
        self._ssh_invalid = re.compile(self.SSH_INVALID)
        self._sudo = re.compile(self.SUDO_PATTERN)
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if this looks like syslog format."""
        # Check for RFC 5424 priority
        if raw_log.startswith('<') and raw_log[1:4].replace('>', '').isdigit():
            return True
        
        # Check for RFC 3164 timestamp
        if self._rfc3164.match(raw_log):
            return True
        
        return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """Parse syslog line."""
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        # Try RFC 5424 first (more structured)
        match = self._rfc5424.match(raw_log)
        if match:
            return self._parse_rfc5424(match, raw_log)
        
        # Try RFC 3164
        match = self._rfc3164.match(raw_log)
        if match:
            return self._parse_rfc3164(match, raw_log, source_type)
        
        return None
    
    def _parse_rfc3164(
        self, 
        match: re.Match, 
        raw_log: str,
        source_type: Optional[str] = None,
    ) -> ParsedEvent:
        """Parse RFC 3164 syslog."""
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        process = match.group("process")
        pid = match.group("pid")
        message = match.group("message")
        
        # Parse timestamp (add current year)
        timestamp = self._parse_timestamp_syslog(timestamp_str) or datetime.utcnow()
        
        # Create base event
        event = ParsedEvent(
            timestamp=timestamp,
            host_name=hostname,
            process_name=process,
            process_pid=int(pid) if pid else None,
            message=message,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type=source_type or "syslog",
        )
        
        # Extract additional info based on process/message
        self._enrich_event(event, process, message)
        
        return event
    
    def _parse_rfc5424(self, match: re.Match, raw_log: str) -> ParsedEvent:
        """Parse RFC 5424 syslog."""
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        appname = match.group("appname")
        procid = match.group("procid")
        message = match.group("message")
        
        # Parse ISO timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.utcnow()
        
        # Handle nil values
        if hostname == "-":
            hostname = None
        if appname == "-":
            appname = None
        
        pid = None
        if procid and procid != "-":
            try:
                pid = int(procid)
            except ValueError:
                pass
        
        event = ParsedEvent(
            timestamp=timestamp,
            host_name=hostname,
            process_name=appname,
            process_pid=pid,
            message=message,
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type="syslog",
        )
        
        if appname:
            self._enrich_event(event, appname, message)
        
        return event
    
    def _enrich_event(self, event: ParsedEvent, process: str, message: str):
        """Enrich event based on process type and message content."""
        process_lower = process.lower() if process else ""
        
        # SSH authentication
        if "ssh" in process_lower:
            event.event_category = ["authentication", "network"]
            
            # Accepted login
            match = self._ssh_accepted.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "success"
                event.user_name = match.group(2)
                event.source_ip = match.group(3)
                event.source_port = int(match.group(4))
                return
            
            # Failed login
            match = self._ssh_failed.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "failure"
                event.user_name = match.group(2)
                event.source_ip = match.group(3)
                event.source_port = int(match.group(4))
                return
            
            # Invalid user
            match = self._ssh_invalid.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "failure"
                event.user_name = match.group(1)
                event.source_ip = match.group(2)
                return
        
        # Sudo
        if "sudo" in process_lower:
            event.event_category = ["process", "authentication"]
            event.event_action = "sudo"
            
            match = self._sudo.search(message)
            if match:
                event.user_name = match.group(1)
                event.process_command_line = match.group(2)
                event.event_outcome = "success"
            
            if "incorrect password" in message.lower():
                event.event_outcome = "failure"
            elif "NOT in sudoers" in message:
                event.event_outcome = "failure"
            return
        
        # Cron
        if "cron" in process_lower:
            event.event_category = ["process"]
            event.event_action = "cron_job"
            return
        
        # Systemd
        if "systemd" in process_lower:
            event.event_category = ["process"]
            if "started" in message.lower():
                event.event_action = "service_started"
            elif "stopped" in message.lower():
                event.event_action = "service_stopped"
            elif "failed" in message.lower():
                event.event_action = "service_failed"
                event.event_outcome = "failure"
            return
        
        # PAM authentication
        if "pam" in message.lower():
            event.event_category = ["authentication"]
            if "authentication failure" in message.lower():
                event.event_outcome = "failure"
            elif "session opened" in message.lower():
                event.event_action = "session_start"
                event.event_outcome = "success"
            elif "session closed" in message.lower():
                event.event_action = "session_end"
