
import re
from datetime import datetime
from typing import Optional

from ..base_parser import BaseParser, ParsedEvent

class LinuxSyslogParser(BaseParser):
    
    parser_id = "linux_syslog"
    parser_name = "Linux Syslog Parser"
    parser_description = "Parses RFC 3164/5424 syslog format"
    supported_formats = ["syslog", "rfc3164", "rfc5424"]
    file_patterns = ["*.log", "messages*", "syslog*", "auth.log*", "secure*"]
    
    RFC3164_PATTERN = (
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>[\w\-\.\/]+)'
        r'(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)$'
    )
    
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
    
    SSH_ACCEPTED = r'Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
    SSH_FAILED = r'Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)'
    SSH_INVALID = r'Invalid user\s+(\S+)\s+from\s+(\S+)'
    
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
        if raw_log.startswith('<') and raw_log[1:4].replace('>', '').isdigit():
            return True
        
        if self._rfc3164.match(raw_log):
            return True
        
        return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        match = self._rfc5424.match(raw_log)
        if match:
            return self._parse_rfc5424(match, raw_log)
        
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
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        process = match.group("process")
        pid = match.group("pid")
        message = match.group("message")
        
        timestamp = self._parse_timestamp_syslog(timestamp_str) or datetime.utcnow()
        
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
        
        self._enrich_event(event, process, message)
        
        return event
    
    def _parse_rfc5424(self, match: re.Match, raw_log: str) -> ParsedEvent:
        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        appname = match.group("appname")
        procid = match.group("procid")
        message = match.group("message")
        
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.utcnow()
        
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
        process_lower = process.lower() if process else ""
        
        if "ssh" in process_lower:
            event.event_category = ["authentication", "network"]
            
            match = self._ssh_accepted.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "success"
                event.user_name = match.group(2)
                event.source_ip = match.group(3)
                event.source_port = int(match.group(4))
                return
            
            match = self._ssh_failed.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "failure"
                event.user_name = match.group(2)
                event.source_ip = match.group(3)
                event.source_port = int(match.group(4))
                return
            
            match = self._ssh_invalid.search(message)
            if match:
                event.event_action = "ssh_login"
                event.event_outcome = "failure"
                event.user_name = match.group(1)
                event.source_ip = match.group(2)
                return
        
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
        
        if "cron" in process_lower:
            event.event_category = ["process"]
            event.event_action = "cron_job"
            return
        
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
        
        if "pam" in message.lower():
            event.event_category = ["authentication"]
            if "authentication failure" in message.lower():
                event.event_outcome = "failure"
            elif "session opened" in message.lower():
                event.event_action = "session_start"
                event.event_outcome = "success"
            elif "session closed" in message.lower():
                event.event_action = "session_end"
