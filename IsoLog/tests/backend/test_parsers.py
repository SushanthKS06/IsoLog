"""
Tests for log parsers.
"""

import pytest
from datetime import datetime

from backend.parsers.base_parser import ParsedEvent
from backend.parsers.formats.linux_syslog import LinuxSyslogParser
from backend.parsers.formats.json_generic import JSONGenericParser
from backend.parsers.formats.csv_generic import CSVGenericParser
from backend.parsers.formats.windows_event import WindowsEventParser
from backend.parsers.formats.firewall import FirewallParser


class TestLinuxSyslogParser:
    """Tests for Linux syslog parser."""
    
    @pytest.fixture
    def parser(self):
        return LinuxSyslogParser()
    
    def test_can_parse_rfc3164(self, parser):
        log = "Dec 31 10:00:00 webserver sshd[1234]: Accepted password for admin from 192.168.1.100 port 52431 ssh2"
        assert parser.can_parse(log) == True
    
    def test_parse_ssh_success(self, parser):
        log = "Dec 31 10:00:00 webserver sshd[1234]: Accepted password for admin from 192.168.1.100 port 52431 ssh2"
        event = parser.parse(log)
        
        assert event is not None
        assert event.hostname == "webserver"
        assert event.user == "admin"
        assert event.source_ip == "192.168.1.100"
        assert event.action == "ssh_login"
        assert event.outcome == "success"
    
    def test_parse_ssh_failure(self, parser):
        log = "Dec 31 10:00:15 webserver sshd[1235]: Failed password for invalid user test from 10.0.0.50 port 43210 ssh2"
        event = parser.parse(log)
        
        assert event is not None
        assert event.outcome == "failure"
        assert "10.0.0.50" in event.source_ip
    
    def test_parse_sudo(self, parser):
        log = "Dec 31 10:01:00 webserver sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        event = parser.parse(log)
        
        assert event is not None
        assert event.action == "sudo_command"
        assert "admin" in event.user
    
    def test_invalid_log(self, parser):
        log = "This is not a valid syslog message"
        assert parser.can_parse(log) == False


class TestJSONParser:
    """Tests for JSON parser."""
    
    @pytest.fixture
    def parser(self):
        return JSONGenericParser()
    
    def test_can_parse_json(self, parser):
        log = '{"message": "test", "level": "info"}'
        assert parser.can_parse(log) == True
    
    def test_parse_simple_json(self, parser):
        log = '{"message": "User logged in", "user": "admin", "ip": "192.168.1.1"}'
        event = parser.parse(log)
        
        assert event is not None
        assert event.message == "User logged in"
    
    def test_parse_ecs_json(self, parser):
        log = '{"@timestamp": "2024-12-31T10:00:00Z", "event": {"action": "login"}, "user": {"name": "admin"}}'
        event = parser.parse(log)
        
        assert event is not None
        assert event.user == "admin"
    
    def test_invalid_json(self, parser):
        log = "not json at all"
        assert parser.can_parse(log) == False


class TestCSVParser:
    """Tests for CSV parser."""
    
    @pytest.fixture
    def parser(self):
        return CSVGenericParser()
    
    def test_can_parse_csv(self, parser):
        log = "2024-12-31,admin,login,success"
        assert parser.can_parse(log) == True
    
    def test_parse_csv_row(self, parser):
        # First pass header
        parser.parse("timestamp,user,action,outcome")
        event = parser.parse("2024-12-31T10:00:00,admin,login,success")
        
        assert event is not None


class TestWindowsEventParser:
    """Tests for Windows Event parser."""
    
    @pytest.fixture
    def parser(self):
        return WindowsEventParser()
    
    def test_can_parse_windows_json(self, parser):
        log = '{"EventID": 4624, "Computer": "DC01", "Message": "An account was successfully logged on."}'
        assert parser.can_parse(log) == True
    
    def test_parse_windows_logon(self, parser):
        log = '{"EventID": 4624, "Computer": "DC01", "TargetUserName": "admin"}'
        event = parser.parse(log)
        
        assert event is not None
        assert event.hostname == "DC01"


class TestFirewallParser:
    """Tests for Firewall parser."""
    
    @pytest.fixture
    def parser(self):
        return FirewallParser()
    
    def test_can_parse_iptables(self, parser):
        log = "[UFW BLOCK] IN=eth0 SRC=192.168.1.1 DST=192.168.1.2 PROTO=TCP DPT=22"
        assert parser.can_parse(log) == True
    
    def test_parse_iptables_block(self, parser):
        log = "Dec 31 10:00:00 server kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.5 PROTO=TCP SPT=12345 DPT=22"
        event = parser.parse(log)
        
        assert event is not None
        assert event.source_ip == "10.0.0.1"
        assert "block" in event.action.lower()
