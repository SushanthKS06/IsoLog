
import asyncio
import logging
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

@dataclass
class SyslogMessage:
    raw: str
    timestamp: Optional[datetime]
    hostname: Optional[str]
    facility: int
    severity: int
    app_name: Optional[str]
    proc_id: Optional[str]
    msg_id: Optional[str]
    message: str
    source_ip: str
    source_port: int

class SyslogProtocol(asyncio.DatagramProtocol):
    
    def __init__(self, collector: "SyslogCollector"):
        self.collector = collector
    
    def datagram_received(self, data: bytes, addr: tuple):
        try:
            message = data.decode("utf-8", errors="replace").strip()
            self.collector._process_message(message, addr[0], addr[1])
        except Exception as e:
            logger.error(f"Error processing syslog UDP: {e}")

class SyslogTCPHandler:
    
    def __init__(self, collector: "SyslogCollector"):
        self.collector = collector
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        logger.debug(f"Syslog TCP connection from {addr}")
        
        buffer = ""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                buffer += data.decode("utf-8", errors="replace")
                
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        self.collector._process_message(line.strip(), addr[0], addr[1])
        except Exception as e:
            logger.error(f"Error in TCP handler: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

class SyslogCollector:
    
    FACILITIES = {
        0: "kern", 1: "user", 2: "mail", 3: "daemon",
        4: "auth", 5: "syslog", 6: "lpr", 7: "news",
        8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
        16: "local0", 17: "local1", 18: "local2", 19: "local3",
        20: "local4", 21: "local5", 22: "local6", 23: "local7",
    }
    
    SEVERITIES = {
        0: "emergency", 1: "alert", 2: "critical", 3: "error",
        4: "warning", 5: "notice", 6: "info", 7: "debug",
    }
    
    def __init__(
        self,
        udp_host: str = "0.0.0.0",
        udp_port: int = 514,
        tcp_host: str = "0.0.0.0",
        tcp_port: int = 1514,
        enable_udp: bool = True,
        enable_tcp: bool = True,
        on_message: Optional[Callable[[SyslogMessage], None]] = None,
    ):
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.enable_udp = enable_udp
        self.enable_tcp = enable_tcp
        self.on_message = on_message
        
        self._udp_transport = None
        self._tcp_server = None
        self._message_queue: asyncio.Queue = None
        self._running = False
        self._stats = {"received": 0, "errors": 0}
    
    async def start(self):
        self._running = True
        self._message_queue = asyncio.Queue(maxsize=10000)
        
        loop = asyncio.get_event_loop()
        
        if self.enable_udp:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: SyslogProtocol(self),
                    local_addr=(self.udp_host, self.udp_port),
                )
                self._udp_transport = transport
                logger.info(f"Syslog UDP listener started on {self.udp_host}:{self.udp_port}")
            except PermissionError:
                logger.warning(f"Cannot bind to UDP port {self.udp_port} (requires root)")
            except Exception as e:
                logger.error(f"Failed to start UDP listener: {e}")
        
        if self.enable_tcp:
            try:
                handler = SyslogTCPHandler(self)
                self._tcp_server = await asyncio.start_server(
                    handler.handle_client,
                    self.tcp_host,
                    self.tcp_port,
                )
                logger.info(f"Syslog TCP listener started on {self.tcp_host}:{self.tcp_port}")
            except Exception as e:
                logger.error(f"Failed to start TCP listener: {e}")
        
        logger.info("Syslog collector started")
    
    async def stop(self):
        self._running = False
        
        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None
        
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None
        
        logger.info("Syslog collector stopped")
    
    def _process_message(self, raw: str, source_ip: str, source_port: int):
        try:
            msg = self._parse_message(raw, source_ip, source_port)
            self._stats["received"] += 1
            
            if self.on_message:
                self.on_message(msg)
            
            if self._message_queue and not self._message_queue.full():
                self._message_queue.put_nowait(msg)
                
        except Exception as e:
            self._stats["errors"] += 1
            logger.debug(f"Failed to parse syslog: {e}")
    
    def _parse_message(self, raw: str, source_ip: str, source_port: int) -> SyslogMessage:
        timestamp = None
        hostname = None
        facility = 1  # user
        severity = 6  # info
        app_name = None
        proc_id = None
        msg_id = None
        message = raw
        
        if raw.startswith("<"):
            try:
                pri_end = raw.index(">")
                priority = int(raw[1:pri_end])
                facility = priority >> 3
                severity = priority & 0x07
                raw = raw[pri_end + 1:]
            except (ValueError, IndexError):
                pass
        
        if raw and raw[0].isdigit():
            parts = raw.split(" ", 7)
            if len(parts) >= 7:
                version = parts[0]
                if version == "1":  # RFC 5424
                    try:
                        timestamp = self._parse_timestamp(parts[1])
                        hostname = parts[2] if parts[2] != "-" else None
                        app_name = parts[3] if parts[3] != "-" else None
                        proc_id = parts[4] if parts[4] != "-" else None
                        msg_id = parts[5] if parts[5] != "-" else None
                        message = parts[6] if len(parts) > 6 else ""
                        
                        return SyslogMessage(
                            raw=raw, timestamp=timestamp, hostname=hostname,
                            facility=facility, severity=severity, app_name=app_name,
                            proc_id=proc_id, msg_id=msg_id, message=message,
                            source_ip=source_ip, source_port=source_port,
                        )
                    except Exception:
                        pass
        
        import re
        
        rfc3164_pattern = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
        match = re.match(rfc3164_pattern, raw)
        
        if match:
            timestamp_str, hostname, rest = match.groups()
            timestamp = self._parse_timestamp(timestamp_str)
            
            tag_match = re.match(r'^(\S+?)(?:\[(\d+)\])?:\s*(.*)$', rest)
            if tag_match:
                app_name = tag_match.group(1)
                proc_id = tag_match.group(2)
                message = tag_match.group(3)
            else:
                message = rest
        
        return SyslogMessage(
            raw=raw, timestamp=timestamp, hostname=hostname,
            facility=facility, severity=severity, app_name=app_name,
            proc_id=proc_id, msg_id=msg_id, message=message,
            source_ip=source_ip, source_port=source_port,
        )
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        from datetime import datetime
        
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%b %d %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.year == 1900:  # No year in format
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        
        return None
    
    async def get_messages(self, timeout: float = 1.0) -> List[SyslogMessage]:
        messages = []
        
        try:
            while True:
                msg = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=timeout if not messages else 0.01,
                )
                messages.append(msg)
        except asyncio.TimeoutError:
            pass
        
        return messages
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "udp_enabled": self.enable_udp,
            "tcp_enabled": self.enable_tcp,
            "running": self._running,
        }
