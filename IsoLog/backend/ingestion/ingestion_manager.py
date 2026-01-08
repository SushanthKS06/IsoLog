
import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .syslog_collector import SyslogCollector, SyslogMessage
from .file_watcher import FileWatcher
from .usb_importer import USBImporter
from .pcap_processor import PCAPProcessor

logger = logging.getLogger(__name__)

class IngestionManager:
    
    def __init__(
        self,
        syslog_enabled: bool = True,
        syslog_udp_port: int = 1514,
        syslog_tcp_port: int = 1515,
        file_watcher_enabled: bool = True,
        watch_paths: List[str] = None,
        usb_import_dir: str = "./data/imports",
        on_raw_event: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    ):
        self.on_raw_event = on_raw_event
        
        self._syslog: Optional[SyslogCollector] = None
        self._file_watcher: Optional[FileWatcher] = None
        self._usb_importer: Optional[USBImporter] = None
        self._pcap_processor: Optional[PCAPProcessor] = None
        
        if syslog_enabled:
            self._syslog = SyslogCollector(
                udp_port=syslog_udp_port,
                tcp_port=syslog_tcp_port,
                on_message=self._handle_syslog,
            )
        
        if file_watcher_enabled and watch_paths:
            self._file_watcher = FileWatcher(
                watch_paths=watch_paths,
                on_new_lines=self._handle_file_lines,
            )
        
        self._usb_importer = USBImporter(
            import_directory=usb_import_dir,
            on_file_imported=self._handle_usb_import,
        )
        
        self._pcap_processor = PCAPProcessor()
        
        self._running = False
        self._event_queue: asyncio.Queue = None
        self._stats = {
            "total_events": 0,
            "syslog_events": 0,
            "file_events": 0,
            "usb_events": 0,
            "pcap_flows": 0,
        }
    
    async def start(self):
        self._running = True
        self._event_queue = asyncio.Queue(maxsize=50000)
        
        if self._syslog:
            await self._syslog.start()
        
        if self._file_watcher:
            await self._file_watcher.start()
        
        logger.info("Ingestion manager started")
    
    async def stop(self):
        self._running = False
        
        if self._syslog:
            await self._syslog.stop()
        
        if self._file_watcher:
            await self._file_watcher.stop()
        
        logger.info("Ingestion manager stopped")
    
    def _handle_syslog(self, msg: SyslogMessage):
        self._stats["syslog_events"] += 1
        self._stats["total_events"] += 1
        
        metadata = {
            "source_ip": msg.source_ip,
            "source_port": msg.source_port,
            "facility": msg.facility,
            "severity": msg.severity,
            "hostname": msg.hostname,
            "app_name": msg.app_name,
            "timestamp": msg.timestamp.isoformat() if msg.timestamp else None,
        }
        
        if self.on_raw_event:
            self.on_raw_event("syslog", msg.message or msg.raw, metadata)
    
    def _handle_file_lines(self, path: str, lines: List[str]):
        self._stats["file_events"] += len(lines)
        self._stats["total_events"] += len(lines)
        
        metadata = {
            "source_file": path,
            "ingestion_time": datetime.utcnow().isoformat(),
        }
        
        for line in lines:
            if line.strip() and self.on_raw_event:
                self.on_raw_event("file", line, metadata)
    
    def _handle_usb_import(self, path: str, lines: List[str]):
        self._stats["usb_events"] += len(lines)
        self._stats["total_events"] += len(lines)
        
        metadata = {
            "source_file": path,
            "import_type": "usb",
            "ingestion_time": datetime.utcnow().isoformat(),
        }
        
        for line in lines:
            if line.strip() and self.on_raw_event:
                self.on_raw_event("usb", line, metadata)
    
    async def import_from_usb(self, path: str):
        if self._usb_importer:
            return await self._usb_importer.import_from_path(path)
        return None
    
    def detect_usb_drives(self):
        if self._usb_importer:
            return self._usb_importer.detect_usb_drives()
        return []
    
    async def process_pcap(self, pcap_path: str):
        if self._pcap_processor:
            flows = self._pcap_processor.process_file(pcap_path)
            self._stats["pcap_flows"] += len(flows)
            
            for flow in flows:
                event = self._pcap_processor.flow_to_event(flow)
                if self.on_raw_event:
                    import json
                    self.on_raw_event("pcap", json.dumps(event), {"flow": True})
            
            return flows
        return []
    
    def add_watch_path(self, path: str):
        if self._file_watcher:
            self._file_watcher.add_path(path)
    
    def get_stats(self) -> Dict[str, Any]:
        stats = {**self._stats, "running": self._running}
        
        if self._syslog:
            stats["syslog"] = self._syslog.get_stats()
        
        if self._file_watcher:
            stats["file_watcher"] = self._file_watcher.get_stats()
        
        if self._usb_importer:
            stats["usb"] = self._usb_importer.get_stats()
        
        if self._pcap_processor:
            stats["pcap"] = self._pcap_processor.get_stats()
        
        return stats
