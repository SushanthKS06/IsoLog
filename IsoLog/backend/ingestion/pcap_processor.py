"""
IsoLog PCAP Processor

Extract network flow metadata from PCAP files.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkFlow:
    """Network flow extracted from PCAP."""
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets: int
    duration_ms: int
    flags: Optional[str] = None


class PCAPProcessor:
    """
    Process PCAP files to extract network flow metadata.
    
    Note: Requires scapy for full functionality.
    Falls back to basic parsing if scapy unavailable.
    """
    
    def __init__(self):
        """Initialize PCAP processor."""
        self._scapy_available = self._check_scapy()
        self._stats = {"files_processed": 0, "flows_extracted": 0}
    
    def _check_scapy(self) -> bool:
        """Check if scapy is available."""
        try:
            from scapy.all import rdpcap
            return True
        except ImportError:
            logger.warning("scapy not available, PCAP processing will be limited")
            return False
    
    def process_file(self, pcap_path: str, max_packets: int = 100000) -> List[NetworkFlow]:
        """
        Process a PCAP file and extract network flows.
        
        Args:
            pcap_path: Path to PCAP file
            max_packets: Maximum packets to process
            
        Returns:
            List of network flows
        """
        path = Path(pcap_path)
        
        if not path.exists():
            logger.error(f"PCAP file not found: {pcap_path}")
            return []
        
        if not self._scapy_available:
            logger.warning("scapy not available, cannot process PCAP")
            return []
        
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            
            flows: Dict[str, Dict[str, Any]] = {}
            packets = rdpcap(str(path), count=max_packets)
            
            for pkt in packets:
                if IP in pkt:
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
                    
                    src_port = 0
                    dst_port = 0
                    flags = None
                    
                    if TCP in pkt:
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        flags = str(pkt[TCP].flags)
                    elif UDP in pkt:
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    
                    # Create flow key
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                    
                    if flow_key not in flows:
                        flows[flow_key] = {
                            "first_seen": float(pkt.time),
                            "last_seen": float(pkt.time),
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": proto,
                            "bytes": 0,
                            "packets": 0,
                            "flags": flags,
                        }
                    
                    flow = flows[flow_key]
                    flow["last_seen"] = float(pkt.time)
                    flow["bytes"] += len(pkt)
                    flow["packets"] += 1
            
            # Convert to NetworkFlow objects
            result = []
            for flow_key, flow_data in flows.items():
                duration_ms = int((flow_data["last_seen"] - flow_data["first_seen"]) * 1000)
                
                result.append(NetworkFlow(
                    timestamp=datetime.fromtimestamp(flow_data["first_seen"]),
                    source_ip=flow_data["src_ip"],
                    source_port=flow_data["src_port"],
                    dest_ip=flow_data["dst_ip"],
                    dest_port=flow_data["dst_port"],
                    protocol=flow_data["protocol"],
                    bytes_sent=flow_data["bytes"],
                    bytes_received=0,  # Would need bidirectional analysis
                    packets=flow_data["packets"],
                    duration_ms=duration_ms,
                    flags=flow_data["flags"],
                ))
            
            self._stats["files_processed"] += 1
            self._stats["flows_extracted"] += len(result)
            
            logger.info(f"Extracted {len(result)} flows from {pcap_path}")
            return result
            
        except Exception as e:
            logger.error(f"Error processing PCAP {pcap_path}: {e}")
            return []
    
    def flow_to_event(self, flow: NetworkFlow) -> Dict[str, Any]:
        """Convert network flow to ECS-compatible event."""
        return {
            "@timestamp": flow.timestamp.isoformat(),
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["connection"],
                "action": "network_flow",
            },
            "source": {
                "ip": flow.source_ip,
                "port": flow.source_port,
                "bytes": flow.bytes_sent,
                "packets": flow.packets,
            },
            "destination": {
                "ip": flow.dest_ip,
                "port": flow.dest_port,
            },
            "network": {
                "protocol": flow.protocol.lower(),
                "bytes": flow.bytes_sent + flow.bytes_received,
                "packets": flow.packets,
            },
            "event": {
                "duration": flow.duration_ms * 1000000,  # nanoseconds
            },
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            **self._stats,
            "scapy_available": self._scapy_available,
        }
