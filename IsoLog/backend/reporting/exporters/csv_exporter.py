
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class CSVExporter:
    
    def export_alerts(self, alerts: List[Dict[str, Any]], output_path: str):
        if not alerts:
            self._write_empty(output_path, ["timestamp", "severity", "rule_name", "description"])
            return
        
        headers = [
            "id", "timestamp", "severity", "rule_name", "rule_description",
            "detection_type", "threat_score", "status", "mitre_tactics",
            "mitre_techniques", "host", "user", "source_ip",
        ]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            
            for alert in alerts:
                row = {
                    "id": alert.get("id", ""),
                    "timestamp": alert.get("created_at", ""),
                    "severity": alert.get("severity", ""),
                    "rule_name": alert.get("rule_name", ""),
                    "rule_description": alert.get("rule_description", ""),
                    "detection_type": alert.get("detection_type", ""),
                    "threat_score": alert.get("threat_score", ""),
                    "status": alert.get("status", ""),
                    "mitre_tactics": ",".join(alert.get("mitre_tactics", [])),
                    "mitre_techniques": ",".join(alert.get("mitre_techniques", [])),
                    "host": self._extract_nested(alert, "event_summary.host", ""),
                    "user": self._extract_nested(alert, "event_summary.user", ""),
                    "source_ip": self._extract_nested(alert, "event_summary.source_ip", ""),
                }
                writer.writerow(row)
        
        logger.info(f"Exported {len(alerts)} alerts to {output_path}")
    
    def export_events(self, events: List[Dict[str, Any]], output_path: str):
        if not events:
            self._write_empty(output_path, ["timestamp", "host", "message"])
            return
        
        headers = [
            "id", "timestamp", "host_name", "host_ip", "user_name",
            "event_kind", "event_category", "event_action", "event_outcome",
            "source_ip", "source_port", "dest_ip", "dest_port",
            "process_name", "message",
        ]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            
            for event in events:
                row = {
                    "id": event.get("id", ""),
                    "timestamp": event.get("timestamp") or event.get("@timestamp", ""),
                    "host_name": self._extract_nested(event, "host.name", ""),
                    "host_ip": self._extract_nested(event, "host.ip", ""),
                    "user_name": self._extract_nested(event, "user.name", ""),
                    "event_kind": self._extract_nested(event, "event.kind", ""),
                    "event_category": self._flatten_list(self._extract_nested(event, "event.category", [])),
                    "event_action": self._extract_nested(event, "event.action", ""),
                    "event_outcome": self._extract_nested(event, "event.outcome", ""),
                    "source_ip": self._extract_nested(event, "source.ip", ""),
                    "source_port": self._extract_nested(event, "source.port", ""),
                    "dest_ip": self._extract_nested(event, "destination.ip", ""),
                    "dest_port": self._extract_nested(event, "destination.port", ""),
                    "process_name": self._extract_nested(event, "process.name", ""),
                    "message": event.get("message", ""),
                }
                writer.writerow(row)
        
        logger.info(f"Exported {len(events)} events to {output_path}")
    
    def export_timeline(self, timeline: List[Dict[str, Any]], output_path: str):
        if not timeline:
            self._write_empty(output_path, ["timestamp", "count"])
            return
        
        headers = list(timeline[0].keys()) if timeline else ["timestamp", "count"]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(timeline)
        
        logger.info(f"Exported timeline to {output_path}")
    
    def _write_empty(self, output_path: str, headers: List[str]):
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
    
    def _extract_nested(self, data: Dict, path: str, default: Any = "") -> Any:
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        
        return value
    
    def _flatten_list(self, value: Any) -> str:
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        return str(value)
