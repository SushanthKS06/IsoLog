"""
IsoLog JSON Exporter

Export data to JSON format.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export data to JSON files."""
    
    def export(self, data: Any, output_path: str, pretty: bool = True):
        """
        Export data to JSON file.
        
        Args:
            data: Data to export
            output_path: Output file path
            pretty: Pretty print JSON
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=2 if pretty else None,
                default=self._json_serializer,
                ensure_ascii=False,
            )
        
        logger.info(f"Exported JSON to {output_path}")
    
    def export_alerts(self, alerts: List[Dict[str, Any]], output_path: str):
        """Export alerts to JSON."""
        self.export({"alerts": alerts, "count": len(alerts)}, output_path)
    
    def export_events(self, events: List[Dict[str, Any]], output_path: str):
        """Export events to JSON."""
        self.export({"events": events, "count": len(events)}, output_path)
    
    def export_jsonl(self, items: List[Dict[str, Any]], output_path: str):
        """
        Export to JSON Lines format (one JSON per line).
        
        Args:
            items: Items to export
            output_path: Output file path
        """
        with open(output_path, "w", encoding="utf-8") as f:
            for item in items:
                f.write(json.dumps(item, default=self._json_serializer) + "\n")
        
        logger.info(f"Exported {len(items)} items to JSONL: {output_path}")
    
    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for special types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
