"""
IsoLog CSV Generic Parser

Parses CSV-formatted logs.
"""

import csv
import io
from datetime import datetime
from typing import Dict, List, Optional

from ..base_parser import BaseParser, ParsedEvent


class CSVGenericParser(BaseParser):
    """
    Generic parser for CSV-formatted logs.
    
    Uses first line as header to map columns to fields.
    """
    
    parser_id = "csv_generic"
    parser_name = "CSV Generic Parser"
    parser_description = "Parses CSV log format"
    supported_formats = ["csv"]
    file_patterns = ["*.csv"]
    
    # Column name mappings (lowercase for matching)
    COLUMN_MAPPINGS = {
        "timestamp": ["timestamp", "time", "datetime", "date", "eventtime"],
        "message": ["message", "msg", "log", "description", "event"],
        "host_name": ["host", "hostname", "server", "machine", "computer"],
        "source_ip": ["source_ip", "sourceip", "src_ip", "srcip", "client_ip", "clientip"],
        "destination_ip": ["dest_ip", "destip", "dst_ip", "dstip", "destination_ip"],
        "source_port": ["source_port", "src_port", "srcport"],
        "destination_port": ["dest_port", "dst_port", "dstport"],
        "user_name": ["user", "username", "user_name", "account"],
        "action": ["action", "event_type", "eventtype", "operation"],
        "severity": ["severity", "level", "priority"],
        "process_name": ["process", "process_name", "application", "app"],
    }
    
    # Track if we've seen header
    _header: Optional[List[str]] = None
    _column_map: Optional[Dict[str, str]] = None
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if this looks like CSV."""
        raw_log = raw_log.strip()
        if not raw_log:
            return False
        
        # Must contain comma
        if ',' not in raw_log:
            return False
        
        # Try to parse as CSV
        try:
            reader = csv.reader(io.StringIO(raw_log))
            row = next(reader)
            # Should have multiple columns
            return len(row) >= 2
        except (csv.Error, StopIteration):
            return False
    
    def parse(self, raw_log: str, source_type: Optional[str] = None) -> Optional[ParsedEvent]:
        """Parse CSV line."""
        raw_log = raw_log.strip()
        if not raw_log:
            return None
        
        try:
            reader = csv.reader(io.StringIO(raw_log))
            row = list(next(reader))
        except (csv.Error, StopIteration):
            return None
        
        # Auto-detect or use existing header
        if self._header is None:
            # Check if this looks like a header
            if self._looks_like_header(row):
                self._header = [col.lower().strip() for col in row]
                self._build_column_map()
                return None  # Skip header line
            else:
                # Generate numeric headers
                self._header = [f"col{i}" for i in range(len(row))]
                self._build_column_map()
        
        # Map row to dict
        if len(row) != len(self._header):
            # Pad or truncate
            while len(row) < len(self._header):
                row.append("")
            row = row[:len(self._header)]
        
        data = dict(zip(self._header, row))
        
        # Extract fields
        event = ParsedEvent(
            timestamp=self._parse_timestamp(data),
            message=self._get_mapped_value(data, "message") or raw_log,
            host_name=self._get_mapped_value(data, "host_name"),
            source_ip=self._get_mapped_value(data, "source_ip"),
            destination_ip=self._get_mapped_value(data, "destination_ip"),
            source_port=self._parse_int(self._get_mapped_value(data, "source_port")),
            destination_port=self._parse_int(self._get_mapped_value(data, "destination_port")),
            user_name=self._get_mapped_value(data, "user_name"),
            event_action=self._get_mapped_value(data, "action"),
            process_name=self._get_mapped_value(data, "process_name"),
            raw_log=raw_log,
            parser_id=self.parser_id,
            source_type=source_type or "csv",
        )
        
        # Store unmapped columns as extra
        mapped_cols = set()
        if self._column_map:
            for cols in self.COLUMN_MAPPINGS.values():
                for col in cols:
                    if col in data:
                        mapped_cols.add(col)
        
        event.extra = {k: v for k, v in data.items() if k not in mapped_cols and v}
        
        return event
    
    def reset(self):
        """Reset parser state for new file."""
        self._header = None
        self._column_map = None
    
    def _looks_like_header(self, row: List[str]) -> bool:
        """Check if row looks like a header."""
        # Headers typically don't have numbers in first columns
        # and contain common header names
        header_keywords = [
            "timestamp", "time", "date", "host", "message", "user",
            "source", "dest", "ip", "port", "event", "action", "level"
        ]
        
        row_lower = [col.lower().strip() for col in row]
        
        # Check if any column matches header keywords
        for col in row_lower:
            for keyword in header_keywords:
                if keyword in col:
                    return True
        
        return False
    
    def _build_column_map(self):
        """Build mapping from our field names to actual column names."""
        self._column_map = {}
        if not self._header:
            return
        
        for field_name, possible_cols in self.COLUMN_MAPPINGS.items():
            for col in possible_cols:
                if col in self._header:
                    self._column_map[field_name] = col
                    break
    
    def _get_mapped_value(self, data: Dict[str, str], field_name: str) -> Optional[str]:
        """Get value using column mapping."""
        if self._column_map and field_name in self._column_map:
            col = self._column_map[field_name]
            value = data.get(col, "").strip()
            return value if value else None
        return None
    
    def _parse_timestamp(self, data: Dict[str, str]) -> datetime:
        """Parse timestamp from data."""
        ts_str = self._get_mapped_value(data, "timestamp")
        if not ts_str:
            return datetime.utcnow()
        
        # Try common formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ]:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return datetime.utcnow()
    
    def _parse_int(self, value: Optional[str]) -> Optional[int]:
        """Parse integer value."""
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None
