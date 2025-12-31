"""
IsoLog Parser Registry

Dynamic parser loading and selection.
"""

import logging
from typing import Dict, List, Optional, Type

from .base_parser import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)


class ParserRegistry:
    """
    Registry for log parsers.
    
    Manages parser registration, selection, and auto-detection.
    """
    
    def __init__(self):
        """Initialize parser registry."""
        self._parsers: Dict[str, BaseParser] = {}
        self._priority_order: List[str] = []
    
    def register(self, parser: BaseParser, priority: int = 100):
        """
        Register a parser.
        
        Args:
            parser: Parser instance to register
            priority: Lower number = higher priority for auto-detection
        """
        parser_id = parser.parser_id
        self._parsers[parser_id] = parser
        
        # Insert in priority order
        inserted = False
        for i, pid in enumerate(self._priority_order):
            if pid not in self._parsers:
                continue
            # Simple priority ordering - could be more sophisticated
            inserted = True
            self._priority_order.insert(i, parser_id)
            break
        
        if not inserted:
            self._priority_order.append(parser_id)
        
        logger.info(f"Registered parser: {parser_id} ({parser.parser_name})")
    
    def unregister(self, parser_id: str):
        """
        Unregister a parser.
        
        Args:
            parser_id: ID of parser to remove
        """
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            self._priority_order = [p for p in self._priority_order if p != parser_id]
            logger.info(f"Unregistered parser: {parser_id}")
    
    def get_parser(self, parser_id: str) -> Optional[BaseParser]:
        """
        Get parser by ID.
        
        Args:
            parser_id: Parser ID
            
        Returns:
            Parser instance or None
        """
        return self._parsers.get(parser_id)
    
    def list_parsers(self) -> List[Dict[str, str]]:
        """
        List all registered parsers.
        
        Returns:
            List of parser info dictionaries
        """
        return [
            {
                "id": p.parser_id,
                "name": p.parser_name,
                "description": p.parser_description,
                "formats": p.supported_formats,
            }
            for p in self._parsers.values()
        ]
    
    def detect_parser(self, raw_log: str) -> Optional[BaseParser]:
        """
        Auto-detect appropriate parser for a log line.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            Matching parser or None
        """
        for parser_id in self._priority_order:
            parser = self._parsers.get(parser_id)
            if parser and parser.can_parse(raw_log):
                return parser
        return None
    
    def parse(
        self, 
        raw_log: str, 
        parser_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Optional[ParsedEvent]:
        """
        Parse a log line using specified or auto-detected parser.
        
        Args:
            raw_log: Raw log line
            parser_id: Optional specific parser to use
            source_type: Optional source type hint
            
        Returns:
            ParsedEvent or None
        """
        # Use specified parser if provided
        if parser_id:
            parser = self.get_parser(parser_id)
            if parser:
                return parser.parse(raw_log, source_type)
            logger.warning(f"Parser not found: {parser_id}")
            return None
        
        # Auto-detect parser
        parser = self.detect_parser(raw_log)
        if parser:
            return parser.parse(raw_log, source_type)
        
        logger.debug(f"No parser found for log: {raw_log[:100]}...")
        return None
    
    def parse_batch(
        self,
        raw_logs: List[str],
        parser_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> List[ParsedEvent]:
        """
        Parse multiple log lines.
        
        Args:
            raw_logs: List of raw log lines
            parser_id: Optional specific parser to use
            source_type: Optional source type hint
            
        Returns:
            List of parsed events
        """
        events = []
        for raw_log in raw_logs:
            try:
                event = self.parse(raw_log, parser_id, source_type)
                if event:
                    events.append(event)
            except Exception as e:
                logger.debug(f"Failed to parse log: {e}")
                continue
        return events


# Global registry instance
_registry: Optional[ParserRegistry] = None


def get_parser_registry() -> ParserRegistry:
    """Get or create global parser registry."""
    global _registry
    if _registry is None:
        _registry = ParserRegistry()
        _register_default_parsers(_registry)
    return _registry


def _register_default_parsers(registry: ParserRegistry):
    """Register default parsers."""
    # Import and register format parsers
    try:
        from .formats.linux_syslog import LinuxSyslogParser
        registry.register(LinuxSyslogParser(), priority=10)
    except ImportError:
        pass
    
    try:
        from .formats.json_generic import JSONGenericParser
        registry.register(JSONGenericParser(), priority=50)
    except ImportError:
        pass
    
    try:
        from .formats.csv_generic import CSVGenericParser
        registry.register(CSVGenericParser(), priority=60)
    except ImportError:
        pass
    
    try:
        from .formats.windows_event import WindowsEventParser
        registry.register(WindowsEventParser(), priority=20)
    except ImportError:
        pass
    
    try:
        from .formats.firewall import FirewallParser
        registry.register(FirewallParser(), priority=30)
    except ImportError:
        pass
