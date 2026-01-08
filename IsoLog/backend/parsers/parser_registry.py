
import logging
from typing import Dict, List, Optional, Type

from .base_parser import BaseParser, ParsedEvent

logger = logging.getLogger(__name__)

class ParserRegistry:
    
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._priority_order: List[str] = []
    
    def register(self, parser: BaseParser, priority: int = 100):
        parser_id = parser.parser_id
        self._parsers[parser_id] = parser
        
        inserted = False
        for i, pid in enumerate(self._priority_order):
            if pid not in self._parsers:
                continue
            inserted = True
            self._priority_order.insert(i, parser_id)
            break
        
        if not inserted:
            self._priority_order.append(parser_id)
        
        logger.info(f"Registered parser: {parser_id} ({parser.parser_name})")
    
    def unregister(self, parser_id: str):
        if parser_id in self._parsers:
            del self._parsers[parser_id]
            self._priority_order = [p for p in self._priority_order if p != parser_id]
            logger.info(f"Unregistered parser: {parser_id}")
    
    def get_parser(self, parser_id: str) -> Optional[BaseParser]:
        return self._parsers.get(parser_id)
    
    def list_parsers(self) -> List[Dict[str, str]]:
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
        if parser_id:
            parser = self.get_parser(parser_id)
            if parser:
                return parser.parse(raw_log, source_type)
            logger.warning(f"Parser not found: {parser_id}")
            return None
        
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

_registry: Optional[ParserRegistry] = None

def get_parser_registry() -> ParserRegistry:
    global _registry
    if _registry is None:
        _registry = ParserRegistry()
        _register_default_parsers(_registry)
    return _registry

def _register_default_parsers(registry: ParserRegistry):
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
