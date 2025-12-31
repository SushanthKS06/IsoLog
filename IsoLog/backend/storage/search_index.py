"""
IsoLog Search Index

Full-text search using Whoosh.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check if Whoosh is available
try:
    from whoosh import index
    from whoosh.fields import Schema, TEXT, ID, DATETIME, KEYWORD, NUMERIC
    from whoosh.qparser import MultifieldParser, QueryParser
    from whoosh.writing import AsyncWriter
    from whoosh.analysis import StemmingAnalyzer
    WHOOSH_AVAILABLE = True
except ImportError:
    WHOOSH_AVAILABLE = False
    logger.warning("Whoosh not installed. Full-text search will use SQL fallback.")


class SearchIndex:
    """
    Full-text search index using Whoosh.
    
    Indexes events and alerts for fast text search.
    """
    
    def __init__(self, index_path: str = "./data/search_index"):
        """
        Initialize search index.
        
        Args:
            index_path: Directory for index files
        """
        self.index_path = Path(index_path)
        self._available = WHOOSH_AVAILABLE
        self._index = None
        self._schema = None
        
        if self._available:
            self._init_index()
    
    def _init_index(self):
        """Initialize Whoosh index."""
        self.index_path.mkdir(parents=True, exist_ok=True)
        
        # Define schema
        self._schema = Schema(
            id=ID(stored=True, unique=True),
            type=KEYWORD(stored=True),  # event or alert
            timestamp=DATETIME(stored=True),
            host=TEXT(stored=True),
            user=TEXT(stored=True),
            source_ip=TEXT(stored=True),
            message=TEXT(stored=True, analyzer=StemmingAnalyzer()),
            action=KEYWORD(stored=True),
            severity=KEYWORD(stored=True),
            rule_name=TEXT(stored=True),
            mitre_techniques=KEYWORD(stored=True, commas=True),
        )
        
        # Open or create index
        if index.exists_in(str(self.index_path)):
            self._index = index.open_dir(str(self.index_path))
        else:
            self._index = index.create_in(str(self.index_path), self._schema)
        
        logger.info(f"Search index initialized at {self.index_path}")
    
    def is_available(self) -> bool:
        """Check if search index is available."""
        return self._available and self._index is not None
    
    def index_event(self, event: Dict[str, Any]):
        """
        Add an event to the search index.
        
        Args:
            event: Event data
        """
        if not self.is_available():
            return
        
        try:
            with AsyncWriter(self._index) as writer:
                writer.add_document(
                    id=str(event.get("id", "")),
                    type="event",
                    timestamp=self._parse_timestamp(event.get("timestamp")),
                    host=str(event.get("host", {}).get("name", "")),
                    user=str(event.get("user", {}).get("name", "")),
                    source_ip=str(event.get("source", {}).get("ip", "")),
                    message=str(event.get("message", "")),
                    action=str(event.get("event", {}).get("action", "")),
                    severity="",
                    rule_name="",
                    mitre_techniques="",
                )
        except Exception as e:
            logger.error(f"Error indexing event: {e}")
    
    def index_alert(self, alert: Dict[str, Any]):
        """
        Add an alert to the search index.
        
        Args:
            alert: Alert data
        """
        if not self.is_available():
            return
        
        try:
            techniques = ",".join(alert.get("mitre_techniques", []))
            
            with AsyncWriter(self._index) as writer:
                writer.add_document(
                    id=str(alert.get("id", "")),
                    type="alert",
                    timestamp=self._parse_timestamp(alert.get("created_at")),
                    host="",
                    user="",
                    source_ip="",
                    message=str(alert.get("rule_description", "")),
                    action="",
                    severity=str(alert.get("severity", "")),
                    rule_name=str(alert.get("rule_name", "")),
                    mitre_techniques=techniques,
                )
        except Exception as e:
            logger.error(f"Error indexing alert: {e}")
    
    def index_batch(self, items: List[Dict[str, Any]], item_type: str = "event"):
        """
        Index multiple items in batch.
        
        Args:
            items: List of items
            item_type: "event" or "alert"
        """
        if not self.is_available():
            return
        
        try:
            with AsyncWriter(self._index) as writer:
                for item in items:
                    if item_type == "event":
                        writer.add_document(
                            id=str(item.get("id", "")),
                            type="event",
                            timestamp=self._parse_timestamp(item.get("timestamp")),
                            host=str(item.get("host", {}).get("name", "")),
                            user=str(item.get("user", {}).get("name", "")),
                            source_ip=str(item.get("source", {}).get("ip", "")),
                            message=str(item.get("message", "")),
                            action=str(item.get("event", {}).get("action", "")),
                            severity="",
                            rule_name="",
                            mitre_techniques="",
                        )
                    else:
                        techniques = ",".join(item.get("mitre_techniques", []))
                        writer.add_document(
                            id=str(item.get("id", "")),
                            type="alert",
                            timestamp=self._parse_timestamp(item.get("created_at")),
                            host="",
                            user="",
                            source_ip="",
                            message=str(item.get("rule_description", "")),
                            action="",
                            severity=str(item.get("severity", "")),
                            rule_name=str(item.get("rule_name", "")),
                            mitre_techniques=techniques,
                        )
            
            logger.debug(f"Indexed {len(items)} {item_type}s")
        except Exception as e:
            logger.error(f"Error batch indexing: {e}")
    
    def search(
        self,
        query: str,
        item_type: Optional[str] = None,
        limit: int = 50,
        fields: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search the index.
        
        Args:
            query: Search query
            item_type: Filter by "event" or "alert"
            limit: Maximum results
            fields: Fields to search (default: message, host, user, rule_name)
            
        Returns:
            List of matching documents
        """
        if not self.is_available():
            return []
        
        try:
            fields = fields or ["message", "host", "user", "rule_name", "source_ip"]
            
            with self._index.searcher() as searcher:
                parser = MultifieldParser(fields, self._schema)
                parsed_query = parser.parse(query)
                
                # Add type filter if specified
                if item_type:
                    type_query = QueryParser("type", self._schema).parse(item_type)
                    from whoosh.query import And
                    parsed_query = And([parsed_query, type_query])
                
                results = searcher.search(parsed_query, limit=limit)
                
                return [
                    {
                        "id": hit["id"],
                        "type": hit["type"],
                        "timestamp": hit.get("timestamp"),
                        "host": hit.get("host"),
                        "user": hit.get("user"),
                        "message": hit.get("message"),
                        "severity": hit.get("severity"),
                        "rule_name": hit.get("rule_name"),
                        "score": hit.score,
                    }
                    for hit in results
                ]
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
    def suggest(self, prefix: str, field: str = "message", limit: int = 10) -> List[str]:
        """
        Get search suggestions.
        
        Args:
            prefix: Prefix to match
            field: Field to suggest from
            limit: Maximum suggestions
            
        Returns:
            List of suggestions
        """
        if not self.is_available():
            return []
        
        try:
            with self._index.searcher() as searcher:
                suggestions = list(searcher.reader().most_frequent_terms(
                    field, 
                    number=limit * 5,
                    prefix=prefix.lower(),
                ))
                return [term.decode() for freq, term in suggestions[:limit]]
        except Exception as e:
            logger.error(f"Suggestion error: {e}")
            return []
    
    def delete(self, doc_id: str):
        """Delete a document from the index."""
        if not self.is_available():
            return
        
        try:
            with AsyncWriter(self._index) as writer:
                writer.delete_by_term("id", doc_id)
        except Exception as e:
            logger.error(f"Delete error: {e}")
    
    def clear(self):
        """Clear the entire index."""
        if not self.is_available():
            return
        
        try:
            from whoosh.writing import CLEAR
            with self._index.writer() as writer:
                writer.commit(mergetype=CLEAR)
            logger.info("Search index cleared")
        except Exception as e:
            logger.error(f"Clear error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        if not self.is_available():
            return {"available": False}
        
        try:
            with self._index.searcher() as searcher:
                return {
                    "available": True,
                    "doc_count": searcher.doc_count(),
                    "index_path": str(self.index_path),
                }
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Parse timestamp to datetime."""
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                pass
        return None
