
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import and_, or_, not_, desc, asc
from sqlalchemy.orm import Query

@dataclass
class QueryFilter:
    field: str
    operator: str  # eq, ne, gt, gte, lt, lte, like, ilike, in, not_in, is_null, is_not_null
    value: Any = None

@dataclass
class QuerySort:
    field: str
    direction: str = "desc"  # asc or desc

@dataclass
class QuerySpec:
    filters: List[QueryFilter] = field(default_factory=list)
    sorts: List[QuerySort] = field(default_factory=list)
    limit: int = 50
    offset: int = 0
    search_query: Optional[str] = None
    search_fields: List[str] = field(default_factory=list)

class QueryBuilder:
    
    OPERATORS = {
        "eq": lambda col, val: col == val,
        "ne": lambda col, val: col != val,
        "gt": lambda col, val: col > val,
        "gte": lambda col, val: col >= val,
        "lt": lambda col, val: col < val,
        "lte": lambda col, val: col <= val,
        "like": lambda col, val: col.like(f"%{val}%"),
        "ilike": lambda col, val: col.ilike(f"%{val}%"),
        "in": lambda col, val: col.in_(val) if isinstance(val, list) else col.in_([val]),
        "not_in": lambda col, val: ~col.in_(val) if isinstance(val, list) else ~col.in_([val]),
        "is_null": lambda col, val: col.is_(None),
        "is_not_null": lambda col, val: col.isnot(None),
        "starts_with": lambda col, val: col.like(f"{val}%"),
        "ends_with": lambda col, val: col.like(f"%{val}"),
    }
    
    def __init__(self, model_class):
        self.model = model_class
    
    def build(self, spec: QuerySpec) -> Query:
        from sqlalchemy.orm import Session
        from sqlalchemy import select
        
        query = select(self.model)
        
        if spec.filters:
            conditions = self._build_filters(spec.filters)
            if conditions:
                query = query.where(and_(*conditions))
        
        if spec.search_query and spec.search_fields:
            search_conditions = self._build_search(spec.search_query, spec.search_fields)
            if search_conditions:
                query = query.where(or_(*search_conditions))
        
        if spec.sorts:
            for sort in spec.sorts:
                column = getattr(self.model, sort.field, None)
                if column:
                    if sort.direction == "desc":
                        query = query.order_by(desc(column))
                    else:
                        query = query.order_by(asc(column))
        
        query = query.offset(spec.offset).limit(spec.limit)
        
        return query
    
    def _build_filters(self, filters: List[QueryFilter]) -> List:
        conditions = []
        
        for f in filters:
            column = getattr(self.model, f.field, None)
            if column is None:
                continue
            
            operator_func = self.OPERATORS.get(f.operator)
            if operator_func is None:
                continue
            
            try:
                condition = operator_func(column, f.value)
                conditions.append(condition)
            except Exception:
                pass
        
        return conditions
    
    def _build_search(self, query: str, fields: List[str]) -> List:
        conditions = []
        
        for field_name in fields:
            column = getattr(self.model, field_name, None)
            if column is not None:
                conditions.append(column.ilike(f"%{query}%"))
        
        return conditions
    
    def count(self, spec: QuerySpec) -> Query:
        from sqlalchemy import select, func
        
        query = select(func.count()).select_from(self.model)
        
        if spec.filters:
            conditions = self._build_filters(spec.filters)
            if conditions:
                query = query.where(and_(*conditions))
        
        if spec.search_query and spec.search_fields:
            search_conditions = self._build_search(spec.search_query, spec.search_fields)
            if search_conditions:
                query = query.where(or_(*search_conditions))
        
        return query

class EventQueryBuilder(QueryBuilder):
    
    SEARCHABLE_FIELDS = ["message", "host_name", "user_name", "source_ip", "event_action"]
    
    def __init__(self):
        from ..models import Event
        super().__init__(Event)
    
    def from_params(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        event_action: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_dir: str = "desc",
    ) -> QuerySpec:
        filters = []
        
        if start_time:
            filters.append(QueryFilter("timestamp", "gte", start_time))
        if end_time:
            filters.append(QueryFilter("timestamp", "lte", end_time))
        if host_name:
            filters.append(QueryFilter("host_name", "ilike", host_name))
        if user_name:
            filters.append(QueryFilter("user_name", "ilike", user_name))
        if source_ip:
            filters.append(QueryFilter("source_ip", "eq", source_ip))
        if event_action:
            filters.append(QueryFilter("event_action", "eq", event_action))
        
        return QuerySpec(
            filters=filters,
            sorts=[QuerySort(sort_by, sort_dir)],
            limit=page_size,
            offset=(page - 1) * page_size,
            search_query=search,
            search_fields=self.SEARCHABLE_FIELDS if search else [],
        )

class AlertQueryBuilder(QueryBuilder):
    
    SEARCHABLE_FIELDS = ["rule_name", "rule_description"]
    
    def __init__(self):
        from ..models import Alert
        super().__init__(Alert)
    
    def from_params(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        detection_type: Optional[str] = None,
        rule_id: Optional[str] = None,
        min_threat_score: Optional[float] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "created_at",
        sort_dir: str = "desc",
    ) -> QuerySpec:
        filters = []
        
        if severity:
            filters.append(QueryFilter("severity", "eq", severity))
        if status:
            filters.append(QueryFilter("status", "eq", status))
        if detection_type:
            filters.append(QueryFilter("detection_type", "eq", detection_type))
        if rule_id:
            filters.append(QueryFilter("rule_id", "eq", rule_id))
        if min_threat_score:
            filters.append(QueryFilter("threat_score", "gte", min_threat_score))
        if start_time:
            filters.append(QueryFilter("created_at", "gte", start_time))
        if end_time:
            filters.append(QueryFilter("created_at", "lte", end_time))
        
        return QuerySpec(
            filters=filters,
            sorts=[QuerySort(sort_by, sort_dir)],
            limit=page_size,
            offset=(page - 1) * page_size,
            search_query=search,
            search_fields=self.SEARCHABLE_FIELDS if search else [],
        )
