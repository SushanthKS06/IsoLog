import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ruamel.yaml import YAML

from ..engine import Detection
from ...parsers.base_parser import ParsedEvent

logger = logging.getLogger(__name__)

class SigmaMatcher:
    
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.rules: List[Dict[str, Any]] = []
        self._yaml = YAML()
        self._yaml.preserve_quotes = True
    
    @property
    def rule_count(self) -> int:
        return len(self.rules)
    
    async def load_rules(self):
        self.rules = []
        
        if not self.rules_path.exists():
            logger.warning(f"Sigma rules path does not exist: {self.rules_path}")
            self.rules_path.mkdir(parents=True, exist_ok=True)
            return
        
        yaml_files = list(self.rules_path.rglob("*.yml"))
        yaml_files.extend(self.rules_path.rglob("*.yaml"))
        
        for rule_file in yaml_files:
            try:
                rule = self._load_rule_file(rule_file)
                if rule:
                    self.rules.append(rule)
            except Exception as e:
                logger.warning(f"Failed to load rule {rule_file}: {e}")
        
        logger.info(f"Loaded {len(self.rules)} Sigma rules")
    
    def _load_rule_file(self, path: Path) -> Optional[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        docs = list(self._yaml.load_all(content))
        if not docs:
            return None
        
        rule = docs[0]
        
        required = ["title", "detection"]
        if not all(field in rule for field in required):
            return None
        
        rule["_file"] = str(path)
        rule["_id"] = rule.get("id", path.stem)
        
        return rule
    
    async def match(self, event: ParsedEvent) -> List[Detection]:
        detections = []
        event_dict = event.to_dict()
        
        for rule in self.rules:
            try:
                if self._check_rule(rule, event_dict, event.message or ""):
                    detection = self._create_detection(rule, event_dict)
                    detections.append(detection)
            except Exception as e:
                logger.debug(f"Error matching rule {rule.get('title', 'unknown')}: {e}")
        
        return detections
    
    def _check_rule(
        self, 
        rule: Dict[str, Any], 
        event_dict: Dict[str, Any],
        message: str,
    ) -> bool:
        detection = rule.get("detection", {})
        if not detection:
            return False
        
        condition = detection.get("condition", "selection")
        
        selection_results = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            selection_results[key] = self._check_selection(value, event_dict, message)
        
        return self._evaluate_condition(condition, selection_results)
    
    def _check_selection(
        self, 
        selection: Any, 
        event_dict: Dict[str, Any],
        message: str,
    ) -> bool:
        if isinstance(selection, dict):
            return all(
                self._check_field(field, value, event_dict, message)
                for field, value in selection.items()
            )
        elif isinstance(selection, list):
            return any(
                self._check_selection(item, event_dict, message)
                for item in selection
            )
        else:
            return False
    
    def _check_field(
        self, 
        field: str, 
        pattern: Any, 
        event_dict: Dict[str, Any],
        message: str,
    ) -> bool:
        modifiers = []
        if "|" in field:
            parts = field.split("|")
            field = parts[0]
            modifiers = parts[1:]
        
        field_value = self._get_field_value(field, event_dict, message)
        
        if field_value is None and field in ['EventID', 'ObjectName', 'GrantedAccess', 'TargetImage', 'CommandLine']:
            logger.debug(f"Sigma field lookup MISS: {field} not found in event")
        
        if field_value is None:
            return False
        
        return self._match_pattern(field_value, pattern, modifiers)
    
    def _get_field_value(
        self, 
        field: str, 
        event_dict: Dict[str, Any],
        message: str,
    ) -> Optional[str]:
        if field.lower() == "keywords":
            return message
        
        parts = field.split(".")
        value = event_dict
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
            
            if value is None:
                if isinstance(event_dict, dict):
                    for k, v in event_dict.items():
                        if k.lower() == part.lower():
                            value = v
                            break
                if value is None:
                    return None
        
        return str(value) if value is not None else None
    
    def _match_pattern(
        self, 
        value: str, 
        pattern: Any, 
        modifiers: List[str],
    ) -> bool:
        value_str = str(value)
        
        if isinstance(pattern, list):
            return any(self._match_pattern(value_str, p, modifiers) for p in pattern)
        
        pattern_str = str(pattern)
        
        case_insensitive = "i" in modifiers or not modifiers
        if case_insensitive:
            value_str = value_str.lower()
            pattern_str = pattern_str.lower()
        
        if "contains" in modifiers or "*" in pattern_str:
            if pattern_str.startswith("*") and pattern_str.endswith("*"):
                return pattern_str.strip("*") in value_str
            elif pattern_str.startswith("*"):
                return value_str.endswith(pattern_str.lstrip("*"))
            elif pattern_str.endswith("*"):
                return value_str.startswith(pattern_str.rstrip("*"))
            elif "contains" in modifiers:
                return pattern_str in value_str
        
        if "startswith" in modifiers:
            return value_str.startswith(pattern_str)
        if "endswith" in modifiers:
            return value_str.endswith(pattern_str)
        
        return value_str == pattern_str
    
    def _evaluate_condition(
        self, 
        condition: str, 
        selection_results: Dict[str, bool],
    ) -> bool:
        if condition in selection_results:
            return selection_results[condition]
        
        if condition.startswith("not "):
            return not self._evaluate_condition(condition[4:], selection_results)
        
        if " or " in condition:
            parts = condition.split(" or ")
            return any(self._evaluate_condition(p.strip(), selection_results) for p in parts)
        
        if " and " in condition:
            parts = condition.split(" and ")
            return all(self._evaluate_condition(p.strip(), selection_results) for p in parts)
        
        if condition.startswith("all of "):
            pattern = condition[7:].strip()
            matching = [k for k in selection_results if k.startswith(pattern.rstrip("*"))]
            return all(selection_results.get(k, False) for k in matching)
        
        if condition.startswith("1 of "):
            pattern = condition[5:].strip()
            matching = [k for k in selection_results if k.startswith(pattern.rstrip("*"))]
            return any(selection_results.get(k, False) for k in matching)
        
        return selection_results.get(condition, False)
    
    def _create_detection(
        self, 
        rule: Dict[str, Any], 
        event_dict: Dict[str, Any],
    ) -> Detection:
        level = rule.get("level", "medium")
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "informational",
        }
        severity = severity_map.get(level, "medium")
        
        tactics = []
        techniques = []
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                techniques.append(tag.replace("attack.", "").upper())
            elif tag.startswith("attack."):
                tactics.append(tag.replace("attack.", ""))
        
        return Detection(
            rule_id=rule.get("_id", "unknown"),
            rule_name=rule.get("title", "Unknown Rule"),
            rule_description=rule.get("description", ""),
            severity=severity,
            detection_type="sigma",
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            confidence=0.9,
            details={
                "rule_file": rule.get("_file"),
                "author": rule.get("author"),
                "references": rule.get("references", []),
            },
        )
