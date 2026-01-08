
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..parsers.base_parser import ParsedEvent

logger = logging.getLogger(__name__)

@dataclass
class Detection:
    rule_id: str
    rule_name: str
    rule_description: str = ""
    
    severity: str = "medium"  # critical, high, medium, low, informational
    
    detection_type: str = "sigma"  # sigma, ml, heuristic, correlation
    
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    threat_score: float = 0.0
    confidence: float = 0.0
    
    matched_fields: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_alert_dict(self, event_id: str) -> Dict[str, Any]:
        return {
            "event_id": event_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "detection_type": self.detection_type,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "details": {
                "matched_fields": self.matched_fields,
                **self.details,
            },
        }

class DetectionEngine:
    
    def __init__(self):
        self.settings = get_settings()
        
        self._sigma_matcher = None
        self._mitre_mapper = None
        self._anomaly_detector = None
        self._scorer = None
        
        self._initialized = False
    
    async def initialize(self):
        if self._initialized:
            return
        
        logger.info("Initializing detection engine...")
        
        if self.settings.detection.sigma.enabled:
            from .sigma.matcher import SigmaMatcher
            self._sigma_matcher = SigmaMatcher(
                rules_path=str(self.settings.resolve_path(
                    self.settings.detection.sigma.rules_path
                ))
            )
            await self._sigma_matcher.load_rules()
            logger.info(f"Loaded {self._sigma_matcher.rule_count} Sigma rules")
        
        if self.settings.detection.mitre.enabled:
            from .mitre.mapping import MitreMapper
            self._mitre_mapper = MitreMapper(
                attack_json_path=str(self.settings.resolve_path(
                    self.settings.detection.mitre.attack_json_path
                ))
            )
            self._mitre_mapper.load()
            logger.info("Loaded MITRE ATT&CK mapping")
        
        if self.settings.detection.anomaly.enabled:
            from .anomaly.detector import AnomalyDetector
            self._anomaly_detector = AnomalyDetector(
                models_path=str(self.settings.resolve_path(
                    self.settings.detection.anomaly.models_path
                )),
                threshold=self.settings.detection.anomaly.threshold,
            )
            await self._anomaly_detector.initialize()
            logger.info("Initialized anomaly detector")
        
        from .scorer import ThreatScorer
        self._scorer = ThreatScorer(
            sigma_weight=self.settings.detection.scoring.sigma_weight,
            mitre_weight=self.settings.detection.scoring.mitre_weight,
            ml_weight=self.settings.detection.scoring.ml_weight,
            heuristic_weight=self.settings.detection.scoring.heuristic_weight,
        )
        
        self._initialized = True
        logger.info("Detection engine initialized")
    
    async def analyze(self, event: ParsedEvent) -> List[Detection]:
        if not self._initialized:
            await self.initialize()
        
        detections: List[Detection] = []
        
        if self._sigma_matcher:
            sigma_detections = await self._sigma_matcher.match(event)
            detections.extend(sigma_detections)
        
        if self._anomaly_detector:
            anomaly_detection = await self._anomaly_detector.detect(event)
            if anomaly_detection:
                detections.append(anomaly_detection)
        
        if self._mitre_mapper:
            for detection in detections:
                self._mitre_mapper.enrich_detection(detection)
        
        if self._scorer:
            for detection in detections:
                self._scorer.score(detection)
        
        return detections
    
    async def analyze_batch(self, events: List[ParsedEvent]) -> Dict[str, List[Detection]]:
        results = {}
        for event in events:
            event_id = event.extra.get("id") or id(event)
            detections = await self.analyze(event)
            if detections:
                results[event_id] = detections
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        stats = {
            "initialized": self._initialized,
            "sigma_enabled": self._sigma_matcher is not None,
            "mitre_enabled": self._mitre_mapper is not None,
            "anomaly_enabled": self._anomaly_detector is not None,
        }
        
        if self._sigma_matcher:
            stats["sigma_rule_count"] = self._sigma_matcher.rule_count
        
        return stats
