
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import Detection

class ThreatScorer:
    
    SEVERITY_SCORES = {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 25,
        "informational": 10,
    }
    
    DETECTION_TYPE_SCORES = {
        "sigma": 1.0,
        "ml": 0.8,
        "heuristic": 0.6,
        "correlation": 0.9,
    }
    
    def __init__(
        self,
        sigma_weight: float = 0.4,
        mitre_weight: float = 0.2,
        ml_weight: float = 0.3,
        heuristic_weight: float = 0.1,
    ):
        self.sigma_weight = sigma_weight
        self.mitre_weight = mitre_weight
        self.ml_weight = ml_weight
        self.heuristic_weight = heuristic_weight
        
        total = sigma_weight + mitre_weight + ml_weight + heuristic_weight
        if total > 0:
            self.sigma_weight /= total
            self.mitre_weight /= total
            self.ml_weight /= total
            self.heuristic_weight /= total
    
    def score(self, detection: "Detection") -> float:
        severity_score = self.SEVERITY_SCORES.get(detection.severity, 50)
        
        type_multiplier = self.DETECTION_TYPE_SCORES.get(
            detection.detection_type, 0.7
        )
        
        mitre_bonus = 0
        if detection.mitre_techniques:
            mitre_bonus = min(len(detection.mitre_techniques) * 5, 20)
        if detection.mitre_tactics:
            mitre_bonus += min(len(detection.mitre_tactics) * 3, 15)
        
        confidence_factor = max(detection.confidence, 0.5)
        
        base_score = severity_score * type_multiplier
        
        if detection.detection_type == "sigma":
            weighted = base_score * self.sigma_weight
        elif detection.detection_type == "ml":
            weighted = base_score * self.ml_weight
        elif detection.detection_type == "heuristic":
            weighted = base_score * self.heuristic_weight
        else:
            weighted = base_score * 0.5
        
        weighted += mitre_bonus * self.mitre_weight
        
        final_score = weighted * confidence_factor
        
        final_score = min(max(final_score, 0), 100)
        
        detection.threat_score = round(final_score, 2)
        
        return final_score
    
    def aggregate_scores(self, scores: list) -> float:
        if not scores:
            return 0.0
        
        sorted_scores = sorted(scores, reverse=True)
        
        weighted_sum = 0
        weight_sum = 0
        decay = 0.7
        
        for i, score in enumerate(sorted_scores):
            weight = decay ** i
            weighted_sum += score * weight
            weight_sum += weight
        
        return round(weighted_sum / weight_sum, 2) if weight_sum > 0 else 0.0
    
    def classify_severity(self, score: float) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "informational"
