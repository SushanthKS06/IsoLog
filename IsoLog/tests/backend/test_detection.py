
import pytest
from unittest.mock import Mock, patch

from backend.detection.engine import DetectionEngine, Detection
from backend.detection.scorer import ThreatScorer

class TestThreatScorer:
    
    @pytest.fixture
    def scorer(self):
        return ThreatScorer()
    
    def test_calculate_score_sigma_high(self, scorer):
        detections = [
            Detection(
                detection_type="sigma",
                rule_id="test-001",
                rule_name="Test Rule",
                severity="high",
                confidence=0.9,
                mitre_tactics=["execution"],
                mitre_techniques=["T1059"],
            )
        ]
        
        score = scorer.calculate_score(detections)
        assert score >= 60  # High severity should give high score
    
    def test_calculate_score_critical(self, scorer):
        detections = [
            Detection(
                detection_type="sigma",
                rule_id="test-002",
                rule_name="Critical Alert",
                severity="critical",
                confidence=1.0,
                mitre_tactics=["impact"],
                mitre_techniques=["T1486"],
            )
        ]
        
        score = scorer.calculate_score(detections)
        assert score >= 80  # Critical should be very high
    
    def test_calculate_score_low(self, scorer):
        detections = [
            Detection(
                detection_type="heuristic",
                rule_id="test-003",
                rule_name="Low Alert",
                severity="low",
                confidence=0.5,
            )
        ]
        
        score = scorer.calculate_score(detections)
        assert score < 40  # Low severity, low score
    
    def test_calculate_score_empty(self, scorer):
        score = scorer.calculate_score([])
        assert score == 0
    
    def test_multiple_detections(self, scorer):
        detections = [
            Detection(detection_type="sigma", rule_id="1", rule_name="A", severity="medium"),
            Detection(detection_type="ml", rule_id="2", rule_name="B", severity="high"),
        ]
        
        score = scorer.calculate_score(detections)
        assert score > 40  # Combined should be higher

class TestDetectionEngine:
    
    @pytest.fixture
    def engine(self):
        with patch.dict('os.environ', {'ISOLOG_DETECTION__SIGMA__ENABLED': 'false'}):
            engine = DetectionEngine(
                sigma_enabled=False,
                ml_enabled=False,
                mitre_enabled=True,
            )
        return engine
    
    def test_engine_initialization(self, engine):
        assert engine is not None
        stats = engine.get_stats()
        assert "events_processed" in stats
    
    def test_analyze_event(self, engine):
        event = {
            "timestamp": "2024-12-31T10:00:00Z",
            "event": {"action": "ssh_login", "outcome": "failure"},
            "user": {"name": "admin"},
            "source": {"ip": "192.168.1.100"},
        }
        
        detections = engine.analyze(event)
        assert isinstance(detections, list)
    
    def test_heuristic_detection(self, engine):
        event = {
            "timestamp": "2024-12-31T10:00:00Z",
            "event": {"action": "process_start"},
            "process": {
                "name": "powershell.exe",
                "command_line": "powershell -encodedcommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
            },
        }
        
        detections = engine.analyze(event)
        assert isinstance(detections, list)

class TestDetection:
    
    def test_detection_creation(self):
        detection = Detection(
            detection_type="sigma",
            rule_id="test-001",
            rule_name="Test Rule",
            severity="high",
            confidence=0.95,
            description="Test detection",
            mitre_tactics=["execution"],
            mitre_techniques=["T1059"],
        )
        
        assert detection.detection_type == "sigma"
        assert detection.severity == "high"
        assert detection.confidence == 0.95
    
    def test_detection_defaults(self):
        detection = Detection(
            detection_type="heuristic",
            rule_id="h-001",
            rule_name="Heuristic",
            severity="low",
        )
        
        assert detection.confidence == 1.0
        assert detection.mitre_tactics == []
        assert detection.mitre_techniques == []
