
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from ..engine import Detection
from ...parsers.base_parser import ParsedEvent

logger = logging.getLogger(__name__)

class AnomalyDetector:
    
    def __init__(
        self, 
        models_path: str,
        threshold: float = 0.85,
    ):
        self.models_path = Path(models_path)
        self.threshold = threshold
        
        self.model = None
        self._feature_names: List[str] = []
        self._is_trained = False
        self._event_buffer: List[Dict[str, Any]] = []
        self._min_training_samples = 1000
    
    async def initialize(self):
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        model_file = self.models_path / "isolation_forest.pkl"
        if model_file.exists():
            try:
                await self._load_model()
                logger.info("Loaded existing anomaly detection model")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
        else:
            logger.info("No existing model found, will train on incoming data")
    
    async def _load_model(self):
        model_file = self.models_path / "isolation_forest.pkl"
        with open(model_file, "rb") as f:
            data = pickle.load(f)
        
        self.model = data["model"]
        self._feature_names = data["feature_names"]
        self._is_trained = True
    
    async def _save_model(self):
        if not self.model:
            return
        
        model_file = self.models_path / "isolation_forest.pkl"
        with open(model_file, "wb") as f:
            pickle.dump({
                "model": self.model,
                "feature_names": self._feature_names,
                "trained_at": datetime.utcnow().isoformat(),
            }, f)
        
        logger.info(f"Saved anomaly detection model to {model_file}")
    
    async def detect(self, event: ParsedEvent) -> Optional[Detection]:
        features = self._extract_features(event)
        
        self._event_buffer.append(features)
        
        if not self._is_trained and len(self._event_buffer) >= self._min_training_samples:
            await self._train_model()
        
        if not self._is_trained:
            return None
        
        score = self._calculate_anomaly_score(features)
        
        if score >= self.threshold:
            return Detection(
                rule_id="ml_anomaly",
                rule_name="ML Anomaly Detection",
                rule_description="Event detected as anomalous by machine learning model",
                severity=self._score_to_severity(score),
                detection_type="ml",
                confidence=min(score, 1.0),
                details={
                    "anomaly_score": round(score, 4),
                    "threshold": self.threshold,
                    "feature_contributions": self._get_feature_contributions(features),
                },
            )
        
        return None
    
    def _extract_features(self, event: ParsedEvent) -> Dict[str, float]:
        features = {}
        
        if event.timestamp:
            features["hour_of_day"] = event.timestamp.hour
            features["day_of_week"] = event.timestamp.weekday()
            features["is_weekend"] = 1.0 if event.timestamp.weekday() >= 5 else 0.0
            features["is_business_hours"] = 1.0 if 9 <= event.timestamp.hour <= 17 else 0.0
        
        features["has_user"] = 1.0 if event.user_name else 0.0
        features["has_source_ip"] = 1.0 if event.source_ip else 0.0
        features["has_dest_ip"] = 1.0 if event.destination_ip else 0.0
        features["has_process"] = 1.0 if event.process_name else 0.0
        
        if event.source_port:
            features["src_port"] = float(event.source_port)
            features["src_port_high"] = 1.0 if event.source_port > 1024 else 0.0
        if event.destination_port:
            features["dst_port"] = float(event.destination_port)
            features["dst_port_common"] = 1.0 if event.destination_port in [22, 80, 443, 3389] else 0.0
        
        features["is_failure"] = 1.0 if event.event_outcome == "failure" else 0.0
        features["is_authentication"] = 1.0 if "authentication" in (event.event_category or []) else 0.0
        
        if event.message:
            features["message_length"] = float(len(event.message))
        
        if event.process_command_line:
            features["cmdline_length"] = float(len(event.process_command_line))
        
        return features
    
    async def _train_model(self):
        if len(self._event_buffer) < self._min_training_samples:
            logger.warning("Not enough samples for training")
            return
        
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.error("scikit-learn not available for ML training")
            return
        
        logger.info(f"Training anomaly model with {len(self._event_buffer)} samples")
        
        self._feature_names = sorted(
            set(key for sample in self._event_buffer for key in sample.keys())
        )
        
        X = np.array([
            [sample.get(fname, 0.0) for fname in self._feature_names]
            for sample in self._event_buffer
        ])
        
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Expected anomaly rate
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        
        self._is_trained = True
        
        await self._save_model()
        
        self._event_buffer = self._event_buffer[-100:]  # Keep recent samples
        
        logger.info("Anomaly detection model trained successfully")
    
    def _calculate_anomaly_score(self, features: Dict[str, float]) -> float:
        if not self.model or not self._feature_names:
            return 0.0
        
        X = np.array([[features.get(fname, 0.0) for fname in self._feature_names]])
        
        raw_score = self.model.decision_function(X)[0]
        
        normalized_score = max(0.0, min(1.0, 0.5 - raw_score))
        
        return normalized_score
    
    def _score_to_severity(self, score: float) -> str:
        if score >= 0.95:
            return "critical"
        elif score >= 0.90:
            return "high"
        elif score >= 0.85:
            return "medium"
        else:
            return "low"
    
    def _get_feature_contributions(self, features: Dict[str, float]) -> Dict[str, float]:
        contributions = {}
        
        if features.get("hour_of_day", 12) < 6 or features.get("hour_of_day", 12) > 22:
            contributions["unusual_hour"] = 0.2
        
        if features.get("is_failure", 0) == 1:
            contributions["failed_event"] = 0.15
        
        if features.get("cmdline_length", 0) > 500:
            contributions["long_command"] = 0.25
        
        if features.get("is_weekend", 0) == 1:
            contributions["weekend_activity"] = 0.1
        
        return contributions
    
    async def force_retrain(self):
        self._is_trained = False
        self.model = None
        
        if len(self._event_buffer) >= self._min_training_samples:
            await self._train_model()
