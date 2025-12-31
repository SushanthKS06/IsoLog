"""
IsoLog One-Class SVM Anomaly Detector

Alternative ML model using One-Class SVM for anomaly detection.
"""

import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Check if sklearn is available
try:
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, One-Class SVM disabled")


class OneClassSVMDetector:
    """
    One-Class SVM for anomaly detection.
    
    Complementary to Isolation Forest for different anomaly types.
    """
    
    def __init__(
        self,
        model_path: str = "./models/ocsvm_model.pkl",
        nu: float = 0.05,
        kernel: str = "rbf",
        gamma: str = "scale",
    ):
        """
        Initialize One-Class SVM detector.
        
        Args:
            model_path: Path to save/load model
            nu: Upper bound on training errors (default 0.05 = 5%)
            kernel: SVM kernel (rbf, linear, poly, sigmoid)
            gamma: Kernel coefficient
        """
        self.model_path = Path(model_path)
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        
        self._available = SKLEARN_AVAILABLE
        self._model: Optional[OneClassSVM] = None
        self._scaler: Optional[StandardScaler] = None
        self._trained = False
        self._feature_names: List[str] = []
        
        # Training buffer
        self._training_buffer: List[np.ndarray] = []
        self._min_samples = 500
        
        # Load existing model
        self._load_model()
    
    def is_available(self) -> bool:
        """Check if model is available."""
        return self._available
    
    def is_trained(self) -> bool:
        """Check if model is trained."""
        return self._trained and self._model is not None
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from event.
        
        Args:
            event: Event data
            
        Returns:
            Feature vector
        """
        features = []
        
        # Time-based features
        timestamp = event.get("timestamp") or event.get("@timestamp")
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                else:
                    dt = timestamp
                features.append(dt.hour)
                features.append(dt.weekday())
                features.append(1 if dt.weekday() >= 5 else 0)  # Weekend
            except:
                features.extend([12, 3, 0])
        else:
            features.extend([12, 3, 0])
        
        # Event type features
        event_data = event.get("event", {})
        action = event_data.get("action", "")
        
        # Hash action to numeric
        features.append(hash(action) % 1000)
        
        # Outcome (success=1, failure=0, unknown=0.5)
        outcome = event_data.get("outcome", "")
        if outcome == "success":
            features.append(1.0)
        elif outcome == "failure":
            features.append(0.0)
        else:
            features.append(0.5)
        
        # Network features
        source = event.get("source", {})
        dest = event.get("destination", {})
        
        source_port = source.get("port", 0) or 0
        dest_port = dest.get("port", 0) or 0
        
        features.append(min(source_port, 65535))
        features.append(min(dest_port, 65535))
        
        # Well-known port flag
        features.append(1 if dest_port < 1024 else 0)
        
        # Message length
        message = event.get("message", "")
        features.append(min(len(message), 10000))
        
        # Process features
        process = event.get("process", {})
        cmd_len = len(process.get("command_line", ""))
        features.append(min(cmd_len, 5000))
        
        return np.array(features, dtype=np.float32)
    
    def add_sample(self, event: Dict[str, Any]):
        """
        Add event to training buffer.
        
        Args:
            event: Event data
        """
        if not self._available:
            return
        
        features = self.extract_features(event)
        self._training_buffer.append(features)
        
        # Auto-train when buffer is full
        if len(self._training_buffer) >= self._min_samples and not self._trained:
            self.train()
    
    def train(self, samples: List[Dict[str, Any]] = None):
        """
        Train the model.
        
        Args:
            samples: Training samples (uses buffer if None)
        """
        if not self._available:
            return
        
        if samples:
            X = np.array([self.extract_features(s) for s in samples])
        elif self._training_buffer:
            X = np.array(self._training_buffer)
        else:
            logger.warning("No samples for training")
            return
        
        if len(X) < 50:
            logger.warning(f"Insufficient samples for training: {len(X)}")
            return
        
        try:
            # Scale features
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)
            
            # Train model
            self._model = OneClassSVM(
                nu=self.nu,
                kernel=self.kernel,
                gamma=self.gamma,
            )
            self._model.fit(X_scaled)
            
            self._trained = True
            logger.info(f"One-Class SVM trained on {len(X)} samples")
            
            # Save model
            self._save_model()
            
            # Clear buffer
            self._training_buffer = []
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if event is an anomaly.
        
        Args:
            event: Event data
            
        Returns:
            (is_anomaly, anomaly_score)
        """
        if not self.is_trained():
            return False, 0.0
        
        try:
            features = self.extract_features(event)
            X = features.reshape(1, -1)
            X_scaled = self._scaler.transform(X)
            
            # Predict (-1 = anomaly, 1 = normal)
            prediction = self._model.predict(X_scaled)[0]
            
            # Get decision function score (distance from boundary)
            score = -self._model.decision_function(X_scaled)[0]
            
            # Normalize score to 0-1 range
            normalized_score = 1 / (1 + np.exp(-score))
            
            is_anomaly = prediction == -1
            
            return is_anomaly, float(normalized_score)
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return False, 0.0
    
    def _save_model(self):
        """Save model to disk."""
        if not self._trained:
            return
        
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.model_path, "wb") as f:
                pickle.dump({
                    "model": self._model,
                    "scaler": self._scaler,
                    "nu": self.nu,
                    "kernel": self.kernel,
                }, f)
            
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def _load_model(self):
        """Load model from disk."""
        if not self.model_path.exists():
            return
        
        try:
            with open(self.model_path, "rb") as f:
                data = pickle.load(f)
            
            self._model = data["model"]
            self._scaler = data["scaler"]
            self._trained = True
            
            logger.info(f"Model loaded from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get model statistics."""
        return {
            "available": self._available,
            "trained": self._trained,
            "buffer_size": len(self._training_buffer),
            "min_samples": self._min_samples,
            "nu": self.nu,
            "kernel": self.kernel,
        }
