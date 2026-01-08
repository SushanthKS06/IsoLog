
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, One-Class SVM disabled")

class OneClassSVMDetector:
    
    def __init__(
        self,
        model_path: str = "./models/ocsvm_model.pkl",
        nu: float = 0.05,
        kernel: str = "rbf",
        gamma: str = "scale",
    ):
        self.model_path = Path(model_path)
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        
        self._available = SKLEARN_AVAILABLE
        self._model: Optional[OneClassSVM] = None
        self._scaler: Optional[StandardScaler] = None
        self._trained = False
        self._feature_names: List[str] = []
        
        self._training_buffer: List[np.ndarray] = []
        self._min_samples = 500
        
        self._load_model()
    
    def is_available(self) -> bool:
        return self._available
    
    def is_trained(self) -> bool:
        return self._trained and self._model is not None
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        features = []
        
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
        
        event_data = event.get("event", {})
        action = event_data.get("action", "")
        
        features.append(hash(action) % 1000)
        
        outcome = event_data.get("outcome", "")
        if outcome == "success":
            features.append(1.0)
        elif outcome == "failure":
            features.append(0.0)
        else:
            features.append(0.5)
        
        source = event.get("source", {})
        dest = event.get("destination", {})
        
        source_port = source.get("port", 0) or 0
        dest_port = dest.get("port", 0) or 0
        
        features.append(min(source_port, 65535))
        features.append(min(dest_port, 65535))
        
        features.append(1 if dest_port < 1024 else 0)
        
        message = event.get("message", "")
        features.append(min(len(message), 10000))
        
        process = event.get("process", {})
        cmd_len = len(process.get("command_line", ""))
        features.append(min(cmd_len, 5000))
        
        return np.array(features, dtype=np.float32)
    
    def add_sample(self, event: Dict[str, Any]):
        if not self._available:
            return
        
        features = self.extract_features(event)
        self._training_buffer.append(features)
        
        if len(self._training_buffer) >= self._min_samples and not self._trained:
            self.train()
    
    def train(self, samples: List[Dict[str, Any]] = None):
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
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)
            
            self._model = OneClassSVM(
                nu=self.nu,
                kernel=self.kernel,
                gamma=self.gamma,
            )
            self._model.fit(X_scaled)
            
            self._trained = True
            logger.info(f"One-Class SVM trained on {len(X)} samples")
            
            self._save_model()
            
            self._training_buffer = []
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        if not self.is_trained():
            return False, 0.0
        
        try:
            features = self.extract_features(event)
            X = features.reshape(1, -1)
            X_scaled = self._scaler.transform(X)
            
            prediction = self._model.predict(X_scaled)[0]
            
            score = -self._model.decision_function(X_scaled)[0]
            
            normalized_score = 1 / (1 + np.exp(-score))
            
            is_anomaly = prediction == -1
            
            return is_anomaly, float(normalized_score)
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return False, 0.0
    
    def _save_model(self):
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
        return {
            "available": self._available,
            "trained": self._trained,
            "buffer_size": len(self._training_buffer),
            "min_samples": self._min_samples,
            "nu": self.nu,
            "kernel": self.kernel,
        }
