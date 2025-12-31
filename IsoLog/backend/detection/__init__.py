"""
IsoLog Detection Package

Threat detection engine with Sigma rules, ML anomaly detection, and MITRE mapping.
"""

from .engine import DetectionEngine
from .scorer import ThreatScorer

__all__ = [
    "DetectionEngine",
    "ThreatScorer",
]
