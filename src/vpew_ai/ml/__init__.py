"""
VPEW-AI Machine Learning Module
Anomaly detection and threat classification
"""

from .models import AnomalyDetector, ThreatClassifier
from .training import Trainer

__all__ = [
    "AnomalyDetector",
    "ThreatClassifier", 
    "Trainer"
]
