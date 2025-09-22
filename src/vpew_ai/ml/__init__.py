"""
VPEW-AI Machine Learning Module
Anomaly detection and threat classification
"""

# Use simple models to avoid TensorFlow compatibility issues
from .simple_models import SimpleAnomalyDetector as AnomalyDetector, SimpleThreatClassifier as ThreatClassifier
from .training import Trainer

__all__ = [
    "AnomalyDetector",
    "ThreatClassifier", 
    "Trainer"
]
