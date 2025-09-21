"""
VPEW-AI Core Package
"""

# Core ML functionality is always available
from .ml import AnomalyDetector, ThreatClassifier

# Optional imports with fallbacks
try:
    from .sensor import Agent
except ImportError:
    Agent = None

try:
    from .rules import SigmaEngine
except ImportError:
    SigmaEngine = None

try:
    from .backend import APIServer
except ImportError:
    APIServer = None

try:
    from .communication import SecureChannel
except ImportError:
    SecureChannel = None

__all__ = [
    "AnomalyDetector", 
    "ThreatClassifier",
    "Agent",
    "SigmaEngine",
    "APIServer",
    "SecureChannel"
]
