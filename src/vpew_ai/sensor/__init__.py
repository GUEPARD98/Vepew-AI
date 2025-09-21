"""
VPEW-AI Sensor Module
Endpoint monitoring and data collection
"""

from .agent import VPEWAgent as Agent
try:
    from .collectors import EventCollector, SysmonCollector, ETWCollector
except ImportError:
    EventCollector = SysmonCollector = ETWCollector = None

try:
    from .processors import FeatureExtractor
except ImportError:
    FeatureExtractor = None

__all__ = [
    "Agent",
    "EventCollector",
    "SysmonCollector", 
    "ETWCollector",
    "FeatureExtractor"
]
