"""
VPEW-AI Sensor Module
Endpoint monitoring and data collection
"""

# Import agent only when needed to avoid RuntimeWarning
# from .agent import VPEWAgent as Agent
try:
    from .collectors import EventCollector, SysmonCollector, ETWCollector
except ImportError:
    EventCollector = SysmonCollector = ETWCollector = None

try:
    from .processors import FeatureExtractor
except ImportError:
    FeatureExtractor = None

# Define Agent as a lazy import function
def get_agent():
    """Lazy import of Agent to avoid RuntimeWarning"""
    from .agent import VPEWAgent
    return VPEWAgent

# Create Agent alias that uses lazy loading
Agent = get_agent

__all__ = [
    "Agent",
    "EventCollector",
    "SysmonCollector", 
    "ETWCollector",
    "FeatureExtractor"
]
