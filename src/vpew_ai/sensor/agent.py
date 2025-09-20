#!/usr/bin/env python3
"""
VPEW-AI Sensor Agent
Main endpoint monitoring agent with legal/ethical validation
"""

import os
import sys
import time
import logging
import threading
import signal
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

import psutil
import yaml
from cryptography.fernet import Fernet

from .collectors import EventCollector, SysmonCollector, ETWCollector
from .processors import FeatureExtractor
from ..ml import AnomalyDetector, ThreatClassifier
from ..rules import SigmaEngine
from ..communication import SecureChannel
from ..response import PlaybookEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpew-agent.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AgentConfig:
    """Agent configuration settings"""
    endpoint_id: str
    backend_url: str
    cert_path: str
    key_path: str
    ca_cert_path: str
    collection_interval: int = 5
    ml_threshold: float = 0.7
    enable_response: bool = True
    log_level: str = "INFO"

class VPEWAgent:
    """
    Main VPEW-AI sensor agent for endpoint monitoring
    
    This agent implements defensive monitoring with legal/ethical validation:
    - Collects security events from Windows endpoints
    - Applies ML-based anomaly detection
    - Executes Sigma rules for known attack patterns
    - Communicates securely with backend
    - Triggers automated response playbooks
    """
    
    def __init__(self, config_path: str):
        """
        Initialize VPEW-AI agent with legal validation
        
        Args:
            config_path: Path to agent configuration file
        """
        logger.info("Initializing VPEW-AI Agent v0.1.0")
        
        # Legal/Ethical validation
        self._validate_legal_compliance()
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.running = False
        self.collectors = {}
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.threat_classifier = ThreatClassifier()
        self.sigma_engine = SigmaEngine()
        self.secure_channel = SecureChannel(
            cert_path=self.config.cert_path,
            key_path=self.config.key_path,
            ca_cert_path=self.config.ca_cert_path
        )
        self.playbook_engine = PlaybookEngine()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"Agent initialized for endpoint: {self.config.endpoint_id}")
    
    def _validate_legal_compliance(self) -> None:
        """
        Validate legal and ethical compliance before initialization
        
        This function ensures:
        - System is used only for defensive purposes
        - No offensive capabilities are enabled
        - Proper authorization is in place
        - Compliance with corporate policies
        """
        logger.info("Performing legal/ethical validation...")
        
        # Check for authorization file
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        if not auth_file.exists():
            logger.error("Defense authorization file not found!")
            logger.error("Create DEFENSE_AUTHORIZATION.txt to confirm defensive use only")
            sys.exit(1)
        
        # Validate authorization content
        try:
            with open(auth_file, 'r') as f:
                auth_content = f.read().strip()
                if "DEFENSIVE_USE_ONLY" not in auth_content:
                    logger.error("Invalid authorization: Must contain 'DEFENSIVE_USE_ONLY'")
                    sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to validate authorization: {e}")
            sys.exit(1)
        
        # Ensure no offensive modules are present
        offensive_indicators = [
            "exploit", "payload", "shellcode", "backdoor", 
            "keylogger", "stealer", "ransomware"
        ]
        
        current_dir = Path(__file__).parent.parent
        for root, dirs, files in os.walk(current_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for indicator in offensive_indicators:
                                if indicator in content and "# DEFENSIVE:" not in content:
                                    logger.warning(f"Potential offensive content in {file_path}")
                    except:
                        continue
        
        logger.info("Legal/ethical validation completed successfully")
        logger.info("System authorized for DEFENSIVE USE ONLY")
    
    def _load_config(self, config_path: str) -> AgentConfig:
        """Load agent configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            return AgentConfig(
                endpoint_id=config_data.get('endpoint_id', f"endpoint-{os.getenv('COMPUTERNAME', 'unknown')}"),
                backend_url=config_data.get('backend_url', 'https://vpew-backend:8443'),
                cert_path=config_data.get('cert_path', 'certs/client.crt'),
                key_path=config_data.get('key_path', 'certs/client.key'),
                ca_cert_path=config_data.get('ca_cert_path', 'certs/ca.crt'),
                collection_interval=config_data.get('collection_interval', 5),
                ml_threshold=config_data.get('ml_threshold', 0.7),
                enable_response=config_data.get('enable_response', True),
                log_level=config_data.get('log_level', 'INFO')
            )
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def initialize_collectors(self) -> None:
        """Initialize data collectors for various Windows event sources"""
        logger.info("Initializing event collectors...")
        
        try:
            # Windows Event Log collector
            self.collectors['events'] = EventCollector()
            
            # Sysmon collector (if available)
            if self._is_sysmon_available():
                self.collectors['sysmon'] = SysmonCollector()
                logger.info("Sysmon collector initialized")
            else:
                logger.warning("Sysmon not available, using basic event collection")
            
            # ETW collector for low-level events
            self.collectors['etw'] = ETWCollector()
            
            logger.info(f"Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            logger.error(f"Failed to initialize collectors: {e}")
            raise
    
    def _is_sysmon_available(self) -> bool:
        """Check if Sysmon is installed and running"""
        try:
            for service in psutil.win_service_iter():
                if service.name().lower() == 'sysmon' or service.name().lower() == 'sysmon64':
                    return service.status() == 'running'
            return False
        except:
            return False
    
    def start(self) -> None:
        """Start the VPEW-AI agent"""
        logger.info("Starting VPEW-AI Agent...")
        
        try:
            # Initialize collectors
            self.initialize_collectors()
            
            # Load ML models
            self.anomaly_detector.load_model()
            self.threat_classifier.load_model()
            
            # Load Sigma rules
            self.sigma_engine.load_rules()
            
            # Start collection loop
            self.running = True
            self._collection_loop()
            
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")
            sys.exit(1)
    
    def stop(self) -> None:
        """Stop the VPEW-AI agent gracefully"""
        logger.info("Stopping VPEW-AI Agent...")
        self.running = False
        
        # Stop collectors
        for collector_name, collector in self.collectors.items():
            try:
                collector.stop()
                logger.info(f"Stopped {collector_name} collector")
            except Exception as e:
                logger.error(f"Error stopping {collector_name}: {e}")
        
        logger.info("VPEW-AI Agent stopped")
    
    def _collection_loop(self) -> None:
        """Main event collection and processing loop"""
        logger.info("Starting event collection loop...")
        
        while self.running:
            try:
                # Collect events from all sources
                events = self._collect_events()
                
                if events:
                    # Process events
                    processed_events = self._process_events(events)
                    
                    # Analyze with ML and rules
                    alerts = self._analyze_events(processed_events)
                    
                    # Send to backend
                    if processed_events:
                        self._send_to_backend(processed_events, alerts)
                    
                    # Execute response if needed
                    if alerts and self.config.enable_response:
                        self._execute_response(alerts)
                
                # Wait for next collection interval
                time.sleep(self.config.collection_interval)
                
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                time.sleep(5)  # Brief pause before retry
    
    def _collect_events(self) -> List[Dict]:
        """Collect events from all configured collectors"""
        all_events = []
        
        for collector_name, collector in self.collectors.items():
            try:
                events = collector.collect()
                if events:
                    # Tag events with collector source
                    for event in events:
                        event['collector_source'] = collector_name
                        event['endpoint_id'] = self.config.endpoint_id
                        event['timestamp'] = time.time()
                    
                    all_events.extend(events)
                    logger.debug(f"Collected {len(events)} events from {collector_name}")
                    
            except Exception as e:
                logger.error(f"Error collecting from {collector_name}: {e}")
        
        return all_events
    
    def _process_events(self, events: List[Dict]) -> List[Dict]:
        """Process raw events into features for ML analysis"""
        processed_events = []
        
        for event in events:
            try:
                # Extract features using feature extractor
                features = self.feature_extractor.extract(event)
                
                if features:
                    event['features'] = features
                    processed_events.append(event)
                    
            except Exception as e:
                logger.error(f"Error processing event: {e}")
        
        logger.debug(f"Processed {len(processed_events)} events")
        return processed_events
    
    def _analyze_events(self, events: List[Dict]) -> List[Dict]:
        """Analyze events using ML models and Sigma rules"""
        alerts = []
        
        for event in events:
            try:
                # ML-based anomaly detection
                if 'features' in event:
                    anomaly_score = self.anomaly_detector.predict(event['features'])
                    threat_class = self.threat_classifier.predict(event['features'])
                    
                    event['anomaly_score'] = anomaly_score
                    event['threat_class'] = threat_class
                    
                    # Generate alert if threshold exceeded
                    if anomaly_score > self.config.ml_threshold:
                        alert = {
                            'type': 'ml_anomaly',
                            'severity': 'medium',
                            'event': event,
                            'score': anomaly_score,
                            'classification': threat_class
                        }
                        alerts.append(alert)
                
                # Sigma rule matching
                sigma_matches = self.sigma_engine.match(event)
                for match in sigma_matches:
                    alert = {
                        'type': 'sigma_rule',
                        'severity': match.get('level', 'medium'),
                        'rule_id': match.get('id'),
                        'rule_title': match.get('title'),
                        'event': event
                    }
                    alerts.append(alert)
                    
            except Exception as e:
                logger.error(f"Error analyzing event: {e}")
        
        if alerts:
            logger.info(f"Generated {len(alerts)} alerts")
        
        return alerts
    
    def _send_to_backend(self, events: List[Dict], alerts: List[Dict]) -> None:
        """Send processed events and alerts to backend"""
        try:
            payload = {
                'endpoint_id': self.config.endpoint_id,
                'timestamp': time.time(),
                'events': events,
                'alerts': alerts,
                'agent_version': '0.1.0'
            }
            
            response = self.secure_channel.send(
                url=f"{self.config.backend_url}/api/v1/events",
                data=payload
            )
            
            if response.get('status') == 'success':
                logger.debug(f"Successfully sent {len(events)} events to backend")
            else:
                logger.warning(f"Backend responded with: {response}")
                
        except Exception as e:
            logger.error(f"Failed to send data to backend: {e}")
    
    def _execute_response(self, alerts: List[Dict]) -> None:
        """Execute automated response playbooks for alerts"""
        for alert in alerts:
            try:
                response_executed = self.playbook_engine.execute(alert)
                if response_executed:
                    logger.info(f"Executed response for alert: {alert.get('type')}")
                    
            except Exception as e:
                logger.error(f"Error executing response: {e}")

def main():
    """Main entry point for VPEW-AI agent"""
    if len(sys.argv) != 2:
        print("Usage: vpew-agent <config_path>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    
    # Create defense authorization file if it doesn't exist
    auth_file = Path("DEFENSE_AUTHORIZATION.txt")
    if not auth_file.exists():
        print("Creating defense authorization file...")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\n")
            f.write("This system is authorized for defensive cybersecurity purposes only.\n")
            f.write("No offensive capabilities are enabled or permitted.\n")
            f.write(f"Authorized by: SOC Team\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Initialize and start agent
    agent = VPEWAgent(config_path)
    
    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Agent failed: {e}")
        sys.exit(1)
    finally:
        agent.stop()

if __name__ == "__main__":
    main()
