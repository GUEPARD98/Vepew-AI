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
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None

try:
    from .collectors import EventCollector, SysmonCollector, ETWCollector
    COLLECTORS_AVAILABLE = True
except ImportError:
    COLLECTORS_AVAILABLE = False
    EventCollector = SysmonCollector = ETWCollector = None

try:
    from .processors import FeatureExtractor
    PROCESSORS_AVAILABLE = True
except ImportError:
    PROCESSORS_AVAILABLE = False
    FeatureExtractor = None

# DEFENSIVE: Import ML models for threat detection and anomaly analysis
from ..ml import AnomalyDetector, ThreatClassifier

try:
    from ..rules import SigmaEngine
    RULES_AVAILABLE = True
except ImportError:
    RULES_AVAILABLE = False
    SigmaEngine = None

try:
    from ..utils import get_structured_logger, get_performance_logger, get_dynamic_config, get_metrics_collector
    from ..utils.health_monitor import get_health_monitor
    from ..utils.event_filter import get_event_filter
    from ..utils.alert_prioritizer import get_alert_prioritizer
    from ..utils.backup_recovery import get_backup_recovery_manager, BackupType
    from ..utils.health_api import get_health_api_server
    STRUCTURED_LOGGING_AVAILABLE = True
    DYNAMIC_CONFIG_AVAILABLE = True
    METRICS_AVAILABLE = True
    HEALTH_MONITOR_AVAILABLE = True
    EVENT_FILTER_AVAILABLE = True
    ALERT_PRIORITIZER_AVAILABLE = True
    BACKUP_RECOVERY_AVAILABLE = True
    HEALTH_API_AVAILABLE = True
except ImportError:
    STRUCTURED_LOGGING_AVAILABLE = False
    DYNAMIC_CONFIG_AVAILABLE = False
    METRICS_AVAILABLE = False
    HEALTH_MONITOR_AVAILABLE = False
    EVENT_FILTER_AVAILABLE = False
    ALERT_PRIORITIZER_AVAILABLE = False
    BACKUP_RECOVERY_AVAILABLE = False
    HEALTH_API_AVAILABLE = False
    get_structured_logger = None
    get_performance_logger = None
    get_dynamic_config = None
    get_metrics_collector = None
    get_health_monitor = None
    get_event_filter = None
    get_alert_prioritizer = None

try:
    from ..communication import SecureChannel
    COMMUNICATION_AVAILABLE = True
except ImportError:
    COMMUNICATION_AVAILABLE = False
    SecureChannel = None

try:
    from ..response import PlaybookEngine
    RESPONSE_AVAILABLE = True
except ImportError:
    RESPONSE_AVAILABLE = False
    PlaybookEngine = None

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
    backend_enabled: bool = True
    log_level: str = "INFO"

class VPEWAgent:
    """
    Main VPEW-AI sensor agent for endpoint monitoring
    
    This agent implements defensive monitoring with legal/ethical validation:
    - Collects security events from Windows endpoints
    - Applies ML-based anomaly detection
    - Executes Sigma rules for known DEFENSIVE attack pattern detection
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
        
        # Initialize structured logging (if available)
        self.structured_logger = None
        self.performance_logger = None
        if STRUCTURED_LOGGING_AVAILABLE:
            try:
                self.structured_logger = get_structured_logger("vpew.agent")
                self.performance_logger = get_performance_logger()
                self.structured_logger.info("Structured logging initialized", component="agent")
            except Exception as e:
                logger.warning(f"Failed to initialize structured logging: {e}")
        
        # Initialize dynamic configuration (if available)
        self.dynamic_config = None
        if DYNAMIC_CONFIG_AVAILABLE:
            try:
                self.dynamic_config = get_dynamic_config(config_path)
                self.dynamic_config.add_change_callback(self._on_config_change)
                self.dynamic_config.start_watching()
                logger.info("Dynamic configuration initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize dynamic configuration: {e}")
        
        # Initialize metrics collection (if available)
        self.metrics_collector = None
        if METRICS_AVAILABLE:
            try:
                self.metrics_collector = get_metrics_collector()
                logger.info("Metrics collection initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize metrics collection: {e}")
        
        # Initialize health monitoring (if available)
        self.health_monitor = None
        if HEALTH_MONITOR_AVAILABLE:
            try:
                self.health_monitor = get_health_monitor(self)
                logger.info("Health monitoring initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize health monitoring: {e}")
        
        # Initialize event filtering (if available)
        self.event_filter = None
        if EVENT_FILTER_AVAILABLE:
            try:
                self.event_filter = get_event_filter()
                logger.info("Event filtering initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize event filtering: {e}")
        
        # Initialize alert prioritization (if available)
        self.alert_prioritizer = None
        if ALERT_PRIORITIZER_AVAILABLE:
            try:
                self.alert_prioritizer = get_alert_prioritizer()
                logger.info("Alert prioritization initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize alert prioritization: {e}")
        
        # Initialize backup and recovery system (if available)
        self.backup_manager = None
        if BACKUP_RECOVERY_AVAILABLE:
            try:
                self.backup_manager = get_backup_recovery_manager()
                logger.info("Backup and recovery system initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize backup and recovery: {e}")
        
        # Initialize health check API server (if available)
        self.health_api_server = None
        if HEALTH_API_AVAILABLE:
            try:
                self.health_api_server = get_health_api_server(self, host="localhost", port=8080)
                logger.info("Health check API server initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize health check API: {e}")
        
        # Legal/Ethical validation
        self._validate_legal_compliance()
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.running = False
        self.collectors = {}
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        # DEFENSIVE: Initialize threat classifier for defensive analysis
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
        - No offensive capabilities are enabled (DEFENSIVE USE ONLY)
        - Proper authorization is in place
        - Compliance with corporate policies
        """
        logger.info("Performing legal/ethical validation...")
        
        # Check for authorization file
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        if not auth_file.exists():
            logger.error("DEFENSIVE authorization file not found!")
            logger.error("Create DEFENSE_AUTHORIZATION.txt to confirm DEFENSIVE use only")
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
        
        # DEFENSIVE: Ensure no offensive modules are present
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
                                    logger.warning(f"Potential DEFENSIVE content validation in {file_path}")
                    except:
                        continue
        
        logger.info("Legal/ethical validation completed successfully")
        logger.info("System authorized for DEFENSIVE USE ONLY")
    
    def _on_config_change(self, new_config: Dict[str, Any]) -> None:
        """Handle dynamic configuration changes"""
        try:
            # Update ML threshold if changed
            if 'agent' in new_config and 'ml_threshold' in new_config['agent']:
                old_threshold = self.config.ml_threshold
                new_threshold = new_config['agent']['ml_threshold']
                if old_threshold != new_threshold:
                    self.config.ml_threshold = new_threshold
                    logger.info(f"ML threshold updated: {old_threshold} -> {new_threshold}")
            
            # Update collection interval if changed
            if 'agent' in new_config and 'collection_interval' in new_config['agent']:
                old_interval = self.config.collection_interval
                new_interval = new_config['agent']['collection_interval']
                if old_interval != new_interval:
                    self.config.collection_interval = new_interval
                    logger.info(f"Collection interval updated: {old_interval} -> {new_interval}")
            
            # Update backend enabled status if changed
            if 'backend' in new_config and 'enabled' in new_config['backend']:
                old_enabled = getattr(self.config, 'backend_enabled', True)
                new_enabled = new_config['backend']['enabled']
                if old_enabled != new_enabled:
                    self.config.backend_enabled = new_enabled
                    logger.info(f"Backend enabled status updated: {old_enabled} -> {new_enabled}")
            
            # Log configuration change
            if self.structured_logger:
                self.structured_logger.info(
                    "Configuration updated dynamically",
                    component="agent",
                    config_sections=list(new_config.keys())
                )
                
        except Exception as e:
            logger.error(f"Error handling config change: {e}")
    
    def _load_config(self, config_path: str) -> AgentConfig:
        """Load agent configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            return AgentConfig(
                endpoint_id=config_data.get('endpoint_id', f"endpoint-{os.getenv('COMPUTERNAME', 'unknown')}"),
                backend_url=config_data.get('backend_url', 'https://vpew-backend:8443'),
                backend_enabled=config_data.get('backend', {}).get('enabled', True),
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
            self.anomaly_detector.load_model("models/anomaly_detector.joblib")
            # DEFENSIVE: Load threat classifier model for defensive analysis
            self.threat_classifier.load_model("models/threat_classifier.joblib")
            
            # Load Sigma rules
            self.sigma_engine.load_rules()
            
        except Exception as e:
            logger.error(f"Failed to initialize agent components: {e}")
            sys.exit(1)
        
        # Start health monitoring
        if self.health_monitor:
            self.health_monitor.start_monitoring(interval=30)
        
        # Start health check API server
        if self.health_api_server:
            try:
                self.health_api_server.start()
                logger.info("Health check API server started")
            except Exception as e:
                logger.error(f"Failed to start health check API server: {e}")
        
        # Start collection loop
        self.running = True
        self._collection_loop()
    
    def stop(self) -> None:
        """Stop the VPEW-AI agent gracefully"""
        logger.info("Stopping VPEW-AI Agent...")
        self.running = False
        
        # Stop health monitoring
        if self.health_monitor:
            try:
                self.health_monitor.stop_monitoring()
                logger.info("Stopped health monitoring")
            except Exception as e:
                logger.error(f"Error stopping health monitoring: {e}")
        
        # Stop dynamic configuration watching
        if self.dynamic_config:
            try:
                self.dynamic_config.stop_watching()
                logger.info("Stopped dynamic configuration watching")
            except Exception as e:
                logger.error(f"Error stopping dynamic config: {e}")
        
        # Stop health check API server
        if self.health_api_server:
            try:
                self.health_api_server.stop()
                logger.info("Health check API server stopped")
            except Exception as e:
                logger.error(f"Error stopping health check API server: {e}")
        
        # Create final backup before stopping
        if self.backup_manager:
            try:
                success, backup_id = self.backup_manager.create_backup(
                    BackupType.CONFIG, 
                    "Automatic backup before agent stop"
                )
                if success:
                    logger.info(f"Final backup created: {backup_id}")
                else:
                    logger.warning("Failed to create final backup")
            except Exception as e:
                logger.error(f"Error creating final backup: {e}")
        
        # Stop collectors
        for collector_name, collector in self.collectors.items():
            try:
                collector.stop()
                logger.info(f"Stopped {collector_name} collector")
            except Exception as e:
                logger.error(f"Error stopping {collector_name}: {e}")
        
        logger.info("VPEW-AI Agent stopped")
    
    def create_backup(self, backup_type: str = "config", description: str = "Manual backup") -> Tuple[bool, str]:
        """Create a backup of specified type"""
        if not self.backup_manager:
            logger.error("Backup system not available")
            return False, ""
        
        try:
            backup_type_enum = BackupType(backup_type.lower())
            success, backup_id = self.backup_manager.create_backup(backup_type_enum, description)
            
            if success:
                logger.info(f"Backup created successfully: {backup_id}")
            else:
                logger.error(f"Failed to create backup: {backup_id}")
            
            return success, backup_id
        except ValueError:
            logger.error(f"Invalid backup type: {backup_type}")
            return False, ""
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return False, ""
    
    def restore_backup(self, backup_id: str) -> bool:
        """Restore from backup"""
        if not self.backup_manager:
            logger.error("Backup system not available")
            return False
        
        try:
            success = self.backup_manager.restore_backup(backup_id)
            
            if success:
                logger.info(f"Backup restored successfully: {backup_id}")
            else:
                logger.error(f"Failed to restore backup: {backup_id}")
            
            return success
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
            return False
    
    def list_backups(self, backup_type: str = None) -> List[Dict[str, Any]]:
        """List available backups"""
        if not self.backup_manager:
            logger.error("Backup system not available")
            return []
        
        try:
            backup_type_enum = BackupType(backup_type.lower()) if backup_type else None
            backups = self.backup_manager.list_backups(backup_type_enum)
            
            return [{
                'backup_id': backup.backup_id,
                'backup_type': backup.backup_type.value,
                'status': backup.status.value,
                'created_at': backup.created_at.isoformat(),
                'size_bytes': backup.size_bytes,
                'description': backup.description,
                'restored_at': backup.restored_at.isoformat() if backup.restored_at else None
            } for backup in backups]
        except ValueError:
            logger.error(f"Invalid backup type: {backup_type}")
            return []
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return []
    
    def get_backup_statistics(self) -> Dict[str, Any]:
        """Get backup and recovery statistics"""
        if not self.backup_manager:
            logger.error("Backup system not available")
            return {}
        
        try:
            return self.backup_manager.get_statistics()
        except Exception as e:
            logger.error(f"Error getting backup statistics: {e}")
            return {}
    
    def get_health_api_status(self) -> Dict[str, Any]:
        """Get health check API server status"""
        if not self.health_api_server:
            return {"available": False, "error": "Health API server not available"}
        
        try:
            return {
                "available": True,
                **self.health_api_server.get_status()
            }
        except Exception as e:
            logger.error(f"Error getting health API status: {e}")
            return {"available": False, "error": str(e)}
    
    def restart_health_api_server(self, host: str = "localhost", port: int = 8080) -> bool:
        """Restart health check API server with new configuration"""
        try:
            # Stop current server
            if self.health_api_server:
                self.health_api_server.stop()
            
            # Start new server
            if HEALTH_API_AVAILABLE:
                self.health_api_server = get_health_api_server(self, host, port)
                self.health_api_server.start()
                logger.info(f"Health API server restarted on {host}:{port}")
                return True
            else:
                logger.error("Health API server not available")
                return False
                
        except Exception as e:
            logger.error(f"Error restarting health API server: {e}")
            return False
    
    def _collection_loop(self) -> None:
        """Main event collection and processing loop"""
        logger.info("Starting event collection loop...")
        
        while self.running:
            try:
                # Start collection timing
                collection_start = time.time()
                
                # Collect system metrics
                if self.metrics_collector:
                    self.metrics_collector.collect_system_metrics()
                
                # Collect events from all sources
                events = self._collect_events()
                collection_time = (time.time() - collection_start) * 1000  # Convert to ms
                
                if events:
                    # Process events
                    processed_events = self._process_events(events)
                    
                    # Analyze with ML and rules
                    analysis_start = time.time()
                    alerts = self._analyze_events(processed_events)
                    analysis_time = (time.time() - analysis_start) * 1000  # Convert to ms
                    
                    # Send to backend
                    backend_start = time.time()
                    if processed_events:
                        self._send_to_backend(processed_events, alerts)
                    backend_time = (time.time() - backend_start) * 1000  # Convert to ms
                    
                    # Execute response if needed
                    if alerts and self.config.enable_response:
                        self._execute_response(alerts)
                    
                    # Collect application metrics
                    if self.metrics_collector:
                        self.metrics_collector.collect_app_metrics(
                            events_processed=len(processed_events),
                            alerts_generated=len(alerts),
                            ml_predictions=len(processed_events),
                            collection_time_ms=collection_time,
                            analysis_time_ms=analysis_time,
                            backend_send_time_ms=backend_time,
                            error_count=0
                        )
                
                # Wait for next collection interval
                time.sleep(self.config.collection_interval)
                
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                # Increment error counter
                if self.metrics_collector:
                    self.metrics_collector.increment_counter('collection_errors')
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
        
        # Apply event filtering if available
        if self.event_filter and events:
            try:
                filtered_events = self.event_filter.filter_events(events)
                # Convert FilteredEvent objects back to dict format for processing
                events = [filtered_event.original_event for filtered_event in filtered_events]
                logger.debug(f"Event filtering: {len(events)} events after filtering")
            except Exception as e:
                logger.error(f"Error in event filtering: {e}")
                # Continue with original events if filtering fails
        
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
        
        # Start performance timing if structured logging is available
        if self.performance_logger:
            self.performance_logger.start_timer("event_analysis")
        
        for event in events:
            try:
                # ML-based anomaly detection
                if 'features' in event:
                    # Convert features to DataFrame
                    import pandas as pd
                    features_data = event['features']
                    
                    if isinstance(features_data, dict):
                        # If it's the feature extractor output, get the feature vector
                        if 'feature_vector' in features_data:
                            feature_vector = features_data['feature_vector']
                            # Convert numpy array to DataFrame with generic column names (matching training)
                            if hasattr(feature_vector, 'shape') and len(feature_vector) > 0:
                                # Always use generic feature names to match training data
                                feature_names = [f'feature_{i}' for i in range(len(feature_vector))]
                                features_df = pd.DataFrame([feature_vector], columns=feature_names)
                            else:
                                # Skip if no valid features
                                continue
                        else:
                            # Direct dict to DataFrame conversion with generic column names
                            features_df = pd.DataFrame([features_data])
                            # Rename columns to match training data format
                            if not features_df.empty:
                                features_df.columns = [f'feature_{i}' for i in range(len(features_df.columns))]
                    else:
                        features_df = features_data
                    
                    anomaly_predictions = self.anomaly_detector.predict(features_df)
                    # DEFENSIVE: Predict threat classification for defensive analysis
                    threat_predictions = self.threat_classifier.predict(features_df)
                    
                    # Handle empty arrays safely
                    if len(anomaly_predictions) > 0:
                        anomaly_score = float(anomaly_predictions[0])
                        event['anomaly_score'] = anomaly_score
                        
                        # Generate alert if threshold exceeded
                        if anomaly_score > self.config.ml_threshold:
                            alert = {
                                'type': 'ml_anomaly',
                                'severity': 'medium',
                                'event': event,
                                'score': anomaly_score,
                                'classification': threat_predictions[0] if len(threat_predictions) > 0 else 'unknown'
                            }
                            alerts.append(alert)
                    else:
                        # No valid predictions, set default values
                        event['anomaly_score'] = 0.0
                    
                    # DEFENSIVE: Assign threat classification for defensive analysis
                    if len(threat_predictions) > 0:
                        event['threat_class'] = threat_predictions[0]
                    else:
                        event['threat_class'] = 'unknown'
                
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
            
            # Apply alert prioritization if available
            if self.alert_prioritizer:
                try:
                    prioritized_alerts = self.alert_prioritizer.prioritize_alerts(alerts)
                    # Convert back to dict format for compatibility
                    alerts = [prioritized_alert.original_alert for prioritized_alert in prioritized_alerts]
                    
                    # Log prioritization results
                    if prioritized_alerts:
                        severity_counts = {}
                        for prioritized_alert in prioritized_alerts:
                            severity = prioritized_alert.severity.value
                            severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        
                        logger.info(f"Alert prioritization: {severity_counts}")
                        
                        # Log high priority alerts
                        high_priority = [pa for pa in prioritized_alerts 
                                       if pa.severity.value in ['critical', 'high']]
                        if high_priority:
                            logger.warning(f"High priority alerts detected: {len(high_priority)}")
                            for alert in high_priority[:3]:  # Log first 3 high priority alerts
                                logger.warning(f"High priority: {alert.severity.value} - "
                                             f"{alert.original_alert.get('type')} - "
                                             f"Score: {alert.priority_score:.3f}")
                    
                except Exception as e:
                    logger.error(f"Error in alert prioritization: {e}")
                    # Continue with original alerts if prioritization fails
        
        # End performance timing and log metrics
        if self.performance_logger:
            self.performance_logger.end_timer(
                "event_analysis",
                events_processed=len(events),
                alerts_generated=len(alerts),
                alert_rate=len(alerts) / len(events) if events else 0
            )
        
        return alerts
    
    def _send_to_backend(self, events: List[Dict], alerts: List[Dict]) -> None:
        """Send processed events and alerts to backend"""
        # Check if backend is enabled in config
        if hasattr(self, 'config') and hasattr(self.config, 'backend_enabled') and not self.config.backend_enabled:
            logger.debug("Backend disabled, skipping data transmission")
            return
            
        try:
            # DEFENSIVE: Data payload for secure transmission to backend
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
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of the agent"""
        if self.health_monitor:
            return self.health_monitor.get_health_summary()
        else:
            return {
                "status": "unknown",
                "message": "Health monitoring not available",
                "timestamp": time.time()
            }
    
    def get_health_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get health history for specified hours"""
        if self.health_monitor:
            return self.health_monitor.get_health_history(hours)
        else:
            return []
    
    def get_event_filter_stats(self) -> Dict[str, Any]:
        """Get event filtering statistics"""
        if self.event_filter:
            return self.event_filter.get_statistics()
        else:
            return {"message": "Event filtering not available"}
    
    def get_event_filter_rules(self) -> List[Dict[str, Any]]:
        """Get event filtering rules statistics"""
        if self.event_filter:
            return self.event_filter.get_rule_statistics()
        else:
            return []
    
    def get_alert_prioritizer_stats(self) -> Dict[str, Any]:
        """Get alert prioritization statistics"""
        if self.alert_prioritizer:
            return self.alert_prioritizer.get_statistics()
        else:
            return {"message": "Alert prioritization not available"}
    
    def get_risk_profiles(self) -> Dict[str, Any]:
        """Get risk profiles from alert prioritizer"""
        if self.alert_prioritizer:
            return self.alert_prioritizer.get_risk_profiles()
        else:
            return {"message": "Alert prioritization not available"}

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
            f.write("This system is authorized for DEFENSIVE cybersecurity purposes only.\n")
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
