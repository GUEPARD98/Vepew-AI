"""
Intelligent Alert Prioritization System for VPEW-AI
Provides smart alert prioritization based on multiple factors
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import hashlib

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertCategory(Enum):
    """Alert categories"""
    SECURITY = "security"
    SYSTEM = "system"
    NETWORK = "network"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    ML_ANOMALY = "ml_anomaly"

class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

@dataclass
class AlertContext:
    """Context information for alert prioritization"""
    endpoint_id: str
    user_name: Optional[str] = None
    process_name: Optional[str] = None
    remote_ip: Optional[str] = None
    local_ip: Optional[str] = None
    file_path: Optional[str] = None
    registry_path: Optional[str] = None
    timestamp: datetime = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class PrioritizedAlert:
    """Alert with prioritization metadata"""
    original_alert: Dict[str, Any]
    priority_score: float
    severity: AlertSeverity
    category: AlertCategory
    context: AlertContext
    priority_factors: Dict[str, float]
    correlated_alerts: List[str] = None
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if self.correlated_alerts is None:
            self.correlated_alerts = []

class AlertPrioritizer:
    """Intelligent alert prioritization system"""
    
    def __init__(self):
        self.alert_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.user_risk_profiles: Dict[str, Dict[str, Any]] = {}
        self.process_risk_profiles: Dict[str, Dict[str, Any]] = {}
        self.ip_risk_profiles: Dict[str, Dict[str, Any]] = {}
        self.correlation_window = 300  # 5 minutes
        self.priority_weights = {
            'base_severity': 0.3,
            'context_risk': 0.25,
            'correlation_boost': 0.2,
            'user_risk': 0.15,
            'process_risk': 0.1
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            'critical': 0.8,
            'high': 0.6,
            'medium': 0.4,
            'low': 0.2
        }
        
        # Initialize risk profiles
        self._initialize_risk_profiles()
        
        logger.info("Alert prioritization system initialized")
    
    def _initialize_risk_profiles(self):
        """Initialize default risk profiles"""
        # High-risk users
        high_risk_users = ['administrator', 'admin', 'system', 'root', 'service']
        for user in high_risk_users:
            self.user_risk_profiles[user.lower()] = {
                'risk_score': 0.8,
                'alert_count': 0,
                'last_alert': None,
                'risk_factors': ['privileged_account']
            }
        
        # High-risk processes
        high_risk_processes = [
            'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
            'wscript.exe', 'cscript.exe', 'mshta.exe', 'certutil.exe'
        ]
        for process in high_risk_processes:
            self.process_risk_profiles[process.lower()] = {
                'risk_score': 0.7,
                'alert_count': 0,
                'last_alert': None,
                'risk_factors': ['executable_scripting']
            }
        
        # High-risk IPs (example - should be configurable)
        high_risk_ips = ['0.0.0.0', '127.0.0.1']
        for ip in high_risk_ips:
            self.ip_risk_profiles[ip] = {
                'risk_score': 0.5,
                'alert_count': 0,
                'last_alert': None,
                'risk_factors': ['local_network']
            }
        
        logger.info(f"Initialized risk profiles: {len(self.user_risk_profiles)} users, "
                   f"{len(self.process_risk_profiles)} processes, {len(self.ip_risk_profiles)} IPs")
    
    def prioritize_alert(self, alert: Dict[str, Any]) -> PrioritizedAlert:
        """Prioritize a single alert"""
        try:
            # Extract context
            context = self._extract_alert_context(alert)
            
            # Calculate priority factors
            priority_factors = self._calculate_priority_factors(alert, context)
            
            # Calculate overall priority score
            priority_score = self._calculate_priority_score(priority_factors)
            
            # Determine severity and category
            severity = self._determine_severity(priority_score)
            category = self._determine_category(alert, context)
            
            # Check for correlations
            correlated_alerts = self._find_correlated_alerts(context)
            
            # Create prioritized alert
            prioritized_alert = PrioritizedAlert(
                original_alert=alert,
                priority_score=priority_score,
                severity=severity,
                category=category,
                context=context,
                priority_factors=priority_factors,
                correlated_alerts=correlated_alerts
            )
            
            # Update risk profiles
            self._update_risk_profiles(context, prioritized_alert)
            
            # Add to history
            self._add_to_history(prioritized_alert)
            
            return prioritized_alert
            
        except Exception as e:
            logger.error(f"Error prioritizing alert: {e}")
            # Return default prioritized alert
            return PrioritizedAlert(
                original_alert=alert,
                priority_score=0.5,
                severity=AlertSeverity.MEDIUM,
                category=AlertCategory.SYSTEM,
                context=AlertContext(endpoint_id="unknown"),
                priority_factors={'error': 1.0}
            )
    
    def prioritize_alerts(self, alerts: List[Dict[str, Any]]) -> List[PrioritizedAlert]:
        """Prioritize multiple alerts"""
        prioritized_alerts = []
        
        for alert in alerts:
            prioritized_alert = self.prioritize_alert(alert)
            prioritized_alerts.append(prioritized_alert)
        
        # Sort by priority score (highest first)
        prioritized_alerts.sort(key=lambda x: x.priority_score, reverse=True)
        
        logger.debug(f"Prioritized {len(prioritized_alerts)} alerts")
        return prioritized_alerts
    
    def _extract_alert_context(self, alert: Dict[str, Any]) -> AlertContext:
        """Extract context information from alert"""
        event = alert.get('event', {})
        
        return AlertContext(
            endpoint_id=event.get('endpoint_id', 'unknown'),
            user_name=event.get('user_name'),
            process_name=event.get('process_name'),
            remote_ip=event.get('remote_ip'),
            local_ip=event.get('local_ip'),
            file_path=event.get('file_path'),
            registry_path=event.get('registry_path'),
            timestamp=datetime.fromtimestamp(event.get('timestamp', time.time()))
        )
    
    def _calculate_priority_factors(self, alert: Dict[str, Any], context: AlertContext) -> Dict[str, float]:
        """Calculate individual priority factors"""
        factors = {}
        
        # Base severity factor
        alert_type = alert.get('type', 'unknown')
        factors['base_severity'] = self._get_base_severity_score(alert_type)
        
        # Context risk factor
        factors['context_risk'] = self._calculate_context_risk(context)
        
        # User risk factor
        factors['user_risk'] = self._get_user_risk_score(context.user_name)
        
        # Process risk factor
        factors['process_risk'] = self._get_process_risk_score(context.process_name)
        
        # ML confidence factor
        if 'score' in alert:
            factors['ml_confidence'] = alert['score']
        else:
            factors['ml_confidence'] = 0.5
        
        # Time-based factor (higher priority for recent alerts)
        time_factor = self._calculate_time_factor(context.timestamp)
        factors['time_factor'] = time_factor
        
        return factors
    
    def _get_base_severity_score(self, alert_type: str) -> float:
        """Get base severity score for alert type"""
        severity_scores = {
            'ml_anomaly': 0.7,
            'sigma_rule': 0.8,
            'process_anomaly': 0.6,
            'network_anomaly': 0.5,
            'user_anomaly': 0.6,
            'file_anomaly': 0.5,
            'registry_anomaly': 0.4
        }
        return severity_scores.get(alert_type, 0.5)
    
    def _calculate_context_risk(self, context: AlertContext) -> float:
        """Calculate context-based risk score"""
        risk_score = 0.0
        
        # Network context
        if context.remote_ip:
            if self._is_external_ip(context.remote_ip):
                risk_score += 0.3
            if context.remote_ip in self.ip_risk_profiles:
                risk_score += self.ip_risk_profiles[context.remote_ip]['risk_score'] * 0.2
        
        # File context
        if context.file_path:
            if any(susp in context.file_path.lower() for susp in ['temp', 'download', 'appdata']):
                risk_score += 0.2
        
        # Registry context
        if context.registry_path:
            if any(susp in context.registry_path.lower() for susp in ['run', 'startup', 'services']):
                risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (simple implementation)"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                first_octet = int(parts[0])
                # Private IP ranges
                if (first_octet == 10 or 
                    (first_octet == 172 and 16 <= int(parts[1]) <= 31) or
                    (first_octet == 192 and int(parts[1]) == 168)):
                    return False
                return True
        except:
            pass
        return False
    
    def _get_user_risk_score(self, user_name: Optional[str]) -> float:
        """Get user risk score"""
        if not user_name:
            return 0.0
        
        user_lower = user_name.lower()
        if user_lower in self.user_risk_profiles:
            return self.user_risk_profiles[user_lower]['risk_score']
        
        return 0.0
    
    def _get_process_risk_score(self, process_name: Optional[str]) -> float:
        """Get process risk score"""
        if not process_name:
            return 0.0
        
        process_lower = process_name.lower()
        if process_lower in self.process_risk_profiles:
            return self.process_risk_profiles[process_lower]['risk_score']
        
        return 0.0
    
    def _calculate_time_factor(self, timestamp: datetime) -> float:
        """Calculate time-based priority factor"""
        now = datetime.now()
        time_diff = (now - timestamp).total_seconds()
        
        # Higher priority for more recent alerts
        if time_diff < 60:  # Last minute
            return 1.0
        elif time_diff < 300:  # Last 5 minutes
            return 0.8
        elif time_diff < 900:  # Last 15 minutes
            return 0.6
        elif time_diff < 3600:  # Last hour
            return 0.4
        else:
            return 0.2
    
    def _calculate_priority_score(self, factors: Dict[str, float]) -> float:
        """Calculate overall priority score"""
        score = 0.0
        
        # Apply weights to factors
        for factor, value in factors.items():
            weight = self.priority_weights.get(factor, 0.1)
            score += value * weight
        
        # Normalize to 0-1 range
        return min(max(score, 0.0), 1.0)
    
    def _determine_severity(self, priority_score: float) -> AlertSeverity:
        """Determine alert severity based on priority score"""
        if priority_score >= self.risk_thresholds['critical']:
            return AlertSeverity.CRITICAL
        elif priority_score >= self.risk_thresholds['high']:
            return AlertSeverity.HIGH
        elif priority_score >= self.risk_thresholds['medium']:
            return AlertSeverity.MEDIUM
        elif priority_score >= self.risk_thresholds['low']:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def _determine_category(self, alert: Dict[str, Any], context: AlertContext) -> AlertCategory:
        """Determine alert category"""
        alert_type = alert.get('type', 'unknown')
        
        if 'ml_anomaly' in alert_type:
            return AlertCategory.ML_ANOMALY
        elif context.process_name:
            return AlertCategory.PROCESS
        elif context.remote_ip or context.local_ip:
            return AlertCategory.NETWORK
        elif context.user_name:
            return AlertCategory.USER
        elif context.file_path:
            return AlertCategory.FILE
        elif context.registry_path:
            return AlertCategory.REGISTRY
        elif 'security' in alert_type.lower():
            return AlertCategory.SECURITY
        else:
            return AlertCategory.SYSTEM
    
    def _find_correlated_alerts(self, context: AlertContext) -> List[str]:
        """Find correlated alerts within time window"""
        correlated = []
        cutoff_time = context.timestamp - timedelta(seconds=self.correlation_window)
        
        # Check user-based correlations
        if context.user_name:
            user_key = f"user:{context.user_name.lower()}"
            if user_key in self.alert_history:
                for alert_id, timestamp in self.alert_history[user_key]:
                    if timestamp > cutoff_time:
                        correlated.append(alert_id)
        
        # Check process-based correlations
        if context.process_name:
            process_key = f"process:{context.process_name.lower()}"
            if process_key in self.alert_history:
                for alert_id, timestamp in self.alert_history[process_key]:
                    if timestamp > cutoff_time:
                        correlated.append(alert_id)
        
        # Check IP-based correlations
        if context.remote_ip:
            ip_key = f"ip:{context.remote_ip}"
            if ip_key in self.alert_history:
                for alert_id, timestamp in self.alert_history[ip_key]:
                    if timestamp > cutoff_time:
                        correlated.append(alert_id)
        
        return list(set(correlated))  # Remove duplicates
    
    def _update_risk_profiles(self, context: AlertContext, alert: PrioritizedAlert):
        """Update risk profiles based on alert"""
        # Update user risk profile
        if context.user_name:
            user_lower = context.user_name.lower()
            if user_lower not in self.user_risk_profiles:
                self.user_risk_profiles[user_lower] = {
                    'risk_score': 0.3,
                    'alert_count': 0,
                    'last_alert': None,
                    'risk_factors': []
                }
            
            profile = self.user_risk_profiles[user_lower]
            profile['alert_count'] += 1
            profile['last_alert'] = context.timestamp
            
            # Increase risk score based on alert severity
            if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
                profile['risk_score'] = min(profile['risk_score'] + 0.1, 1.0)
        
        # Update process risk profile
        if context.process_name:
            process_lower = context.process_name.lower()
            if process_lower not in self.process_risk_profiles:
                self.process_risk_profiles[process_lower] = {
                    'risk_score': 0.3,
                    'alert_count': 0,
                    'last_alert': None,
                    'risk_factors': []
                }
            
            profile = self.process_risk_profiles[process_lower]
            profile['alert_count'] += 1
            profile['last_alert'] = context.timestamp
            
            # Increase risk score based on alert severity
            if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
                profile['risk_score'] = min(profile['risk_score'] + 0.1, 1.0)
        
        # Update IP risk profile
        if context.remote_ip:
            if context.remote_ip not in self.ip_risk_profiles:
                self.ip_risk_profiles[context.remote_ip] = {
                    'risk_score': 0.3,
                    'alert_count': 0,
                    'last_alert': None,
                    'risk_factors': []
                }
            
            profile = self.ip_risk_profiles[context.remote_ip]
            profile['alert_count'] += 1
            profile['last_alert'] = context.timestamp
    
    def _add_to_history(self, alert: PrioritizedAlert):
        """Add alert to history for correlation"""
        alert_id = self._generate_alert_id(alert)
        timestamp = alert.context.timestamp
        
        # Add to user history
        if alert.context.user_name:
            user_key = f"user:{alert.context.user_name.lower()}"
            self.alert_history[user_key].append((alert_id, timestamp))
        
        # Add to process history
        if alert.context.process_name:
            process_key = f"process:{alert.context.process_name.lower()}"
            self.alert_history[process_key].append((alert_id, timestamp))
        
        # Add to IP history
        if alert.context.remote_ip:
            ip_key = f"ip:{alert.context.remote_ip}"
            self.alert_history[ip_key].append((alert_id, timestamp))
    
    def _generate_alert_id(self, alert: PrioritizedAlert) -> str:
        """Generate unique alert ID"""
        key_data = f"{alert.context.endpoint_id}:{alert.context.timestamp}:{alert.original_alert.get('type')}"
        return hashlib.md5(key_data.encode()).hexdigest()[:16]
    
    def get_risk_profiles(self) -> Dict[str, Any]:
        """Get current risk profiles"""
        return {
            'users': dict(self.user_risk_profiles),
            'processes': dict(self.process_risk_profiles),
            'ips': dict(self.ip_risk_profiles)
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get prioritization statistics"""
        return {
            'total_alerts_processed': sum(len(history) for history in self.alert_history.values()),
            'risk_profiles_count': {
                'users': len(self.user_risk_profiles),
                'processes': len(self.process_risk_profiles),
                'ips': len(self.ip_risk_profiles)
            },
            'correlation_window': self.correlation_window,
            'priority_weights': self.priority_weights
        }

def get_alert_prioritizer() -> AlertPrioritizer:
    """Get alert prioritizer instance"""
    return AlertPrioritizer()
