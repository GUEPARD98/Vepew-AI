"""
Health Monitoring System for VPEW-AI Agent
Monitors agent health, performance, and system status
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import psutil

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class HealthCheck:
    """Individual health check result"""
    name: str
    status: HealthStatus
    message: str
    timestamp: datetime
    details: Optional[Dict[str, Any]] = None

@dataclass
class SystemHealth:
    """Overall system health status"""
    overall_status: HealthStatus
    checks: List[HealthCheck]
    timestamp: datetime
    uptime_seconds: float
    version: str = "0.1.0"

class HealthMonitor:
    """Health monitoring system for VPEW-AI agent"""
    
    def __init__(self, agent_instance=None):
        self.agent = agent_instance
        self.start_time = time.time()
        self.health_history = []
        self.max_history_size = 100
        self.last_health_check = None
        self._stop_event = threading.Event()
        self._monitor_thread = None
        
        logger.info("Health monitoring system initialized")
    
    def start_monitoring(self, interval: int = 30):
        """Start continuous health monitoring"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Health monitoring already running")
            return
        
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Health monitoring started with {interval}s interval")
    
    def stop_monitoring(self):
        """Stop continuous health monitoring"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._stop_event.set()
            self._monitor_thread.join(timeout=5)
            logger.info("Health monitoring stopped")
    
    def _monitoring_loop(self, interval: int):
        """Continuous monitoring loop"""
        while not self._stop_event.is_set():
            try:
                health = self.get_current_health()
                self._store_health_status(health)
                
                # Log warnings and critical issues
                if health.overall_status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                    logger.warning(f"Health status: {health.overall_status.value}")
                    for check in health.checks:
                        if check.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                            logger.warning(f"Health check '{check.name}': {check.message}")
                
            except Exception as e:
                logger.error(f"Error in health monitoring loop: {e}")
            
            self._stop_event.wait(interval)
    
    def get_current_health(self) -> SystemHealth:
        """Get current system health status"""
        checks = []
        
        # Check agent status
        checks.append(self._check_agent_status())
        
        # Check system resources
        checks.append(self._check_memory_usage())
        checks.append(self._check_cpu_usage())
        checks.append(self._check_disk_space())
        
        # Check ML models
        checks.append(self._check_ml_models())
        
        # Check collectors
        checks.append(self._check_collectors())
        
        # Check configuration
        checks.append(self._check_configuration())
        
        # Determine overall status
        overall_status = self._determine_overall_status(checks)
        
        return SystemHealth(
            overall_status=overall_status,
            checks=checks,
            timestamp=datetime.now(),
            uptime_seconds=time.time() - self.start_time,
            version="0.1.0"
        )
    
    def _check_agent_status(self) -> HealthCheck:
        """Check if agent is running properly"""
        try:
            if self.agent:
                # Check if agent is properly initialized
                if hasattr(self.agent, 'config') and self.agent.config:
                    return HealthCheck(
                        name="agent_status",
                        status=HealthStatus.HEALTHY,
                        message="Agent is running normally",
                        timestamp=datetime.now()
                    )
                else:
                    return HealthCheck(
                        name="agent_status",
                        status=HealthStatus.WARNING,
                        message="Agent initialized but configuration not loaded",
                        timestamp=datetime.now()
                    )
            else:
                return HealthCheck(
                    name="agent_status",
                    status=HealthStatus.WARNING,
                    message="Agent instance not available for health check",
                    timestamp=datetime.now()
                )
        except Exception as e:
            return HealthCheck(
                name="agent_status",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking agent status: {e}",
                timestamp=datetime.now()
            )
    
    def _check_memory_usage(self) -> HealthCheck:
        """Check memory usage"""
        try:
            if not psutil:
                return HealthCheck(
                    name="memory_usage",
                    status=HealthStatus.UNKNOWN,
                    message="psutil not available",
                    timestamp=datetime.now()
                )
            
            memory = psutil.virtual_memory()
            usage_percent = memory.percent
            
            if usage_percent < 80:
                status = HealthStatus.HEALTHY
                message = f"Memory usage: {usage_percent:.1f}%"
            elif usage_percent < 90:
                status = HealthStatus.WARNING
                message = f"High memory usage: {usage_percent:.1f}%"
            else:
                status = HealthStatus.CRITICAL
                message = f"Critical memory usage: {usage_percent:.1f}%"
            
            return HealthCheck(
                name="memory_usage",
                status=status,
                message=message,
                timestamp=datetime.now(),
                details={"usage_percent": usage_percent, "available_mb": memory.available / (1024 * 1024)}
            )
        except Exception as e:
            return HealthCheck(
                name="memory_usage",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking memory: {e}",
                timestamp=datetime.now()
            )
    
    def _check_cpu_usage(self) -> HealthCheck:
        """Check CPU usage"""
        try:
            if not psutil:
                return HealthCheck(
                    name="cpu_usage",
                    status=HealthStatus.UNKNOWN,
                    message="psutil not available",
                    timestamp=datetime.now()
                )
            
            cpu_percent = psutil.cpu_percent(interval=1)
            
            if cpu_percent < 70:
                status = HealthStatus.HEALTHY
                message = f"CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent < 85:
                status = HealthStatus.WARNING
                message = f"High CPU usage: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.CRITICAL
                message = f"Critical CPU usage: {cpu_percent:.1f}%"
            
            return HealthCheck(
                name="cpu_usage",
                status=status,
                message=message,
                timestamp=datetime.now(),
                details={"cpu_percent": cpu_percent}
            )
        except Exception as e:
            return HealthCheck(
                name="cpu_usage",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking CPU: {e}",
                timestamp=datetime.now()
            )
    
    def _check_disk_space(self) -> HealthCheck:
        """Check disk space"""
        try:
            if not psutil:
                return HealthCheck(
                    name="disk_space",
                    status=HealthStatus.UNKNOWN,
                    message="psutil not available",
                    timestamp=datetime.now()
                )
            
            disk = psutil.disk_usage('/')
            usage_percent = (disk.used / disk.total) * 100
            free_gb = disk.free / (1024**3)
            
            if usage_percent < 80:
                status = HealthStatus.HEALTHY
                message = f"Disk usage: {usage_percent:.1f}% ({free_gb:.1f}GB free)"
            elif usage_percent < 90:
                status = HealthStatus.WARNING
                message = f"Low disk space: {usage_percent:.1f}% ({free_gb:.1f}GB free)"
            else:
                status = HealthStatus.CRITICAL
                message = f"Critical disk space: {usage_percent:.1f}% ({free_gb:.1f}GB free)"
            
            return HealthCheck(
                name="disk_space",
                status=status,
                message=message,
                timestamp=datetime.now(),
                details={"usage_percent": usage_percent, "free_gb": free_gb}
            )
        except Exception as e:
            return HealthCheck(
                name="disk_space",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking disk space: {e}",
                timestamp=datetime.now()
            )
    
    def _check_ml_models(self) -> HealthCheck:
        """Check ML models status"""
        try:
            if self.agent and hasattr(self.agent, 'anomaly_detector') and hasattr(self.agent, 'threat_classifier'):
                if self.agent.anomaly_detector and self.agent.threat_classifier:
                    return HealthCheck(
                        name="ml_models",
                        status=HealthStatus.HEALTHY,
                        message="ML models loaded and ready",
                        timestamp=datetime.now()
                    )
                else:
                    return HealthCheck(
                        name="ml_models",
                        status=HealthStatus.WARNING,
                        message="ML models not properly loaded",
                        timestamp=datetime.now()
                    )
            else:
                return HealthCheck(
                    name="ml_models",
                    status=HealthStatus.UNKNOWN,
                    message="Agent ML models not accessible",
                    timestamp=datetime.now()
                )
        except Exception as e:
            return HealthCheck(
                name="ml_models",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking ML models: {e}",
                timestamp=datetime.now()
            )
    
    def _check_collectors(self) -> HealthCheck:
        """Check event collectors status"""
        try:
            if self.agent and hasattr(self.agent, 'collectors'):
                active_collectors = 0
                total_collectors = len(self.agent.collectors) if self.agent.collectors else 0
                
                # Check if collectors are initialized (they don't have a 'running' attribute)
                if total_collectors > 0:
                    # For now, consider collectors active if they exist and are initialized
                    # In a real implementation, you might want to add a status check method
                    active_collectors = total_collectors
                    status = HealthStatus.HEALTHY
                    message = f"All {active_collectors} collectors initialized"
                else:
                    status = HealthStatus.CRITICAL
                    message = "No collectors initialized"
                
                return HealthCheck(
                    name="collectors",
                    status=status,
                    message=message,
                    timestamp=datetime.now(),
                    details={"active": active_collectors, "total": total_collectors}
                )
            else:
                return HealthCheck(
                    name="collectors",
                    status=HealthStatus.UNKNOWN,
                    message="Collectors not accessible",
                    timestamp=datetime.now()
                )
        except Exception as e:
            return HealthCheck(
                name="collectors",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking collectors: {e}",
                timestamp=datetime.now()
            )
    
    def _check_configuration(self) -> HealthCheck:
        """Check configuration status"""
        try:
            if self.agent and hasattr(self.agent, 'config'):
                config = self.agent.config
                issues = []
                
                # Check critical configuration
                if not hasattr(config, 'endpoint_id') or not config.endpoint_id:
                    issues.append("Missing endpoint_id")
                
                if not hasattr(config, 'collection_interval') or config.collection_interval <= 0:
                    issues.append("Invalid collection_interval")
                
                if issues:
                    return HealthCheck(
                        name="configuration",
                        status=HealthStatus.WARNING,
                        message=f"Configuration issues: {', '.join(issues)}",
                        timestamp=datetime.now(),
                        details={"issues": issues}
                    )
                else:
                    return HealthCheck(
                        name="configuration",
                        status=HealthStatus.HEALTHY,
                        message="Configuration is valid",
                        timestamp=datetime.now()
                    )
            else:
                return HealthCheck(
                    name="configuration",
                    status=HealthStatus.UNKNOWN,
                    message="Configuration not accessible",
                    timestamp=datetime.now()
                )
        except Exception as e:
            return HealthCheck(
                name="configuration",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking configuration: {e}",
                timestamp=datetime.now()
            )
    
    def _determine_overall_status(self, checks: List[HealthCheck]) -> HealthStatus:
        """Determine overall health status from individual checks"""
        if not checks:
            return HealthStatus.UNKNOWN
        
        # Priority: CRITICAL > WARNING > UNKNOWN > HEALTHY
        statuses = [check.status for check in checks]
        
        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        elif HealthStatus.WARNING in statuses:
            return HealthStatus.WARNING
        elif HealthStatus.UNKNOWN in statuses:
            return HealthStatus.UNKNOWN
        else:
            return HealthStatus.HEALTHY
    
    def _store_health_status(self, health: SystemHealth):
        """Store health status in history"""
        self.health_history.append(health)
        
        # Limit history size
        if len(self.health_history) > self.max_history_size:
            self.health_history.pop(0)
        
        self.last_health_check = health
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for external monitoring"""
        if not self.last_health_check:
            return {"status": "unknown", "message": "No health checks performed"}
        
        health = self.last_health_check
        
        # Convert to dictionary for JSON serialization
        summary = {
            "status": health.overall_status.value,
            "timestamp": health.timestamp.isoformat(),
            "uptime_seconds": health.uptime_seconds,
            "version": health.version,
            "checks": []
        }
        
        for check in health.checks:
            check_dict = {
                "name": check.name,
                "status": check.status.value,
                "message": check.message,
                "timestamp": check.timestamp.isoformat()
            }
            if check.details:
                check_dict["details"] = check.details
            summary["checks"].append(check_dict)
        
        return summary
    
    def get_health_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get health history for specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        history = []
        for health in self.health_history:
            if health.timestamp >= cutoff_time:
                history.append(self._health_to_dict(health))
        
        return history
    
    def _health_to_dict(self, health: SystemHealth) -> Dict[str, Any]:
        """Convert SystemHealth to dictionary"""
        return {
            "overall_status": health.overall_status.value,
            "timestamp": health.timestamp.isoformat(),
            "uptime_seconds": health.uptime_seconds,
            "version": health.version,
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "message": check.message,
                    "timestamp": check.timestamp.isoformat(),
                    "details": check.details
                }
                for check in health.checks
            ]
        }

def get_health_monitor(agent_instance=None) -> HealthMonitor:
    """Get health monitor instance"""
    return HealthMonitor(agent_instance)
