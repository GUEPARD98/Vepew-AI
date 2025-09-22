"""
Performance metrics collection for VPEW-AI
Provides system and application metrics for monitoring
"""

import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from collections import deque, defaultdict
from dataclasses import dataclass, asdict


@dataclass
class SystemMetrics:
    """System-level performance metrics"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int


@dataclass
class ApplicationMetrics:
    """Application-level performance metrics"""
    timestamp: str
    events_processed: int
    alerts_generated: int
    ml_predictions: int
    collection_time_ms: float
    analysis_time_ms: float
    backend_send_time_ms: float
    error_count: int


class MetricsCollector:
    """Collects and manages performance metrics"""
    
    def __init__(self, max_history: int = 100):
        """
        Initialize metrics collector
        
        Args:
            max_history: Maximum number of historical metrics to keep
        """
        self.max_history = max_history
        self.system_metrics_history = deque(maxlen=max_history)
        self.app_metrics_history = deque(maxlen=max_history)
        self.counters = defaultdict(int)
        self.timers = {}
        self.lock = threading.Lock()
        
        # Network baseline for delta calculations
        self.network_baseline = self._get_network_stats()
        self.last_collection_time = time.time()
    
    def _get_network_stats(self) -> Dict[str, int]:
        """Get current network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }
        except:
            return {'bytes_sent': 0, 'bytes_recv': 0}
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics"""
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Network (delta since last collection)
            current_network = self._get_network_stats()
            network_delta = {
                'bytes_sent': current_network['bytes_sent'] - self.network_baseline['bytes_sent'],
                'bytes_recv': current_network['bytes_recv'] - self.network_baseline['bytes_recv']
            }
            self.network_baseline = current_network
            
            metrics = SystemMetrics(
                timestamp=datetime.utcnow().isoformat(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=round(memory.used / 1024 / 1024, 2),
                memory_available_mb=round(memory.available / 1024 / 1024, 2),
                disk_usage_percent=disk.percent,
                network_bytes_sent=network_delta['bytes_sent'],
                network_bytes_recv=network_delta['bytes_recv']
            )
            
            with self.lock:
                self.system_metrics_history.append(metrics)
            
            return metrics
            
        except Exception as e:
            print(f"Error collecting system metrics: {e}")
            return None
    
    def collect_app_metrics(self, **kwargs) -> ApplicationMetrics:
        """Collect current application metrics"""
        metrics = ApplicationMetrics(
            timestamp=datetime.utcnow().isoformat(),
            events_processed=kwargs.get('events_processed', 0),
            alerts_generated=kwargs.get('alerts_generated', 0),
            ml_predictions=kwargs.get('ml_predictions', 0),
            collection_time_ms=kwargs.get('collection_time_ms', 0.0),
            analysis_time_ms=kwargs.get('analysis_time_ms', 0.0),
            backend_send_time_ms=kwargs.get('backend_send_time_ms', 0.0),
            error_count=kwargs.get('error_count', 0)
        )
        
        with self.lock:
            self.app_metrics_history.append(metrics)
        
        return metrics
    
    def increment_counter(self, name: str, value: int = 1) -> None:
        """Increment a counter metric"""
        with self.lock:
            self.counters[name] += value
    
    def start_timer(self, name: str) -> None:
        """Start timing an operation"""
        self.timers[name] = time.time()
    
    def end_timer(self, name: str) -> Optional[float]:
        """End timing an operation and return duration"""
        if name in self.timers:
            duration = time.time() - self.timers[name]
            del self.timers[name]
            return duration
        return None
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get a summary of all metrics"""
        with self.lock:
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'system': self._get_system_summary(),
                'application': self._get_app_summary(),
                'counters': dict(self.counters),
                'active_timers': list(self.timers.keys())
            }
            return summary
    
    def _get_system_summary(self) -> Dict[str, Any]:
        """Get system metrics summary"""
        if not self.system_metrics_history:
            return {}
        
        recent_metrics = list(self.system_metrics_history)[-10:]  # Last 10 measurements
        
        return {
            'avg_cpu_percent': sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
            'avg_memory_percent': sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
            'current_memory_mb': recent_metrics[-1].memory_used_mb if recent_metrics else 0,
            'avg_disk_percent': sum(m.disk_usage_percent for m in recent_metrics) / len(recent_metrics),
            'total_network_bytes_sent': sum(m.network_bytes_sent for m in recent_metrics),
            'total_network_bytes_recv': sum(m.network_bytes_recv for m in recent_metrics)
        }
    
    def _get_app_summary(self) -> Dict[str, Any]:
        """Get application metrics summary"""
        if not self.app_metrics_history:
            return {}
        
        recent_metrics = list(self.app_metrics_history)[-10:]  # Last 10 measurements
        
        return {
            'total_events_processed': sum(m.events_processed for m in recent_metrics),
            'total_alerts_generated': sum(m.alerts_generated for m in recent_metrics),
            'total_ml_predictions': sum(m.ml_predictions for m in recent_metrics),
            'avg_collection_time_ms': sum(m.collection_time_ms for m in recent_metrics) / len(recent_metrics),
            'avg_analysis_time_ms': sum(m.analysis_time_ms for m in recent_metrics) / len(recent_metrics),
            'total_errors': sum(m.error_count for m in recent_metrics),
            'alert_rate': sum(m.alerts_generated for m in recent_metrics) / max(sum(m.events_processed for m in recent_metrics), 1)
        }
    
    def get_historical_data(self, hours: int = 1) -> Dict[str, List[Dict]]:
        """Get historical metrics data"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self.lock:
            system_data = [
                asdict(metric) for metric in self.system_metrics_history
                if datetime.fromisoformat(metric.timestamp) > cutoff_time
            ]
            
            app_data = [
                asdict(metric) for metric in self.app_metrics_history
                if datetime.fromisoformat(metric.timestamp) > cutoff_time
            ]
        
        return {
            'system_metrics': system_data,
            'app_metrics': app_data
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics"""
        with self.lock:
            self.system_metrics_history.clear()
            self.app_metrics_history.clear()
            self.counters.clear()
            self.timers.clear()


class MetricsReporter:
    """Reports metrics to various outputs"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
    
    def generate_text_report(self) -> str:
        """Generate a text-based metrics report"""
        summary = self.metrics_collector.get_metrics_summary()
        
        report = f"""
=== VPEW-AI Performance Report ===
Timestamp: {summary['timestamp']}

SYSTEM METRICS:
- CPU Usage: {summary['system'].get('avg_cpu_percent', 0):.1f}%
- Memory Usage: {summary['system'].get('avg_memory_percent', 0):.1f}% ({summary['system'].get('current_memory_mb', 0):.1f} MB)
- Disk Usage: {summary['system'].get('avg_disk_percent', 0):.1f}%
- Network Sent: {summary['system'].get('total_network_bytes_sent', 0)} bytes
- Network Received: {summary['system'].get('total_network_bytes_recv', 0)} bytes

APPLICATION METRICS:
- Events Processed: {summary['application'].get('total_events_processed', 0)}
- Alerts Generated: {summary['application'].get('total_alerts_generated', 0)}
- ML Predictions: {summary['application'].get('total_ml_predictions', 0)}
- Avg Collection Time: {summary['application'].get('avg_collection_time_ms', 0):.2f} ms
- Avg Analysis Time: {summary['application'].get('avg_analysis_time_ms', 0):.2f} ms
- Alert Rate: {summary['application'].get('alert_rate', 0):.2%}
- Total Errors: {summary['application'].get('total_errors', 0)}

COUNTERS:
{chr(10).join(f"- {name}: {value}" for name, value in summary['counters'].items())}

ACTIVE TIMERS:
{chr(10).join(f"- {name}" for name in summary['active_timers'])}
"""
        return report
    
    def generate_json_report(self) -> Dict[str, Any]:
        """Generate a JSON-based metrics report"""
        return self.metrics_collector.get_metrics_summary()
    
    def save_report_to_file(self, filename: str, format: str = 'json') -> None:
        """Save metrics report to file"""
        if format.lower() == 'json':
            import json
            report = self.generate_json_report()
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        else:
            report = self.generate_text_report()
            with open(filename, 'w') as f:
                f.write(report)


# Global metrics collector instance
_metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def get_metrics_reporter() -> MetricsReporter:
    """Get metrics reporter instance"""
    return MetricsReporter(get_metrics_collector())
