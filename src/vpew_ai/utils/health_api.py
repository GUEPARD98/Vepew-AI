"""
Health Check API for VPEW-AI
Provides HTTP endpoints for external monitoring and health checks
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socket

logger = logging.getLogger(__name__)

class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health check endpoints"""
    
    def __init__(self, agent_instance, *args, **kwargs):
        self.agent = agent_instance
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_path = urlparse(self.path)
            endpoint = parsed_path.path
            query_params = parse_qs(parsed_path.query)
            
            if endpoint == '/health':
                self._handle_health_check(query_params)
            elif endpoint == '/health/detailed':
                self._handle_detailed_health(query_params)
            elif endpoint == '/health/metrics':
                self._handle_metrics(query_params)
            elif endpoint == '/health/status':
                self._handle_status(query_params)
            elif endpoint == '/health/backup':
                self._handle_backup_status(query_params)
            else:
                self._send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self._send_error(500, f"Internal server error: {str(e)}")
    
    def _handle_health_check(self, query_params: Dict[str, list]):
        """Handle basic health check"""
        try:
            # Basic health status
            is_healthy = True
            status_code = 200
            issues = []
            
            # Check agent status
            if not self.agent or not hasattr(self.agent, 'running') or not self.agent.running:
                is_healthy = False
                status_code = 503
                issues.append("Agent not running")
            
            # Check ML models
            if hasattr(self.agent, 'anomaly_detector') and hasattr(self.agent, 'threat_classifier'):
                if not (self.agent.anomaly_detector.is_loaded and self.agent.threat_classifier.is_loaded):
                    is_healthy = False
                    status_code = 503
                    issues.append("ML models not loaded")
            
            # Check collectors
            if hasattr(self.agent, 'collectors') and not self.agent.collectors:
                is_healthy = False
                status_code = 503
                issues.append("No collectors active")
            
            response = {
                "status": "healthy" if is_healthy else "unhealthy",
                "timestamp": datetime.now().isoformat(),
                "agent_version": "0.1.0",
                "uptime_seconds": time.time() - getattr(self.agent, 'start_time', time.time()),
                "issues": issues
            }
            
            self._send_json_response(response, status_code)
            
        except Exception as e:
            logger.error(f"Error in health check: {e}")
            self._send_error(500, f"Health check failed: {str(e)}")
    
    def _handle_detailed_health(self, query_params: Dict[str, list]):
        """Handle detailed health check"""
        try:
            detailed_info = {
                "timestamp": datetime.now().isoformat(),
                "agent_version": "0.1.0",
                "overall_status": "healthy",
                "components": {}
            }
            
            # Agent status
            detailed_info["components"]["agent"] = {
                "running": getattr(self.agent, 'running', False),
                "uptime_seconds": time.time() - getattr(self.agent, 'start_time', time.time()),
                "status": "running" if getattr(self.agent, 'running', False) else "stopped"
            }
            
            # ML Models
            if hasattr(self.agent, 'anomaly_detector') and hasattr(self.agent, 'threat_classifier'):
                detailed_info["components"]["ml_models"] = {
                    "anomaly_detector_loaded": self.agent.anomaly_detector.is_loaded,
                    "threat_classifier_loaded": self.agent.threat_classifier.is_loaded,
                    "status": "loaded" if (self.agent.anomaly_detector.is_loaded and self.agent.threat_classifier.is_loaded) else "not_loaded"
                }
            
            # Collectors
            if hasattr(self.agent, 'collectors'):
                collector_status = {}
                for name, collector in self.agent.collectors.items():
                    collector_status[name] = {
                        "active": collector is not None,
                        "type": type(collector).__name__ if collector else "None"
                    }
                detailed_info["components"]["collectors"] = collector_status
            
            # Health Monitor
            if hasattr(self.agent, 'health_monitor') and self.agent.health_monitor:
                try:
                    health_summary = self.agent.health_monitor.get_health_summary()
                    detailed_info["components"]["health_monitor"] = health_summary
                except Exception as e:
                    detailed_info["components"]["health_monitor"] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Event Filter
            if hasattr(self.agent, 'event_filter') and self.agent.event_filter:
                try:
                    filter_stats = self.agent.event_filter.get_statistics()
                    detailed_info["components"]["event_filter"] = filter_stats
                except Exception as e:
                    detailed_info["components"]["event_filter"] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Alert Prioritizer
            if hasattr(self.agent, 'alert_prioritizer') and self.agent.alert_prioritizer:
                try:
                    prioritizer_stats = self.agent.alert_prioritizer.get_statistics()
                    detailed_info["components"]["alert_prioritizer"] = prioritizer_stats
                except Exception as e:
                    detailed_info["components"]["alert_prioritizer"] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Backup System
            if hasattr(self.agent, 'backup_manager') and self.agent.backup_manager:
                try:
                    backup_stats = self.agent.backup_manager.get_statistics()
                    detailed_info["components"]["backup_system"] = backup_stats
                except Exception as e:
                    detailed_info["components"]["backup_system"] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            self._send_json_response(detailed_info, 200)
            
        except Exception as e:
            logger.error(f"Error in detailed health check: {e}")
            self._send_error(500, f"Detailed health check failed: {str(e)}")
    
    def _handle_metrics(self, query_params: Dict[str, list]):
        """Handle metrics endpoint"""
        try:
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "system_metrics": {},
                "application_metrics": {}
            }
            
            # System metrics
            if hasattr(self.agent, 'metrics_collector') and self.agent.metrics_collector:
                try:
                    all_metrics = self.agent.metrics_collector.get_all_metrics()
                    metrics["system_metrics"] = all_metrics.get("system", {})
                    metrics["application_metrics"] = all_metrics.get("application", {})
                    metrics["counters"] = all_metrics.get("counters", {})
                except Exception as e:
                    metrics["system_metrics"] = {"error": str(e)}
            
            self._send_json_response(metrics, 200)
            
        except Exception as e:
            logger.error(f"Error in metrics endpoint: {e}")
            self._send_error(500, f"Metrics endpoint failed: {str(e)}")
    
    def _handle_status(self, query_params: Dict[str, list]):
        """Handle status endpoint"""
        try:
            status = {
                "timestamp": datetime.now().isoformat(),
                "agent_status": "running" if getattr(self.agent, 'running', False) else "stopped",
                "version": "0.1.0",
                "endpoint_id": getattr(self.agent.config, 'endpoint_id', 'unknown') if hasattr(self.agent, 'config') else 'unknown',
                "collection_interval": getattr(self.agent.config, 'collection_interval', 0) if hasattr(self.agent, 'config') else 0,
                "ml_threshold": getattr(self.agent.config, 'ml_threshold', 0.0) if hasattr(self.agent, 'config') else 0.0,
                "backend_enabled": getattr(self.agent.config, 'backend_enabled', False) if hasattr(self.agent, 'config') else False
            }
            
            self._send_json_response(status, 200)
            
        except Exception as e:
            logger.error(f"Error in status endpoint: {e}")
            self._send_error(500, f"Status endpoint failed: {str(e)}")
    
    def _handle_backup_status(self, query_params: Dict[str, list]):
        """Handle backup status endpoint"""
        try:
            backup_status = {
                "timestamp": datetime.now().isoformat(),
                "backup_system_available": hasattr(self.agent, 'backup_manager') and self.agent.backup_manager is not None,
                "statistics": {}
            }
            
            if backup_status["backup_system_available"]:
                try:
                    backup_status["statistics"] = self.agent.backup_manager.get_statistics()
                except Exception as e:
                    backup_status["statistics"] = {"error": str(e)}
            
            self._send_json_response(backup_status, 200)
            
        except Exception as e:
            logger.error(f"Error in backup status endpoint: {e}")
            self._send_error(500, f"Backup status endpoint failed: {str(e)}")
    
    def _send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        """Send JSON response"""
        try:
            json_data = json.dumps(data, indent=2, default=str)
            
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            
            self.wfile.write(json_data.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error sending JSON response: {e}")
    
    def _send_error(self, status_code: int, message: str):
        """Send error response"""
        try:
            error_response = {
                "error": message,
                "status_code": status_code,
                "timestamp": datetime.now().isoformat()
            }
            self._send_json_response(error_response, status_code)
        except Exception as e:
            logger.error(f"Error sending error response: {e}")
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def log_message(self, format, *args):
        """Override to reduce HTTP server logging"""
        logger.debug(f"HTTP: {format % args}")

class HealthAPIServer:
    """Health Check API Server"""
    
    def __init__(self, agent_instance, host: str = "localhost", port: int = 8080):
        self.agent = agent_instance
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False
        
        logger.info(f"Health API Server initialized on {host}:{port}")
    
    def start(self):
        """Start the health check server"""
        try:
            if self.running:
                logger.warning("Health API server already running")
                return
            
            # Create handler with agent instance
            def handler_factory(*args, **kwargs):
                return HealthCheckHandler(self.agent, *args, **kwargs)
            
            # Create server
            self.server = HTTPServer((self.host, self.port), handler_factory)
            
            # Start server in separate thread
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            self.running = True
            logger.info(f"Health API server started on http://{self.host}:{self.port}")
            
            # Log available endpoints
            logger.info("Available endpoints:")
            logger.info(f"  GET /health - Basic health check")
            logger.info(f"  GET /health/detailed - Detailed health information")
            logger.info(f"  GET /health/metrics - System and application metrics")
            logger.info(f"  GET /health/status - Agent status information")
            logger.info(f"  GET /health/backup - Backup system status")
            
        except Exception as e:
            logger.error(f"Failed to start health API server: {e}")
            raise
    
    def stop(self):
        """Stop the health check server"""
        try:
            if not self.running:
                logger.warning("Health API server not running")
                return
            
            self.running = False
            
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                logger.info("Health API server stopped")
            
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=5)
            
        except Exception as e:
            logger.error(f"Error stopping health API server: {e}")
    
    def _run_server(self):
        """Run the HTTP server"""
        try:
            self.server.serve_forever()
        except Exception as e:
            if self.running:  # Only log if we're supposed to be running
                logger.error(f"Health API server error: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get server status"""
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "url": f"http://{self.host}:{self.port}",
            "endpoints": [
                "/health",
                "/health/detailed", 
                "/health/metrics",
                "/health/status",
                "/health/backup"
            ]
        }
    
    def is_port_available(self) -> bool:
        """Check if the port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                return True
        except OSError:
            return False

def get_health_api_server(agent_instance, host: str = "localhost", port: int = 8080) -> HealthAPIServer:
    """Get health API server instance"""
    return HealthAPIServer(agent_instance, host, port)
