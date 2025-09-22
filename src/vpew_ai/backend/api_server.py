#!/usr/bin/env python3
"""
VPEW-AI Backend API Server
Central processing server for VPEW-AI sensor data
"""

import logging
import json
import time
from typing import Dict, List, Optional
from pathlib import Path
from flask import Flask, request, jsonify
from werkzeug.serving import WSGIRequestHandler
import ssl

logger = logging.getLogger(__name__)

class APIServer:
    """
    Backend API server for VPEW-AI
    
    Provides REST API endpoints for:
    - Event ingestion from sensors
    - Alert management
    - Configuration distribution
    - Health monitoring
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443):
        """
        Initialize API server
        
        Args:
            host: Server host address
            port: Server port
        """
        self.host = host
        self.port = port
        
        # Flask application
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'vpew-ai-secret-key'
        
        # Data storage (in production, would use proper database)
        self.events_storage = []
        self.alerts_storage = []
        self.agents_registry = {}
        
        # Setup routes
        self._setup_routes()
        
        logger.info(f"API server initialized on {host}:{port}")
    
    def _setup_routes(self) -> None:
        """Setup Flask routes"""
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': time.time(),
                'version': '0.1.0',
                'service': 'vpew-ai-backend'
            })
        
        @self.app.route('/api/v1/events', methods=['POST'])
        def ingest_events():
            """Ingest events from sensors"""
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({'error': 'No data provided'}), 400
                
                # Validate required fields
                required_fields = ['endpoint_id', 'timestamp', 'events']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'Missing field: {field}'}), 400
                
                # Store events
                endpoint_id = data['endpoint_id']
                events = data['events']
                alerts = data.get('alerts', [])
                
                # Update agent registry
                self.agents_registry[endpoint_id] = {
                    'last_seen': time.time(),
                    'agent_version': data.get('agent_version', 'unknown'),
                    'events_count': len(events),
                    'alerts_count': len(alerts)
                }
                
                # Store events and alerts
                for event in events:
                    event['received_timestamp'] = time.time()
                    self.events_storage.append(event)
                
                for alert in alerts:
                    alert['received_timestamp'] = time.time()
                    alert['endpoint_id'] = endpoint_id
                    self.alerts_storage.append(alert)
                
                logger.info(f"Received {len(events)} events and {len(alerts)} alerts from {endpoint_id}")
                
                return jsonify({
                    'status': 'success',
                    'events_received': len(events),
                    'alerts_received': len(alerts),
                    'timestamp': time.time()
                })
                
            except Exception as e:
                logger.error(f"Error ingesting events: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/api/v1/alerts', methods=['GET'])
        def get_alerts():
            """Get recent alerts"""
            try:
                limit = request.args.get('limit', 100, type=int)
                severity = request.args.get('severity')
                endpoint_id = request.args.get('endpoint_id')
                
                # Filter alerts
                filtered_alerts = self.alerts_storage
                
                if severity:
                    filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity]
                
                if endpoint_id:
                    filtered_alerts = [a for a in filtered_alerts if a.get('endpoint_id') == endpoint_id]
                
                # Sort by timestamp (newest first) and limit
                filtered_alerts = sorted(filtered_alerts, key=lambda x: x.get('received_timestamp', 0), reverse=True)
                filtered_alerts = filtered_alerts[:limit]
                
                return jsonify({
                    'alerts': filtered_alerts,
                    'total_count': len(self.alerts_storage),
                    'filtered_count': len(filtered_alerts)
                })
                
            except Exception as e:
                logger.error(f"Error getting alerts: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/api/v1/agents', methods=['GET'])
        def get_agents():
            """Get registered agents status"""
            try:
                current_time = time.time()
                agents_status = {}
                
                for endpoint_id, info in self.agents_registry.items():
                    last_seen = info['last_seen']
                    time_diff = current_time - last_seen
                    
                    # Determine status
                    if time_diff < 60:
                        status = 'online'
                    elif time_diff < 300:
                        status = 'warning'
                    else:
                        status = 'offline'
                    
                    agents_status[endpoint_id] = {
                        'status': status,
                        'last_seen': last_seen,
                        'time_since_last_seen': time_diff,
                        'agent_version': info.get('agent_version'),
                        'events_count': info.get('events_count', 0),
                        'alerts_count': info.get('alerts_count', 0)
                    }
                
                return jsonify({
                    'agents': agents_status,
                    'total_agents': len(agents_status)
                })
                
            except Exception as e:
                logger.error(f"Error getting agents: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/api/v1/stats', methods=['GET'])
        def get_stats():
            """Get system statistics"""
            try:
                current_time = time.time()
                
                # Calculate statistics
                total_events = len(self.events_storage)
                total_alerts = len(self.alerts_storage)
                
                # Recent activity (last hour)
                hour_ago = current_time - 3600
                recent_events = len([e for e in self.events_storage if e.get('received_timestamp', 0) > hour_ago])
                recent_alerts = len([a for a in self.alerts_storage if a.get('received_timestamp', 0) > hour_ago])
                
                # Alert severity distribution
                severity_counts = {}
                for alert in self.alerts_storage:
                    severity = alert.get('severity', 'unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                return jsonify({
                    'total_events': total_events,
                    'total_alerts': total_alerts,
                    'recent_events_1h': recent_events,
                    'recent_alerts_1h': recent_alerts,
                    'alert_severity_distribution': severity_counts,
                    'active_agents': len(self.agents_registry),
                    'timestamp': current_time
                })
                
            except Exception as e:
                logger.error(f"Error getting stats: {e}")
                return jsonify({'error': 'Internal server error'}), 500
    
    def run(self, ssl_cert_path: str = None, ssl_key_path: str = None, debug: bool = False) -> None:
        """
        Start the API server
        
        Args:
            ssl_cert_path: Path to SSL certificate
            ssl_key_path: Path to SSL private key
            debug: Enable debug mode
        """
        try:
            # Configure SSL context
            ssl_context = None
            if ssl_cert_path and ssl_key_path:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_cert_chain(ssl_cert_path, ssl_key_path)
                logger.info("SSL enabled")
            else:
                logger.warning("Running without SSL - not recommended for production")
            
            logger.info(f"Starting API server on {self.host}:{self.port}")
            
            # Start server
            self.app.run(
                host=self.host,
                port=self.port,
                ssl_context=ssl_context,
                debug=debug,
                threaded=True
            )
            
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            raise

def main():
    """Main entry point for API server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='VPEW-AI Backend API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Server host')
    parser.add_argument('--port', type=int, default=8443, help='Server port')
    parser.add_argument('--ssl-cert', help='SSL certificate path')
    parser.add_argument('--ssl-key', help='SSL private key path')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Initialize and start server
    server = APIServer(host=args.host, port=args.port)
    server.run(
        ssl_cert_path=args.ssl_cert,
        ssl_key_path=args.ssl_key,
        debug=args.debug
    )

if __name__ == "__main__":
    main()
