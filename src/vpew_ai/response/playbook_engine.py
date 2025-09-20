#!/usr/bin/env python3
"""
Playbook Engine
Automated incident response execution based on detected threats
"""

import logging
import time
import subprocess
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ResponseAction(Enum):
    """Types of response actions"""
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_PROCESS = "block_process" 
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_SOC = "notify_soc"
    CREATE_TICKET = "create_ticket"

@dataclass
class PlaybookStep:
    """Individual step in a response playbook"""
    action: ResponseAction
    parameters: Dict[str, Any]
    timeout: int = 30
    retry_count: int = 3
    critical: bool = False

@dataclass 
class Playbook:
    """Response playbook definition"""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    steps: List[PlaybookStep]
    approval_required: bool = False

class PlaybookEngine:
    """
    Automated incident response engine
    
    Executes predefined playbooks based on alert types and severity
    Implements the three core VPEW-AI playbooks:
    - PB1: Binary integrity violation response
    - PB2: Credential extraction response  
    - PB3: Reconnaissance anomaly response
    """
    
    def __init__(self):
        """Initialize playbook engine"""
        self.playbooks: Dict[str, Playbook] = {}
        self.execution_log: List[Dict] = []
        self.enabled = True
        
        # Initialize core playbooks
        self._initialize_core_playbooks()
        
        logger.info("Playbook engine initialized")
    
    def _initialize_core_playbooks(self) -> None:
        """Initialize the three core VPEW-AI response playbooks"""
        
        # PB1: Binary Integrity Violation Response
        pb1_steps = [
            PlaybookStep(
                action=ResponseAction.ISOLATE_ENDPOINT,
                parameters={"method": "network", "duration": 3600},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.COLLECT_EVIDENCE,
                parameters={"type": "memory_dump", "preserve": True},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.QUARANTINE_FILE,
                parameters={"action": "move_to_quarantine"},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.NOTIFY_SOC,
                parameters={"priority": "high", "escalate": True}
            ),
            PlaybookStep(
                action=ResponseAction.CREATE_TICKET,
                parameters={"category": "malware", "severity": "high"}
            )
        ]
        
        pb1 = Playbook(
            id="PB1",
            name="Binary Integrity Violation Response",
            description="Response to compromised system binaries",
            trigger_conditions={"rule_id": "vpew-r3-persistence"},
            steps=pb1_steps,
            approval_required=True
        )
        
        # PB2: Credential Extraction Response
        pb2_steps = [
            PlaybookStep(
                action=ResponseAction.BLOCK_PROCESS,
                parameters={"terminate": True, "block_hash": True},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.DISABLE_USER,
                parameters={"scope": "affected_accounts"},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.RESET_PASSWORD,
                parameters={"force_change": True, "invalidate_tokens": True},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.COLLECT_EVIDENCE,
                parameters={"type": "process_memory", "lsass_focus": True},
                critical=True
            ),
            PlaybookStep(
                action=ResponseAction.NOTIFY_SOC,
                parameters={"priority": "critical", "immediate": True}
            )
        ]
        
        pb2 = Playbook(
            id="PB2", 
            name="Credential Extraction Response",
            description="Response to credential dumping attempts",
            trigger_conditions={"rule_id": "vpew-r2-credential-access"},
            steps=pb2_steps,
            approval_required=False  # Immediate response required
        )
        
        # PB3: Reconnaissance Anomaly Response
        pb3_steps = [
            PlaybookStep(
                action=ResponseAction.COLLECT_EVIDENCE,
                parameters={"type": "network_traffic", "duration": 300}
            ),
            PlaybookStep(
                action=ResponseAction.BLOCK_PROCESS,
                parameters={"suspend": True, "analyze": True}
            ),
            PlaybookStep(
                action=ResponseAction.NOTIFY_SOC,
                parameters={"priority": "medium", "threat_hunting": True}
            ),
            PlaybookStep(
                action=ResponseAction.CREATE_TICKET,
                parameters={"category": "reconnaissance", "severity": "medium"}
            )
        ]
        
        pb3 = Playbook(
            id="PB3",
            name="Reconnaissance Anomaly Response", 
            description="Response to network reconnaissance activities",
            trigger_conditions={"rule_id": "vpew-r1-reconnaissance"},
            steps=pb3_steps,
            approval_required=False
        )
        
        # Register playbooks
        self.playbooks["PB1"] = pb1
        self.playbooks["PB2"] = pb2
        self.playbooks["PB3"] = pb3
        
        logger.info("Core playbooks initialized: PB1, PB2, PB3")
    
    def execute(self, alert: Dict) -> bool:
        """
        Execute appropriate playbook based on alert
        
        Args:
            alert: Alert dictionary containing threat information
            
        Returns:
            True if playbook executed successfully, False otherwise
        """
        try:
            # Find matching playbook
            playbook = self._find_matching_playbook(alert)
            if not playbook:
                logger.warning(f"No matching playbook for alert: {alert.get('type', 'unknown')}")
                return False
            
            # Check if engine is enabled
            if not self.enabled:
                logger.info("Playbook engine disabled, skipping execution")
                return False
            
            # Execute playbook
            return self._execute_playbook(playbook, alert)
            
        except Exception as e:
            logger.error(f"Error executing playbook: {e}")
            return False
    
    def _find_matching_playbook(self, alert: Dict) -> Optional[Playbook]:
        """
        Find playbook that matches alert conditions
        
        Args:
            alert: Alert to match against
            
        Returns:
            Matching playbook or None
        """
        try:
            # Check rule-based matching first
            rule_id = alert.get('rule_id')
            if rule_id:
                for playbook in self.playbooks.values():
                    trigger_rule = playbook.trigger_conditions.get('rule_id')
                    if trigger_rule == rule_id:
                        return playbook
            
            # Check alert type matching
            alert_type = alert.get('type')
            if alert_type == 'ml_anomaly':
                # Use reconnaissance playbook for ML anomalies
                return self.playbooks.get('PB3')
            
            # Default based on severity
            severity = alert.get('severity', 'low')
            if severity == 'high':
                return self.playbooks.get('PB1')  # Most comprehensive response
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding matching playbook: {e}")
            return None
    
    def _execute_playbook(self, playbook: Playbook, alert: Dict) -> bool:
        """
        Execute a specific playbook
        
        Args:
            playbook: Playbook to execute
            alert: Alert that triggered the playbook
            
        Returns:
            True if execution successful, False otherwise
        """
        try:
            logger.info(f"Executing playbook: {playbook.name}")
            
            # Log execution start
            execution_record = {
                "playbook_id": playbook.id,
                "playbook_name": playbook.name,
                "alert": alert,
                "start_time": time.time(),
                "steps_executed": [],
                "success": False
            }
            
            # Check approval requirement
            if playbook.approval_required:
                if not self._request_approval(playbook, alert):
                    logger.info(f"Approval denied for playbook: {playbook.name}")
                    return False
            
            # Execute each step
            for i, step in enumerate(playbook.steps):
                try:
                    logger.info(f"Executing step {i+1}/{len(playbook.steps)}: {step.action.value}")
                    
                    success = self._execute_step(step, alert)
                    
                    step_record = {
                        "step_number": i + 1,
                        "action": step.action.value,
                        "parameters": step.parameters,
                        "success": success,
                        "timestamp": time.time()
                    }
                    execution_record["steps_executed"].append(step_record)
                    
                    if not success and step.critical:
                        logger.error(f"Critical step failed: {step.action.value}")
                        execution_record["error"] = f"Critical step {i+1} failed"
                        self.execution_log.append(execution_record)
                        return False
                    
                except Exception as e:
                    logger.error(f"Error executing step {i+1}: {e}")
                    if step.critical:
                        execution_record["error"] = str(e)
                        self.execution_log.append(execution_record)
                        return False
            
            # Mark execution as successful
            execution_record["success"] = True
            execution_record["end_time"] = time.time()
            execution_record["duration"] = execution_record["end_time"] - execution_record["start_time"]
            
            self.execution_log.append(execution_record)
            
            logger.info(f"Playbook {playbook.name} executed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error executing playbook {playbook.name}: {e}")
            return False
    
    def _execute_step(self, step: PlaybookStep, alert: Dict) -> bool:
        """
        Execute individual playbook step
        
        Args:
            step: Step to execute
            alert: Alert context
            
        Returns:
            True if step executed successfully, False otherwise
        """
        try:
            # Get endpoint information from alert
            endpoint_id = alert.get('event', {}).get('endpoint_id', 'unknown')
            
            # Execute based on action type
            if step.action == ResponseAction.ISOLATE_ENDPOINT:
                return self._isolate_endpoint(endpoint_id, step.parameters)
            
            elif step.action == ResponseAction.BLOCK_PROCESS:
                return self._block_process(alert, step.parameters)
            
            elif step.action == ResponseAction.QUARANTINE_FILE:
                return self._quarantine_file(alert, step.parameters)
            
            elif step.action == ResponseAction.DISABLE_USER:
                return self._disable_user(alert, step.parameters)
            
            elif step.action == ResponseAction.RESET_PASSWORD:
                return self._reset_password(alert, step.parameters)
            
            elif step.action == ResponseAction.COLLECT_EVIDENCE:
                return self._collect_evidence(alert, step.parameters)
            
            elif step.action == ResponseAction.NOTIFY_SOC:
                return self._notify_soc(alert, step.parameters)
            
            elif step.action == ResponseAction.CREATE_TICKET:
                return self._create_ticket(alert, step.parameters)
            
            else:
                logger.warning(f"Unknown action type: {step.action}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing step {step.action}: {e}")
            return False
    
    def _request_approval(self, playbook: Playbook, alert: Dict) -> bool:
        """
        Request approval for playbook execution
        
        Args:
            playbook: Playbook requiring approval
            alert: Alert context
            
        Returns:
            True if approved, False otherwise
        """
        # In production, this would integrate with approval workflow
        # For now, simulate approval based on severity
        severity = alert.get('severity', 'low')
        
        if severity in ['high', 'critical']:
            logger.info(f"Auto-approving {playbook.name} due to {severity} severity")
            return True
        
        logger.info(f"Approval required for {playbook.name} - simulating approval")
        return True  # Simulate approval for demo
    
    def _isolate_endpoint(self, endpoint_id: str, params: Dict) -> bool:
        """Isolate endpoint from network"""
        try:
            method = params.get('method', 'network')
            duration = params.get('duration', 3600)
            
            logger.info(f"Isolating endpoint {endpoint_id} using {method} for {duration}s")
            
            # In production, this would:
            # - Disable network adapters
            # - Apply firewall rules
            # - Notify network security appliances
            
            # Simulate isolation
            return True
            
        except Exception as e:
            logger.error(f"Error isolating endpoint: {e}")
            return False
    
    def _block_process(self, alert: Dict, params: Dict) -> bool:
        """Block or terminate malicious process"""
        try:
            process_id = alert.get('event', {}).get('processid')
            image_path = alert.get('event', {}).get('image')
            
            terminate = params.get('terminate', False)
            block_hash = params.get('block_hash', False)
            
            logger.info(f"Blocking process PID:{process_id} Image:{image_path}")
            
            if terminate and process_id:
                # Simulate process termination
                logger.info(f"Terminating process {process_id}")
            
            if block_hash and image_path:
                # Simulate hash-based blocking
                logger.info(f"Adding {image_path} to block list")
            
            return True
            
        except Exception as e:
            logger.error(f"Error blocking process: {e}")
            return False
    
    def _quarantine_file(self, alert: Dict, params: Dict) -> bool:
        """Quarantine malicious file"""
        try:
            file_path = alert.get('event', {}).get('targetfilename') or alert.get('event', {}).get('image')
            
            if not file_path:
                logger.warning("No file path found in alert")
                return False
            
            action = params.get('action', 'move_to_quarantine')
            
            logger.info(f"Quarantining file: {file_path}")
            
            # In production, this would move file to secure quarantine location
            # and update file reputation databases
            
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return False
    
    def _disable_user(self, alert: Dict, params: Dict) -> bool:
        """Disable compromised user account"""
        try:
            user = alert.get('event', {}).get('target_user') or alert.get('event', {}).get('user_name')
            
            if not user:
                logger.warning("No user found in alert")
                return False
            
            scope = params.get('scope', 'single_user')
            
            logger.info(f"Disabling user account: {user}")
            
            # In production, this would:
            # - Disable AD account
            # - Revoke active sessions
            # - Notify identity management system
            
            return True
            
        except Exception as e:
            logger.error(f"Error disabling user: {e}")
            return False
    
    def _reset_password(self, alert: Dict, params: Dict) -> bool:
        """Reset user password"""
        try:
            user = alert.get('event', {}).get('target_user') or alert.get('event', {}).get('user_name')
            
            if not user:
                logger.warning("No user found in alert")
                return False
            
            force_change = params.get('force_change', True)
            invalidate_tokens = params.get('invalidate_tokens', True)
            
            logger.info(f"Resetting password for user: {user}")
            
            # In production, this would integrate with identity management
            
            return True
            
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return False
    
    def _collect_evidence(self, alert: Dict, params: Dict) -> bool:
        """Collect forensic evidence"""
        try:
            evidence_type = params.get('type', 'basic')
            preserve = params.get('preserve', True)
            
            logger.info(f"Collecting evidence type: {evidence_type}")
            
            # In production, this would:
            # - Create memory dumps
            # - Collect process artifacts
            # - Preserve network traffic
            # - Generate forensic timeline
            
            return True
            
        except Exception as e:
            logger.error(f"Error collecting evidence: {e}")
            return False
    
    def _notify_soc(self, alert: Dict, params: Dict) -> bool:
        """Notify SOC team"""
        try:
            priority = params.get('priority', 'medium')
            escalate = params.get('escalate', False)
            
            logger.info(f"Notifying SOC - Priority: {priority}, Escalate: {escalate}")
            
            # In production, this would:
            # - Send email notifications
            # - Update SIEM dashboard
            # - Trigger pager/SMS for critical alerts
            # - Post to SOC chat channels
            
            return True
            
        except Exception as e:
            logger.error(f"Error notifying SOC: {e}")
            return False
    
    def _create_ticket(self, alert: Dict, params: Dict) -> bool:
        """Create incident ticket"""
        try:
            category = params.get('category', 'security')
            severity = params.get('severity', 'medium')
            
            logger.info(f"Creating ticket - Category: {category}, Severity: {severity}")
            
            # In production, this would integrate with ticketing system
            # (ServiceNow, Jira, etc.)
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating ticket: {e}")
            return False
    
    def get_execution_history(self, limit: int = 10) -> List[Dict]:
        """
        Get recent playbook execution history
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of execution records
        """
        return self.execution_log[-limit:]
    
    def get_playbook_stats(self) -> Dict:
        """
        Get playbook execution statistics
        
        Returns:
            Dictionary with execution statistics
        """
        total_executions = len(self.execution_log)
        successful_executions = sum(1 for record in self.execution_log if record.get('success'))
        
        stats = {
            "total_playbooks": len(self.playbooks),
            "total_executions": total_executions,
            "successful_executions": successful_executions,
            "success_rate": successful_executions / total_executions if total_executions > 0 else 0,
            "playbook_list": list(self.playbooks.keys()),
            "enabled": self.enabled
        }
        
        return stats
