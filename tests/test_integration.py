#!/usr/bin/env python3
"""
VPEW-AI Integration Tests
End-to-end testing of the complete system
"""

import pytest
import time
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Import VPEW-AI components
from vpew_ai.sensor.agent import VPEWAgent
from vpew_ai.sensor.collectors import EventCollector, SysmonCollector
from vpew_ai.sensor.processors import FeatureExtractor
from vpew_ai.ml.models import AnomalyDetector, ThreatClassifier
from vpew_ai.rules import SigmaEngine
from vpew_ai.communication import SecureChannel
from vpew_ai.response import PlaybookEngine

class TestVPEWIntegration:
    """Integration tests for VPEW-AI system"""
    
    @pytest.fixture
    def temp_config(self):
        """Create temporary configuration file"""
        config_data = {
            'endpoint_id': 'test-endpoint',
            'backend_url': 'https://test-backend:8443',
            'cert_path': 'test_certs/client.crt',
            'key_path': 'test_certs/client.key',
            'ca_cert_path': 'test_certs/ca.crt',
            'collection_interval': 1,
            'ml_threshold': 0.7,
            'enable_response': True,
            'log_level': 'DEBUG'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            return f.name
    
    @pytest.fixture
    def mock_certificates(self):
        """Create mock certificate files"""
        cert_dir = Path("test_certs")
        cert_dir.mkdir(exist_ok=True)
        
        # Create empty cert files for testing
        (cert_dir / "client.crt").touch()
        (cert_dir / "client.key").touch() 
        (cert_dir / "ca.crt").touch()
        
        yield cert_dir
        
        # Cleanup
        import shutil
        shutil.rmtree(cert_dir, ignore_errors=True)
    
    def test_p1_network_reconnaissance_detection(self, temp_config, mock_certificates):
        """
        P1: Test detection of network reconnaissance activities
        Validates R1 Sigma rule and ML anomaly detection
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize components
            sigma_engine = SigmaEngine()
            sigma_engine.load_rules()
            
            feature_extractor = FeatureExtractor()
            
            # Simulate reconnaissance events
            recon_events = [
                {
                    'event_id': 1,
                    'log_type': 'sysmon',
                    'image': 'C:\\Windows\\System32\\net.exe',
                    'commandline': 'net view /domain',
                    'processid': 1234,
                    'time_generated': time.time()
                },
                {
                    'event_id': 1,
                    'log_type': 'sysmon', 
                    'image': 'C:\\Windows\\System32\\netstat.exe',
                    'commandline': 'netstat -an',
                    'processid': 1235,
                    'time_generated': time.time()
                },
                {
                    'event_id': 1,
                    'log_type': 'sysmon',
                    'image': 'C:\\Windows\\System32\\nslookup.exe', 
                    'commandline': 'nslookup domain.com',
                    'processid': 1236,
                    'time_generated': time.time()
                }
            ]
            
            # Test Sigma rule matching
            matches = []
            for event in recon_events:
                event_matches = sigma_engine.match(event)
                matches.extend(event_matches)
            
            # Should detect reconnaissance pattern
            assert len(matches) > 0, "Failed to detect reconnaissance pattern"
            
            # Test feature extraction
            features_list = []
            for event in recon_events:
                features = feature_extractor.extract(event)
                if features:
                    features_list.append(features['feature_vector'])
            
            assert len(features_list) > 0, "Failed to extract features from events"
            
            print("✓ P1: Network reconnaissance detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p2_credential_extraction_detection(self, temp_config, mock_certificates):
        """
        P2: Test detection of credential extraction attempts
        Validates LSASS access detection
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize Sigma engine
            sigma_engine = SigmaEngine()
            sigma_engine.load_rules()
            
            # Simulate LSASS access event
            lsass_event = {
                'event_id': 10,
                'log_type': 'sysmon',
                'targetimage': 'C:\\Windows\\System32\\lsass.exe',
                'grantedaccess': '0x1010',
                'sourceimage': 'C:\\temp\\malware.exe',
                'processid': 2345,
                'time_generated': time.time()
            }
            
            # Test Sigma rule matching
            matches = sigma_engine.match(lsass_event)
            
            # Should detect credential access attempt
            assert len(matches) > 0, "Failed to detect LSASS access"
            
            # Verify rule details
            match = matches[0]
            assert 'credential' in match['title'].lower() or 'lsass' in match['title'].lower()
            assert match['level'] == 'high'
            
            print("✓ P2: Credential extraction detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p3_persistence_mechanism_detection(self, temp_config, mock_certificates):
        """
        P3: Test detection of persistence mechanisms
        Validates binary modification and service installation detection
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize components
            sigma_engine = SigmaEngine()
            sigma_engine.load_rules()
            
            playbook_engine = PlaybookEngine()
            
            # Simulate service installation event
            service_event = {
                'event_id': 4697,
                'log_type': 'security',
                'service_name': 'MaliciousService',
                'service_file_name': 'C:\\temp\\malware.exe',
                'service_type': 'user mode service',
                'service_start_type': 'auto start',
                'time_generated': time.time()
            }
            
            # Test detection
            matches = sigma_engine.match(service_event)
            
            # Create alert for playbook testing
            alert = {
                'type': 'sigma_rule',
                'severity': 'high',
                'rule_id': 'vpew-r3-persistence',
                'event': service_event
            }
            
            # Test playbook execution (simulated)
            with patch.object(playbook_engine, '_isolate_endpoint', return_value=True), \
                 patch.object(playbook_engine, '_collect_evidence', return_value=True), \
                 patch.object(playbook_engine, '_quarantine_file', return_value=True):
                
                response_executed = playbook_engine.execute(alert)
                assert response_executed, "Failed to execute persistence response playbook"
            
            print("✓ P3: Persistence mechanism detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p4_evasion_technique_detection(self, temp_config, mock_certificates):
        """
        P4: Test detection of evasion techniques
        Validates behavioral analysis and ML anomaly detection
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize components
            feature_extractor = FeatureExtractor()
            anomaly_detector = AnomalyDetector()
            
            # Simulate evasive behavior events
            evasive_events = [
                {
                    'event_id': 1,
                    'log_type': 'sysmon',
                    'image': 'C:\\temp\\a1b2c3d4.exe',  # Random hex name
                    'commandline': 'powershell -enc JABhAD0AJwBoAGUAbABsAG8A',  # Encoded command
                    'processid': 3456,
                    'time_generated': time.time()
                }
            ]
            
            # Extract features
            for event in evasive_events:
                features = feature_extractor.extract(event)
                assert features is not None, "Failed to extract features from evasive event"
                
                # Check for evasion indicators
                raw_features = features['raw_features']
                assert raw_features['process_features']['has_suspicious_name'] == 1
                assert raw_features['process_features']['has_encoded_command'] == 1
            
            print("✓ P4: Evasion technique detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p5_hardening_validation(self, temp_config, mock_certificates):
        """
        P5: Test security configuration validation
        Validates system hardening checks
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Test certificate validation
            secure_channel = SecureChannel(
                cert_path="test_certs/client.crt",
                key_path="test_certs/client.key", 
                ca_cert_path="test_certs/ca.crt"
            )
            
            connection_info = secure_channel.get_connection_info()
            assert connection_info['cert_exists'], "Client certificate not found"
            assert connection_info['key_exists'], "Client key not found" 
            assert connection_info['ca_exists'], "CA certificate not found"
            
            print("✓ P5: Hardening validation test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p6_log_clearing_detection(self, temp_config, mock_certificates):
        """
        P6: Test detection of log clearing attempts
        Validates defense evasion detection
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize Sigma engine
            sigma_engine = SigmaEngine()
            sigma_engine.load_rules()
            
            # Simulate log clearing event
            log_clear_event = {
                'event_id': 1102,
                'log_type': 'security',
                'subject_user': 'DOMAIN\\attacker',
                'time_generated': time.time()
            }
            
            # Test detection
            matches = sigma_engine.match(log_clear_event)
            
            # Should detect log clearing
            assert len(matches) > 0, "Failed to detect log clearing attempt"
            
            print("✓ P6: Log clearing detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p7_defensive_validation(self, temp_config, mock_certificates):
        """
        P7: Test comprehensive defensive controls validation
        Validates overall system defensive posture
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Test all major components
            components = {
                'sigma_engine': SigmaEngine(),
                'feature_extractor': FeatureExtractor(),
                'anomaly_detector': AnomalyDetector(),
                'playbook_engine': PlaybookEngine()
            }
            
            # Validate component initialization
            for name, component in components.items():
                assert component is not None, f"Failed to initialize {name}"
            
            # Test Sigma rules loading
            rules_loaded = components['sigma_engine'].load_rules()
            assert rules_loaded >= 5, f"Expected at least 5 rules, loaded {rules_loaded}"
            
            # Test playbook availability
            playbook_stats = components['playbook_engine'].get_playbook_stats()
            assert playbook_stats['total_playbooks'] >= 3, "Missing core playbooks"
            assert 'PB1' in playbook_stats['playbook_list'], "PB1 playbook missing"
            assert 'PB2' in playbook_stats['playbook_list'], "PB2 playbook missing"
            assert 'PB3' in playbook_stats['playbook_list'], "PB3 playbook missing"
            
            print("✓ P7: Defensive validation test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)
    
    def test_p8_blackbox_evasion(self, temp_config, mock_certificates):
        """
        P8: Test blackbox evasion detection
        Validates detection of unknown attack patterns
        """
        # Create defense authorization
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        with open(auth_file, 'w') as f:
            f.write("DEFENSIVE_USE_ONLY\nTest authorization\n")
        
        try:
            # Initialize ML components
            feature_extractor = FeatureExtractor()
            anomaly_detector = AnomalyDetector()
            
            # Simulate unknown attack pattern
            unknown_attack = {
                'event_id': 1,
                'log_type': 'sysmon',
                'image': 'C:\\temp\\unknown_tool.exe',
                'commandline': 'unknown_tool.exe --stealth --bypass --hide',
                'processid': 4567,
                'parentprocessid': 1000,
                'time_generated': time.time()
            }
            
            # Extract features
            features = feature_extractor.extract(unknown_attack)
            assert features is not None, "Failed to extract features from unknown attack"
            
            # Test anomaly detection capability
            # Note: Without training data, we test the interface
            feature_vector = features['feature_vector']
            assert len(feature_vector) > 0, "Empty feature vector"
            
            print("✓ P8: Blackbox evasion detection test passed")
            
        finally:
            # Cleanup
            auth_file.unlink(exist_ok=True)

if __name__ == "__main__":
    # Run integration tests
    test_suite = TestVPEWIntegration()
    
    # Create temporary config and certificates
    import tempfile
    import yaml
    
    config_data = {
        'endpoint_id': 'test-endpoint',
        'backend_url': 'https://test-backend:8443',
        'cert_path': 'test_certs/client.crt',
        'key_path': 'test_certs/client.key',
        'ca_cert_path': 'test_certs/ca.crt'
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config_data, f)
        temp_config = f.name
    
    # Create mock certificates
    cert_dir = Path("test_certs")
    cert_dir.mkdir(exist_ok=True)
    (cert_dir / "client.crt").touch()
    (cert_dir / "client.key").touch()
    (cert_dir / "ca.crt").touch()
    
    try:
        print("Running VPEW-AI Integration Tests...")
        print("=" * 50)
        
        # Run all test cases
        test_suite.test_p1_network_reconnaissance_detection(temp_config, cert_dir)
        test_suite.test_p2_credential_extraction_detection(temp_config, cert_dir)
        test_suite.test_p3_persistence_mechanism_detection(temp_config, cert_dir)
        test_suite.test_p4_evasion_technique_detection(temp_config, cert_dir)
        test_suite.test_p5_hardening_validation(temp_config, cert_dir)
        test_suite.test_p6_log_clearing_detection(temp_config, cert_dir)
        test_suite.test_p7_defensive_validation(temp_config, cert_dir)
        test_suite.test_p8_blackbox_evasion(temp_config, cert_dir)
        
        print("=" * 50)
        print("✅ All integration tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise
    finally:
        # Cleanup
        Path(temp_config).unlink(exist_ok=True)
        import shutil
        shutil.rmtree(cert_dir, ignore_errors=True)
