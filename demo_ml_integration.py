#!/usr/bin/env python3
"""
Demo script showing VPEW-AI ML integration
Demonstrates threat detection with TensorFlow models
"""

import sys
import os
import time
import numpy as np
from pathlib import Path

# Add src to path
sys.path.append('src')

def main():
    print("🧠 VPEW-AI ML Integration Demo")
    print("=" * 50)
    
    # 1. Test ML Models Import
    print("\n1️⃣  Testing ML Models Import...")
    try:
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier, Trainer
        print("✅ ML models imported successfully")
    except Exception as e:
        print(f"❌ Failed to import ML models: {e}")
        return
    
    # 2. Test Model Instantiation
    print("\n2️⃣  Testing Model Instantiation...")
    try:
        detector = AnomalyDetector()
        classifier = ThreatClassifier()
        print(f"✅ Models instantiated (TensorFlow: {not detector._use_fallback})")
    except Exception as e:
        print(f"❌ Failed to instantiate models: {e}")
        return
    
    # 3. Test Training
    print("\n3️⃣  Testing Model Training...")
    try:
        trainer = Trainer("models")
        
        # Check if models already exist
        if Path("models/anomaly_detector.keras").exists():
            print("✅ Pre-trained models found")
            detector.load_model("models/anomaly_detector.keras")
            classifier.load_model("models/threat_classifier.keras")
        else:
            print("⏳ Training new models (this may take a minute)...")
            results = trainer.train_all_models(epochs=10)
            if all(results.values()):
                print("✅ Models trained successfully")
                detector = trainer.anomaly_detector
                classifier = trainer.threat_classifier
            else:
                print("❌ Training failed")
                return
    except Exception as e:
        print(f"❌ Training failed: {e}")
        return
    
    # 4. Test Threat Detection Scenarios
    print("\n4️⃣  Testing Threat Detection Scenarios...")
    
    test_scenarios = [
        {
            "name": "Normal Process",
            "features": [0.1] * 25,  # Low activity
            "expected": "BENIGN"
        },
        {
            "name": "PowerShell with Encoding",
            "features": [1.0, 0.0, 0.0, 0.0, 0.0,  # Suspicious process
                        0.2, 0.3, 0.0, 0.0, 0.0,  # Some credential access
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No reconnaissance
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No persistence
                        0.8, 1.0, 0.0, 0.3, 0.7], # High activity, PowerShell, suspicious
            "expected": "Suspicious"
        },
        {
            "name": "Reconnaissance Commands",
            "features": [0.0, 0.0, 0.0, 0.0, 0.0,  # Normal process
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No credential access
                        1.0, 1.0, 0.8, 0.0, 0.0,  # High reconnaissance
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No persistence
                        0.6, 0.0, 1.0, 0.2, 0.0], # CMD activity
            "expected": "RECONNAISSANCE"
        },
        {
            "name": "Credential Dumping",
            "features": [0.8, 0.0, 0.0, 0.0, 0.0,  # Suspicious process
                        1.0, 0.9, 1.0, 0.0, 0.0,  # High credential access
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No reconnaissance
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No persistence
                        0.9, 0.0, 0.0, 0.8, 0.0], # High activity, suspicious location
            "expected": "CREDENTIAL_ACCESS"
        }
    ]
    
    for scenario in test_scenarios:
        print(f"\n🔍 Testing: {scenario['name']}")
        
        # Get predictions
        anomaly_score = detector.predict(scenario['features'])
        threat_result = classifier.predict(scenario['features'])
        
        print(f"   Anomaly Score: {anomaly_score:.3f}")
        print(f"   Threat Class: {threat_result['class']}")
        print(f"   Confidence: {threat_result['confidence']:.3f}")
        
        # Show top 3 threat probabilities
        probs = threat_result['probabilities']
        top_threats = sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3]
        print(f"   Top Threats:")
        for threat, prob in top_threats:
            print(f"     {threat}: {prob:.3f}")
    
    # 5. Test Enhanced VPEW Real Agent
    print("\n5️⃣  Testing Enhanced VPEW Real Agent...")
    try:
        # Mock psutil for Linux testing
        class MockProcess:
            def __init__(self, pid, name, cmdline):
                self.info = {
                    'pid': pid, 'name': name, 'cmdline': cmdline.split(),
                    'create_time': time.time(), 'username': 'testuser'
                }
        
        class MockPsutil:
            @staticmethod
            def process_iter(attrs):
                return [
                    MockProcess(1234, 'powershell.exe', 'powershell.exe -enc dGVzdA=='),
                    MockProcess(5678, 'rundll32.exe', 'rundll32.exe comsvcs.dll MiniDump lsass.exe')
                ]
        
        sys.modules['psutil'] = MockPsutil()
        
        # Import and test VPEWRealAgent
        from vpew_real import VPEWRealAgent
        agent = VPEWRealAgent()
        
        print(f"✅ VPEW Real Agent initialized (ML: {'Enabled' if agent.ml_enabled else 'Disabled'})")
        
        # Test process analysis
        test_process = {
            'pid': 1234,
            'name': 'powershell.exe',
            'cmdline': 'powershell.exe -enc dGVzdCBjb21tYW5k',
            'create_time': time.time(),
            'username': 'testuser'
        }
        
        result = agent.analyze_real_process(test_process)
        print(f"   Process Analysis:")
        print(f"     Risk Score: {result['risk_score']:.3f}")
        print(f"     Is Threat: {result['is_threat']}")
        print(f"     Threats Found: {len(result['threats_found'])}")
        if 'ml_results' in result and result['ml_results']:
            ml = result['ml_results']
            if 'anomaly_score' in ml:
                print(f"     ML Anomaly: {ml['anomaly_score']:.3f}")
                print(f"     ML Threat: {ml['threat_class']}")
        
    except Exception as e:
        print(f"❌ VPEW Real Agent test failed: {e}")
    
    # 6. Summary
    print("\n" + "=" * 50)
    print("🎉 VPEW-AI ML Integration Demo Complete!")
    print("\n✅ Features Demonstrated:")
    print("   • TensorFlow Autoencoder for Anomaly Detection")
    print("   • TensorFlow Neural Network for Threat Classification")
    print("   • Model Training with Synthetic Data")
    print("   • Model Persistence and Loading")
    print("   • Enhanced Real-time Threat Detection")
    print("   • ML + Rule-based Hybrid Analysis")
    print("   • Feature Extraction from Process Data")
    print("\n🎯 The system successfully integrates TensorFlow ML models")
    print("   with rule-based threat detection for comprehensive security analysis.")

if __name__ == "__main__":
    main()