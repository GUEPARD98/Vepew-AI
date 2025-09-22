#!/usr/bin/env python3
"""
Test VPEW-AI functionality with improved models
"""

import sys
import numpy as np
sys.path.append('src')

def test_improved_training():
    """Test with better balanced training data"""
    from vpew_ai.ml.training.trainer import Trainer
    from vpew_ai.ml import AnomalyDetector, ThreatClassifier
    
    print("🔧 Creating improved models with better training data...")
    
    # Create trainer
    trainer = Trainer("models")
    
    # Generate better balanced synthetic data
    np.random.seed(42)
    features_list = []
    labels_list = []
    
    # Generate more realistic data distributions
    for i in range(3000):  # More training data
        if i % 6 == 0:  # BENIGN - 80% should be benign for realistic distribution
            # Normal processes with low feature values
            feature_vec = np.random.normal(0.1, 0.05, 25)  # Lower baseline
            for _ in range(4):  # Generate more benign samples
                features_list.append(np.clip(feature_vec + np.random.normal(0, 0.02, 25), 0, 1))
                labels_list.append(0)
            label = 0
        elif i % 6 == 1:  # RECONNAISSANCE
            feature_vec = np.random.normal(0.2, 0.1, 25)
            feature_vec[10:15] = np.random.uniform(0.6, 0.9, 5)  # Recon indicators
            label = 1
        elif i % 6 == 2:  # CREDENTIAL_ACCESS  
            feature_vec = np.random.normal(0.2, 0.1, 25)
            feature_vec[5:10] = np.random.uniform(0.7, 1.0, 5)  # Credential indicators
            label = 2
        elif i % 6 == 3:  # PERSISTENCE
            feature_vec = np.random.normal(0.2, 0.1, 25)
            feature_vec[15:20] = np.random.uniform(0.5, 0.8, 5)  # Persistence indicators
            label = 3
        elif i % 6 == 4:  # LATERAL_MOVEMENT
            feature_vec = np.random.normal(0.3, 0.15, 25)
            feature_vec[15:20] = np.random.uniform(0.6, 0.9, 5)  # Movement indicators
            label = 4
        else:  # DEFENSE_EVASION
            feature_vec = np.random.normal(0.3, 0.2, 25)
            feature_vec[0:5] = np.random.uniform(0.5, 0.8, 5)  # Evasive indicators
            label = 5
        
        if i % 6 != 0:  # Non-benign
            features_list.append(np.clip(feature_vec, 0, 1))
            labels_list.append(label)
    
    features = np.array(features_list)
    labels = np.array(labels_list)
    
    print(f"Generated {len(features)} samples")
    print(f"Label distribution: {np.bincount(labels)}")
    
    # Train models
    anomaly_detector = AnomalyDetector(model_path="models/anomaly_detector_v2.keras")
    threat_classifier = ThreatClassifier(model_path="models/threat_classifier_v2.keras")
    
    # Train anomaly detector on benign data only
    benign_data = features[labels == 0]
    print(f"Training anomaly detector on {len(benign_data)} benign samples...")
    anomaly_detector.train(benign_data, epochs=30)
    anomaly_detector.save_model()
    
    # Train threat classifier on all data
    print(f"Training threat classifier on {len(features)} total samples...")
    threat_classifier.train(features, labels, epochs=30)
    threat_classifier.save_model()
    
    return anomaly_detector, threat_classifier

def test_scenarios():
    """Test realistic scenarios"""
    print("\n🧪 Testing Realistic Scenarios...")
    
    # Try to load improved models first
    try:
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier
        detector = AnomalyDetector(model_path="models/anomaly_detector_v2.keras")
        classifier = ThreatClassifier(model_path="models/threat_classifier_v2.keras")
        detector.load_model("models/anomaly_detector_v2.keras")
        classifier.load_model("models/threat_classifier_v2.keras")
        print("✅ Using improved models")
    except:
        print("⚠️  Using default models (may be less accurate)")
        detector = AnomalyDetector()
        classifier = ThreatClassifier()
        # Train the models with synthetic data first
        from vpew_ai.ml.training import Trainer
        trainer = Trainer()
        trainer.train_all_models()
        # Load the trained models
        detector.load_model("models/anomaly_detector.joblib")
        classifier.load_model("models/threat_classifier.joblib")
    
    # Test scenarios
    scenarios = [
        {
            "name": "🟢 Normal Notepad",
            "features": [0.0, 0.0, 0.0, 0.0, 0.0] * 5,  # All zeros = normal
            "expected_benign": True
        },
        {
            "name": "🟡 Suspicious PowerShell",
            "features": [1.0, 0.0, 0.0, 0.0, 0.0,  # PowerShell detected
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No credential access
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No reconnaissance
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No persistence
                        0.5, 1.0, 0.0, 0.0, 0.0], # PowerShell active
            "expected_benign": False
        },
        {
            "name": "🔴 Credential Dumping Attack",
            "features": [1.0, 0.0, 0.0, 0.0, 0.0,  # Suspicious process
                        1.0, 1.0, 1.0, 0.0, 0.0,  # High credential access
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No reconnaissance
                        0.0, 0.0, 0.0, 0.0, 0.0,  # No persistence
                        0.8, 0.0, 0.0, 1.0, 0.0], # High activity, suspicious location
            "expected_benign": False
        }
    ]
    
    for scenario in scenarios:
        print(f"\n{scenario['name']}:")
        
        anomaly_score = detector.predict(scenario['features'])
        threat_result = classifier.predict(scenario['features'])
        
        is_anomaly = anomaly_score > 0.5
        is_malicious = threat_result['class'] != 'BENIGN' and threat_result['confidence'] > 0.6
        
        print(f"  Anomaly Score: {anomaly_score:.3f} {'🚨' if is_anomaly else '✅'}")
        print(f"  Threat: {threat_result['class']} ({threat_result['confidence']:.3f}) {'🚨' if is_malicious else '✅'}")
        
        # Check if prediction aligns with expectation
        is_threat_detected = is_anomaly or is_malicious
        if scenario['expected_benign']:
            result = "✅ Correctly identified as benign" if not is_threat_detected else "❌ False positive"
        else:
            result = "✅ Correctly identified as threat" if is_threat_detected else "❌ False negative"
        
        print(f"  Result: {result}")

if __name__ == "__main__":
    print("🔬 VPEW-AI Functionality Test")
    print("=" * 40)
    
    # Test 1: Try improved training
    try:
        detector, classifier = test_improved_training()
        print("✅ Improved models created")
    except Exception as e:
        print(f"⚠️  Could not create improved models: {e}")
    
    # Test 2: Test scenarios
    test_scenarios()
    
    print("\n" + "=" * 40)
    print("🎯 Test Complete!")
    print("\nThe VPEW-AI system now includes:")
    print("• TensorFlow-based ML models")
    print("• Anomaly detection with autoencoders") 
    print("• Multi-class threat classification")
    print("• Enhanced rule-based detection")
    print("• Hybrid ML + rules analysis")
    print("• Real-time process monitoring integration")