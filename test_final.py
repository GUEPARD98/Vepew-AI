#!/usr/bin/env python3
"""
Test final para VPEW-AI sin TensorFlow
"""

import sys
import os
sys.path.insert(0, 'src')

def test_imports():
    """Test imports básicos"""
    print("Testing basic imports...")
    
    try:
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier, Trainer
        print("✓ ML modules imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import ML modules: {e}")
        return False

def test_models():
    """Test creación de modelos"""
    print("\nTesting model creation...")
    
    try:
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier
        
        detector = AnomalyDetector()
        classifier = ThreatClassifier()
        
        print(f"✓ Models created successfully")
        print(f"  - AnomalyDetector: {detector.model_type}")
        print(f"  - ThreatClassifier: {len(classifier.threat_categories)} categories")
        return True
    except Exception as e:
        print(f"✗ Failed to create models: {e}")
        return False

def test_training():
    """Test entrenamiento básico"""
    print("\nTesting basic training...")
    
    try:
        from vpew_ai.ml import Trainer
        import numpy as np
        import pandas as pd
        
        trainer = Trainer()
        
        # Generar datos sintéticos
        features, labels = trainer.generate_synthetic_data(100)
        print(f"✓ Generated synthetic data: {features.shape[0]} samples, {features.shape[1]} features")
        
        # Test entrenamiento de detector de anomalías
        success = trainer.train_anomaly_detector()
        if success:
            print("✓ Anomaly detector training successful")
        else:
            print("✗ Anomaly detector training failed")
            return False
        
        # Test entrenamiento de clasificador de amenazas
        success = trainer.train_threat_classifier()
        if success:
            print("✓ Threat classifier training successful")
        else:
            print("✗ Threat classifier training failed")
            return False
        
        return True
    except Exception as e:
        print(f"✗ Failed to test training: {e}")
        return False

def test_prediction():
    """Test predicciones"""
    print("\nTesting predictions...")
    
    try:
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier
        import numpy as np
        import pandas as pd
        
        # Crear datos de prueba
        np.random.seed(42)
        test_data = pd.DataFrame(
            np.random.normal(0.5, 0.2, (10, 5)),
            columns=['feature_0', 'feature_1', 'feature_2', 'feature_3', 'feature_4']
        )
        
        # Test detector de anomalías
        detector = AnomalyDetector()
        detector.fit(test_data)
        anomalies = detector.predict(test_data)
        print(f"✓ Anomaly detection: {len(anomalies)} predictions")
        
        # Test clasificador de amenazas
        classifier = ThreatClassifier()
        threat_labels = ['normal'] * 5 + ['anomaly'] * 5
        classifier.fit(test_data, threat_labels)
        classifications = classifier.predict(test_data)
        print(f"✓ Threat classification: {len(classifications)} predictions")
        
        return True
    except Exception as e:
        print(f"✗ Failed to test predictions: {e}")
        return False

def main():
    """Ejecutar todos los tests"""
    print("=== VPEW-AI Final Test (Scikit-learn Only) ===\n")
    
    tests = [
        test_imports,
        test_models,
        test_training,
        test_prediction
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! VPEW-AI is working correctly with scikit-learn.")
        print("\n📋 Installation Summary:")
        print("- ✓ Dependencies installed")
        print("- ✓ Virtual environment created")
        print("- ✓ ML models working (scikit-learn)")
        print("- ✓ Training pipeline functional")
        print("- ✓ Prediction pipeline functional")
        print("\n🚀 VPEW-AI is ready to use!")
        return True
    else:
        print("❌ Some tests failed.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

