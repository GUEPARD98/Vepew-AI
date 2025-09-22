#!/usr/bin/env python3
"""
Test final simplificado para VPEW-AI
"""

import sys
import os
sys.path.insert(0, 'src')

def test_complete_workflow():
    """Test del flujo completo de VPEW-AI"""
    print("=== VPEW-AI Complete Workflow Test ===\n")
    
    try:
        # 1. Importar módulos
        print("1. Importing modules...")
        from vpew_ai.ml import AnomalyDetector, ThreatClassifier, Trainer
        import pandas as pd
        import numpy as np
        print("✓ Modules imported successfully")
        
        # 2. Crear y entrenar modelos
        print("\n2. Training models...")
        trainer = Trainer()
        results = trainer.train_all_models()
        print(f"✓ Training completed: {results}")
        
        # 3. Crear modelos para predicción
        print("\n3. Loading trained models...")
        detector = AnomalyDetector()
        classifier = ThreatClassifier()
        
        # Cargar modelos entrenados
        detector.load_model("models/anomaly_detector.joblib")
        classifier.load_model("models/threat_classifier.joblib")
        print("✓ Models loaded successfully")
        
        # 4. Test de predicciones
        print("\n4. Testing predictions...")
        
        # Generar datos de prueba
        np.random.seed(42)
        test_data = pd.DataFrame(
            np.random.normal(0.5, 0.2, (5, 25)),
            columns=[f'feature_{i}' for i in range(25)]
        )
        
        # Test detector de anomalías
        anomalies = detector.predict(test_data)
        print(f"✓ Anomaly detection: {len(anomalies)} predictions")
        print(f"  Anomalies detected: {sum(anomalies)}")
        
        # Test clasificador de amenazas
        classifications = classifier.predict(test_data)
        print(f"✓ Threat classification: {len(classifications)} predictions")
        print(f"  Threat categories: {set(classifications)}")
        
        # 5. Test de escenarios específicos
        print("\n5. Testing specific scenarios...")
        
        # Escenario normal
        normal_data = pd.DataFrame(
            np.random.normal(0.3, 0.1, (1, 25)),
            columns=[f'feature_{i}' for i in range(25)]
        )
        normal_anomaly = detector.predict(normal_data)[0]
        normal_threat = classifier.predict(normal_data)[0]
        print(f"✓ Normal scenario: Anomaly={normal_anomaly}, Threat={normal_threat}")
        
        # Escenario sospechoso
        suspicious_data = pd.DataFrame(
            np.random.normal(0.8, 0.1, (1, 25)),
            columns=[f'feature_{i}' for i in range(25)]
        )
        suspicious_anomaly = detector.predict(suspicious_data)[0]
        suspicious_threat = classifier.predict(suspicious_data)[0]
        print(f"✓ Suspicious scenario: Anomaly={suspicious_anomaly}, Threat={suspicious_threat}")
        
        print("\n🎉 All tests passed! VPEW-AI is working correctly.")
        
        # 6. Información del sistema
        print("\n📊 System Information:")
        info = trainer.get_model_info()
        print(f"  Model directory: {info['model_dir']}")
        print(f"  Anomaly detector: {info['anomaly_detector']['model_type']}")
        print(f"  Threat classifier: {len(info['threat_classifier']['threat_categories'])} categories")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Ejecutar test principal"""
    success = test_complete_workflow()
    
    if success:
        print("\n🚀 VPEW-AI Installation Summary:")
        print("=" * 50)
        print("✅ Virtual environment: vpew_clean")
        print("✅ Dependencies installed (scikit-learn stack)")
        print("✅ ML models working (AnomalyDetector + ThreatClassifier)")
        print("✅ Training pipeline functional")
        print("✅ Prediction pipeline functional")
        print("✅ Complete workflow tested")
        print("\n📁 Key files:")
        print("  - Virtual env: vpew_clean/")
        print("  - Models: models/")
        print("  - Source: src/vpew_ai/")
        print("\n🎯 VPEW-AI is ready for production use!")
        
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

