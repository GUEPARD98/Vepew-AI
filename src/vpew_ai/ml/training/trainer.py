#!/usr/bin/env python3
"""
Trainer for VPEW-AI ML models
"""

import logging
import numpy as np
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from ..simple_models import SimpleAnomalyDetector as AnomalyDetector, SimpleThreatClassifier as ThreatClassifier

logger = logging.getLogger(__name__)

class Trainer:
    """
    Trainer class for VPEW-AI ML models
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir) if model_dir else Path("models")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.anomaly_detector = None
        self.threat_classifier = None
    
    def generate_synthetic_data(self, num_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data for testing purposes
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            Tuple of (features, labels)
        """
        try:
            # Generate synthetic feature data (25 features)
            np.random.seed(42)  # For reproducibility
            
            features = []
            labels = []
            
            for i in range(num_samples):
                # Generate different patterns for different threat classes
                if i % 6 == 0:  # BENIGN
                    feature_vec = np.random.normal(0.3, 0.1, 25)
                    label = 0
                elif i % 6 == 1:  # RECONNAISSANCE
                    feature_vec = np.random.normal(0.6, 0.2, 25)
                    feature_vec[0:5] = np.random.uniform(0.7, 0.9, 5)  # High network activity
                    label = 1
                elif i % 6 == 2:  # CREDENTIAL_ACCESS
                    feature_vec = np.random.normal(0.4, 0.15, 25)
                    feature_vec[5:10] = np.random.uniform(0.8, 1.0, 5)  # High process activity
                    label = 2
                elif i % 6 == 3:  # PERSISTENCE
                    feature_vec = np.random.normal(0.5, 0.1, 25)
                    feature_vec[10:15] = np.random.uniform(0.6, 0.8, 5)  # Registry/file activity
                    label = 3
                elif i % 6 == 4:  # LATERAL_MOVEMENT
                    feature_vec = np.random.normal(0.7, 0.2, 25)
                    feature_vec[15:20] = np.random.uniform(0.7, 0.9, 5)  # Network movement
                    label = 4
                else:  # DEFENSE_EVASION
                    feature_vec = np.random.normal(0.4, 0.3, 25)
                    feature_vec[20:25] = np.random.uniform(0.5, 0.8, 5)  # Evasive patterns
                    label = 5
                
                # Clip values to [0, 1] range
                feature_vec = np.clip(feature_vec, 0, 1)
                
                features.append(feature_vec)
                labels.append(label)
            
            features = np.array(features)
            labels = np.array(labels)
            
            logger.info(f"Generated {num_samples} synthetic samples")
            return features, labels
            
        except Exception as e:
            logger.error(f"Error generating synthetic data: {e}")
            return np.array([]), np.array([])
    
    def train_anomaly_detector(self, training_data: Optional[np.ndarray] = None) -> bool:
        """
        Train the anomaly detector
        
        Args:
            training_data: Normal training data (if None, generates synthetic data)
            
        Returns:
            True if training successful
        """
        try:
            # Initialize model
            anomaly_model_path = str(self.model_dir / "anomaly_detector.joblib")
            self.anomaly_detector = AnomalyDetector(model_path=anomaly_model_path)
            
            # Generate synthetic data if none provided
            if training_data is None:
                features, _ = self.generate_synthetic_data(2000)
                # For anomaly detection, we only use "normal" data (BENIGN class)
                normal_indices = np.arange(0, len(features), 6)  # Every 6th sample is benign
                training_data = features[normal_indices]
            
            # Convert to DataFrame for the new model interface
            import pandas as pd
            training_df = pd.DataFrame(training_data, columns=[f'feature_{i}' for i in range(training_data.shape[1])])
            
            # Train the model
            self.anomaly_detector.fit(training_df)
            
            # Save the trained model
            self.anomaly_detector.save_model(anomaly_model_path)
            logger.info("Anomaly detector training completed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            return False
    
    def train_threat_classifier(self, training_data: Optional[np.ndarray] = None,
                              labels: Optional[np.ndarray] = None) -> bool:
        """
        Train the threat classifier
        
        Args:
            training_data: Training features (if None, generates synthetic data)
            labels: Training labels (if None, generates synthetic data)
            
        Returns:
            True if training successful
        """
        try:
            # Initialize model
            classifier_model_path = str(self.model_dir / "threat_classifier.joblib")
            self.threat_classifier = ThreatClassifier(model_path=classifier_model_path)
            
            # Generate synthetic data if none provided
            if training_data is None or labels is None:
                training_data, labels = self.generate_synthetic_data(2000)
            
            # Convert to DataFrame and string labels
            import pandas as pd
            training_df = pd.DataFrame(training_data, columns=[f'feature_{i}' for i in range(training_data.shape[1])])
            
            # Convert numeric labels to threat category strings
            threat_categories = ['normal', 'reconnaissance', 'credential_access', 'persistence', 'lateral_movement', 'defense_evasion']
            label_strings = [threat_categories[label] if label < len(threat_categories) else 'unknown' for label in labels]
            
            # Train the model
            self.threat_classifier.fit(training_df, label_strings)
            
            # Save the trained model
            self.threat_classifier.save_model(classifier_model_path)
            logger.info("Threat classifier training completed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
            return False
    
    def train_all_models(self) -> Dict[str, bool]:
        """
        Train all models with synthetic data
        
        Returns:
            Dictionary with training results for each model
        """
        results = {}
        
        logger.info("Starting training of all models...")
        
        # Train anomaly detector
        results['anomaly_detector'] = self.train_anomaly_detector()
        
        # Train threat classifier
        results['threat_classifier'] = self.train_threat_classifier()
        
        # Summary
        successful = sum(results.values())
        total = len(results)
        logger.info(f"Training completed: {successful}/{total} models trained successfully")
        
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the trained models"""
        info = {
            'model_dir': str(self.model_dir),
            'anomaly_detector': None,
            'threat_classifier': None
        }
        
        if self.anomaly_detector:
            info['anomaly_detector'] = {
                'model_type': self.anomaly_detector.model_type,
                'is_fitted': self.anomaly_detector.is_fitted,
                'model_path': self.anomaly_detector.model_path
            }
        
        if self.threat_classifier:
            info['threat_classifier'] = {
                'is_fitted': self.threat_classifier.is_fitted,
                'model_path': self.threat_classifier.model_path,
                'threat_categories': self.threat_classifier.threat_categories
            }
        
        return info