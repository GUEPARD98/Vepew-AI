#!/usr/bin/env python3
"""
VPEW-AI Machine Learning Models
Anomaly Detection and Threat Classification Models
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import logging
from pathlib import Path
import pickle
import joblib

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow not available, using sklearn models")

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Anomaly Detection Model for VPEW-AI
    Detects anomalous behavior patterns in endpoint data
    """
    
    def __init__(self, model_path: Optional[str] = None, model_type: str = "isolation_forest"):
        self.model_path = model_path
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # Model configuration
        self.config = {
            'isolation_forest': {
                'contamination': 0.1,
                'random_state': 42,
                'n_estimators': 100
            },
            'one_class_svm': {
                'nu': 0.1,
                'kernel': 'rbf',
                'gamma': 'scale'
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5
            }
        }
        
        # Load model if path provided
        if model_path and Path(model_path).exists():
            self.load_model(model_path)
    
    def _prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare features for anomaly detection"""
        # Select numerical columns only
        numeric_columns = data.select_dtypes(include=[np.number]).columns
        
        if len(numeric_columns) == 0:
            logger.warning("No numerical columns found for anomaly detection")
            return np.array([])
        
        # Fill NaN values with median
        features = data[numeric_columns].fillna(data[numeric_columns].median())
        
        # Scale features
        if not self.is_fitted:
            features_scaled = self.scaler.fit_transform(features)
            self.is_fitted = True
        else:
            features_scaled = self.scaler.transform(features)
        
        return features_scaled
    
    def _create_model(self):
        """Create the anomaly detection model"""
        if self.model_type == "isolation_forest":
            self.model = IsolationForest(**self.config['isolation_forest'])
        elif self.model_type == "one_class_svm":
            self.model = OneClassSVM(**self.config['one_class_svm'])
        elif self.model_type == "dbscan":
            self.model = DBSCAN(**self.config['dbscan'])
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def fit(self, data: pd.DataFrame) -> 'AnomalyDetector':
        """Train the anomaly detection model"""
        logger.info(f"Training {self.model_type} anomaly detector...")
        
        # Prepare features
        features = self._prepare_features(data)
        
        if len(features) == 0:
            logger.error("No features available for training")
            return self
        
        # Create and train model
        self._create_model()
        
        if self.model_type == "dbscan":
            # DBSCAN doesn't have a fit method for anomaly detection
            # We'll use it differently
            self.model.fit(features)
        else:
            self.model.fit(features)
        
        logger.info(f"Anomaly detector trained successfully on {len(features)} samples")
        return self
    
    def predict(self, data: pd.DataFrame) -> np.ndarray:
        """Predict anomalies in the data"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        features = self._prepare_features(data)
        
        if len(features) == 0:
            return np.array([])
        
        if self.model_type == "dbscan":
            # For DBSCAN, predict cluster labels (-1 = anomaly)
            predictions = self.model.fit_predict(features)
            return (predictions == -1).astype(int)
        else:
            # For other models, predict anomaly scores
            predictions = self.model.predict(features)
            return (predictions == -1).astype(int)
    
    def score_samples(self, data: pd.DataFrame) -> np.ndarray:
        """Get anomaly scores for samples"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        features = self._prepare_features(data)
        
        if len(features) == 0:
            return np.array([])
        
        if hasattr(self.model, 'decision_function'):
            scores = self.model.decision_function(features)
            # Convert to anomaly scores (higher = more anomalous)
            return -scores
        elif hasattr(self.model, 'score_samples'):
            return -self.model.score_samples(features)
        else:
            # Fallback: use predictions
            predictions = self.predict(data)
            return predictions.astype(float)
    
    def save_model(self, model_path: str):
        """Save the trained model"""
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'config': self.config,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load a trained model"""
        model_path = Path(model_path)
        
        if not model_path.exists():
            logger.warning(f"Model file not found: {model_path}")
            return
        
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.model_type = model_data['model_type']
            self.config = model_data['config']
            self.is_fitted = model_data['is_fitted']
            
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")


class ThreatClassifier:
    """
    Threat Classification Model for VPEW-AI
    Classifies detected anomalies into threat categories
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = None
        self.is_fitted = False
        
        # Threat categories
        self.threat_categories = [
            'normal',
            'credential_access',
            'defense_evasion', 
            'lateral_movement',
            'persistence',
            'reconnaissance',
            'unknown'
        ]
        
        # Load model if path provided
        if model_path and Path(model_path).exists():
            self.load_model(model_path)
    
    def _prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare features for threat classification"""
        # Select numerical columns only
        numeric_columns = data.select_dtypes(include=[np.number]).columns
        
        if len(numeric_columns) == 0:
            logger.warning("No numerical columns found for threat classification")
            return np.array([])
        
        # Fill NaN values with median
        features = data[numeric_columns].fillna(data[numeric_columns].median())
        
        # Scale features
        if not self.is_fitted:
            features_scaled = self.scaler.fit_transform(features)
            self.is_fitted = True
        else:
            features_scaled = self.scaler.transform(features)
        
        return features_scaled
    
    def _create_model(self):
        """Create the threat classification model"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        
        # Use Random Forest as default classifier
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )
    
    def fit(self, data: pd.DataFrame, labels: List[str]) -> 'ThreatClassifier':
        """Train the threat classification model"""
        logger.info("Training threat classifier...")
        
        # Prepare features
        features = self._prepare_features(data)
        
        if len(features) == 0:
            logger.error("No features available for training")
            return self
        
        # Create label encoder
        from sklearn.preprocessing import LabelEncoder
        self.label_encoder = LabelEncoder()
        encoded_labels = self.label_encoder.fit_transform(labels)
        
        # Create and train model
        self._create_model()
        self.model.fit(features, encoded_labels)
        
        logger.info(f"Threat classifier trained successfully on {len(features)} samples")
        return self
    
    def predict(self, data: pd.DataFrame) -> List[str]:
        """Predict threat categories for the data"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        features = self._prepare_features(data)
        
        if len(features) == 0:
            return ['unknown'] * len(data)
        
        # Make predictions
        encoded_predictions = self.model.predict(features)
        
        # Convert back to string labels
        if self.label_encoder:
            predictions = self.label_encoder.inverse_transform(encoded_predictions)
        else:
            predictions = ['unknown'] * len(encoded_predictions)
        
        return predictions.tolist()
    
    def predict_proba(self, data: pd.DataFrame) -> np.ndarray:
        """Get prediction probabilities for each threat category"""
        if self.model is None:
            raise ValueError("Model not trained. Call fit() first.")
        
        features = self._prepare_features(data)
        
        if len(features) == 0:
            # Return uniform probabilities
            n_samples = len(data)
            n_classes = len(self.threat_categories)
            return np.ones((n_samples, n_classes)) / n_classes
        
        # Get prediction probabilities
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(features)
        else:
            # Fallback: use predictions as probabilities
            predictions = self.predict(data)
            probabilities = np.zeros((len(predictions), len(self.threat_categories)))
            for i, pred in enumerate(predictions):
                if pred in self.threat_categories:
                    idx = self.threat_categories.index(pred)
                    probabilities[i, idx] = 1.0
                else:
                    # Unknown category
                    probabilities[i, -1] = 1.0
        
        return probabilities
    
    def save_model(self, model_path: str):
        """Save the trained model"""
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'threat_categories': self.threat_categories,
            'is_fitted': self.is_fitted
        }
        
        joblib.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load a trained model"""
        model_path = Path(model_path)
        
        if not model_path.exists():
            logger.warning(f"Model file not found: {model_path}")
            return
        
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.threat_categories = model_data['threat_categories']
            self.is_fitted = model_data['is_fitted']
            
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")


class ModelFactory:
    """Factory class for creating ML models"""
    
    @staticmethod
    def create_anomaly_detector(model_type: str = "isolation_forest", **kwargs) -> AnomalyDetector:
        """Create an anomaly detector"""
        return AnomalyDetector(model_type=model_type, **kwargs)
    
    @staticmethod
    def create_threat_classifier(**kwargs) -> ThreatClassifier:
        """Create a threat classifier"""
        return ThreatClassifier(**kwargs)
    
    @staticmethod
    def create_default_models() -> Tuple[AnomalyDetector, ThreatClassifier]:
        """Create default models for VPEW-AI"""
        anomaly_detector = AnomalyDetector(model_type="isolation_forest")
        threat_classifier = ThreatClassifier()
        return anomaly_detector, threat_classifier
