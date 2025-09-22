#!/usr/bin/env python3
"""
Simple ML Models for VPEW-AI (sklearn only)
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import logging
from pathlib import Path
import joblib

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)

class SimpleAnomalyDetector:
    """Simple Anomaly Detection Model using sklearn"""
    
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
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def fit(self, data: pd.DataFrame) -> 'SimpleAnomalyDetector':
        """Train the anomaly detection model"""
        logger.info(f"Training {self.model_type} anomaly detector...")
        
        # Prepare features
        features = self._prepare_features(data)
        
        if len(features) == 0:
            logger.error("No features available for training")
            return self
        
        # Create and train model
        self._create_model()
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
        
        predictions = self.model.predict(features)
        return (predictions == -1).astype(int)
    
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


class SimpleThreatClassifier:
    """Simple Threat Classification Model using sklearn"""
    
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
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )
    
    def fit(self, data: pd.DataFrame, labels: List[str]) -> 'SimpleThreatClassifier':
        """Train the threat classification model"""
        logger.info("Training threat classifier...")
        
        # Prepare features
        features = self._prepare_features(data)
        
        if len(features) == 0:
            logger.error("No features available for training")
            return self
        
        # Create label encoder
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

