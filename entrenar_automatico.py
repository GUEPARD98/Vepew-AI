#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ENTRENAMIENTO AUTOMÁTICO DE IA PARA VPEW-AI
Entrena automáticamente todos los modelos sin interacción del usuario
"""

import os
import sys
import numpy as np
import json
import time
from pathlib import Path
from datetime import datetime
from collections import Counter
import math

# Configurar path del virtualenv
venv_path = Path("C:/ProgramData/vpew-ai/venv")
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "Lib" / "site-packages"))

def calculate_entropy(text):
    """Calcular entropía de Shannon"""
    if not text or len(text) < 2:
        return 0.0
    
    char_counts = Counter(text)
    entropy = 0.0
    text_len = len(text)
    
    for count in char_counts.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def generate_training_data():
    """Generar datos de entrenamiento sintéticos"""
    print("🎲 Generando datos de entrenamiento...")
    
    events = []
    labels = []
    
    # EVENTOS NORMALES (70%)
    normal_processes = [
        ('C:\\Windows\\System32\\notepad.exe', 'notepad.exe document.txt'),
        ('C:\\Windows\\System32\\calc.exe', 'calc.exe'),
        ('C:\\Program Files\\Microsoft Office\\WINWORD.EXE', 'winword.exe /n'),
        ('C:\\Windows\\explorer.exe', 'explorer.exe'),
        ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe -k LocalService')
    ]
    
    for _ in range(700):
        image, cmdline = normal_processes[np.random.randint(0, len(normal_processes))]
        events.append({
            'image': image,
            'command_line': cmdline,
            'target_image': '',
            'target_user': 'normal_user',
            'event_id': 1
        })
        labels.append('BENIGN')
    
    # EVENTOS DE RECONOCIMIENTO (10%)
    recon_commands = [
        'net user /domain',
        'whoami /all',
        'systeminfo',
        'ipconfig /all',
        'net view \\\\domain'
    ]
    
    for _ in range(100):
        events.append({
            'image': 'C:\\Windows\\System32\\net.exe',
            'command_line': recon_commands[np.random.randint(0, len(recon_commands))],
            'target_image': '',
            'target_user': 'attacker',
            'event_id': 1
        })
        labels.append('RECONNAISSANCE')
    
    # EVENTOS DE ACCESO A CREDENCIALES (10%)
    cred_commands = [
        'mimikatz.exe sekurlsa::logonpasswords',
        'procdump.exe -ma lsass.exe lsass.dmp',
        'dumper.exe --lsass --output creds.txt'
    ]
    
    for _ in range(100):
        events.append({
            'image': f'C:\\temp\\{["mimikatz.exe", "procdump.exe", "dumper.exe"][np.random.randint(0, 3)]}',
            'command_line': cred_commands[np.random.randint(0, len(cred_commands))],
            'target_image': 'C:\\Windows\\System32\\lsass.exe',
            'target_user': 'admin',
            'event_id': 10
        })
        labels.append('CREDENTIAL_ACCESS')
    
    # EVENTOS DE EVASIÓN (10%)
    evasion_commands = [
        'powershell -enc JABhAD0AJwBoAGUAbABsAG8A',
        'powershell -e SQBuAHYAbwBrAGUA',
        'powershell -EncodedCommand UwB0AGEAcgB0AC0A'
    ]
    
    for _ in range(100):
        events.append({
            'image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'command_line': evasion_commands[np.random.randint(0, len(evasion_commands))],
            'target_image': '',
            'target_user': 'compromised_user',
            'event_id': 1
        })
        labels.append('DEFENSE_EVASION')
    
    print(f"✅ {len(events)} eventos generados")
    print(f"   • BENIGN: {labels.count('BENIGN')}")
    print(f"   • RECONNAISSANCE: {labels.count('RECONNAISSANCE')}")
    print(f"   • CREDENTIAL_ACCESS: {labels.count('CREDENTIAL_ACCESS')}")
    print(f"   • DEFENSE_EVASION: {labels.count('DEFENSE_EVASION')}")
    
    return events, labels

def extract_features(events):
    """Extraer características numéricas"""
    print("📊 Extrayendo características...")
    
    feature_vectors = []
    
    for event in events:
        features = []
        
        # Características temporales (4)
        now = datetime.now()
        features.extend([
            now.hour / 24.0,
            now.weekday() / 7.0,
            float(9 <= now.hour <= 17),
            float(now.weekday() >= 5)
        ])
        
        # Características de proceso (6)
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        
        features.extend([
            min(len(image.split('\\')[-1]) / 50.0, 1.0),
            float(any(path in image for path in ['system32', 'windows'])),
            min(len(cmdline) / 200.0, 1.0),
            float('powershell' in cmdline),
            float('-enc' in cmdline or 'base64' in cmdline),
            min(calculate_entropy(cmdline) / 5.0, 1.0)
        ])
        
        # Características de riesgo (6)
        target_image = event.get('target_image', '').lower()
        features.extend([
            float('lsass.exe' in target_image),
            float(any(word in cmdline for word in ['sekurlsa', 'logonpasswords', 'mimikatz'])),
            float(any(cmd in cmdline for cmd in ['net user', 'whoami', 'systeminfo'])),
            float(any(path in image for path in ['temp', 'appdata'])),
            float('admin' in event.get('target_user', '').lower()),
            float(event.get('event_id') in [4697, 4698, 4625, 1102, 10])
        ])
        
        feature_vectors.append(features)
    
    return np.array(feature_vectors, dtype=np.float32)

def train_simple_models(X_data, y_labels):
    """Entrenar modelos simplificados"""
    print("🤖 Entrenando modelos de IA...")
    
    base_path = Path("C:/ProgramData/vpew-ai")
    models_path = base_path / "models"
    models_path.mkdir(parents=True, exist_ok=True)
    
    results = {}
    
    # 1. Entrenar Isolation Forest
    try:
        from sklearn.ensemble import IsolationForest
        import joblib
        
        # Solo datos normales para entrenamiento no supervisado
        normal_indices = [i for i, label in enumerate(y_labels) if label == 'BENIGN']
        X_normal = X_data[normal_indices]
        
        isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        isolation_forest.fit(X_normal)
        
        # Guardar modelo
        joblib.dump(isolation_forest, models_path / "isolation_forest.joblib")
        results['isolation_forest'] = True
        print("✅ Isolation Forest entrenado y guardado")
        
    except Exception as e:
        print(f"❌ Error con Isolation Forest: {e}")
        results['isolation_forest'] = False
    
    # 2. Entrenar Random Forest Classifier
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        import joblib
        
        # Codificar etiquetas
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y_labels)
        
        # Entrenar clasificador
        rf_classifier = RandomForestClassifier(n_estimators=50, random_state=42)
        rf_classifier.fit(X_data, y_encoded)
        
        # Guardar modelos
        joblib.dump(rf_classifier, models_path / "threat_classifier.joblib")
        joblib.dump(label_encoder, models_path / "label_encoder.joblib")
        
        results['random_forest'] = True
        print("✅ Random Forest Classifier entrenado y guardado")
        
    except Exception as e:
        print(f"❌ Error con Random Forest: {e}")
        results['random_forest'] = False
    
    # 3. Entrenar Autoencoder simple
    try:
        import tensorflow as tf
        
        # Solo datos normales
        normal_indices = [i for i, label in enumerate(y_labels) if label == 'BENIGN']
        X_normal = X_data[normal_indices]
        
        # Arquitectura simple
        input_dim = X_data.shape[1]
        autoencoder = tf.keras.Sequential([
            tf.keras.layers.Dense(8, activation='relu', input_shape=(input_dim,)),
            tf.keras.layers.Dense(4, activation='relu'),
            tf.keras.layers.Dense(8, activation='relu'),
            tf.keras.layers.Dense(input_dim, activation='linear')
        ])
        
        autoencoder.compile(optimizer='adam', loss='mse')
        
        # Entrenar
        autoencoder.fit(X_normal, X_normal, epochs=20, batch_size=16, verbose=0)
        
        # Guardar modelo
        autoencoder.save(str(models_path / "autoencoder.h5"))
        results['autoencoder'] = True
        print("✅ Autoencoder entrenado y guardado")
        
    except Exception as e:
        print(f"❌ Error con Autoencoder: {e}")
        results['autoencoder'] = False
    
    return results

def main():
    """Entrenamiento automático completo"""
    print("🧠 ENTRENAMIENTO AUTOMÁTICO DE IA VPEW-AI")
    print("=" * 50)
    
    start_time = time.time()
    
    # 1. Generar datos
    events, labels = generate_training_data()
    
    # 2. Extraer características
    X_data = extract_features(events)
    print(f"📈 Matriz de características: {X_data.shape}")
    
    # 3. Entrenar modelos
    results = train_simple_models(X_data, labels)
    
    # 4. Guardar metadatos
    base_path = Path("C:/ProgramData/vpew-ai")
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'training_duration': time.time() - start_time,
        'total_events': len(events),
        'feature_dimensions': X_data.shape[1],
        'models_trained': results,
        'class_distribution': dict(zip(*np.unique(labels, return_counts=True))),
        'training_successful': all(results.values())
    }
    
    with open(base_path / "training_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # 5. Resumen
    print(f"\n🎯 ENTRENAMIENTO COMPLETADO:")
    print(f"   ⏱️ Tiempo total: {metadata['training_duration']:.1f} segundos")
    print(f"   📊 Eventos procesados: {metadata['total_events']}")
    print(f"   🧮 Características: {metadata['feature_dimensions']}")
    
    success_count = sum(results.values())
    total_models = len(results)
    
    if success_count == total_models:
        print(f"\n🚀 ¡ENTRENAMIENTO 100% EXITOSO!")
        print(f"   ✅ {success_count}/{total_models} modelos entrenados")
        print(f"   📁 Modelos guardados en: C:\\ProgramData\\vpew-ai\\models")
        print(f"\n🧠 MODELOS DISPONIBLES:")
        print(f"   • Isolation Forest: Detección de anomalías")
        print(f"   • Random Forest: Clasificación de amenazas")
        print(f"   • Autoencoder: Análisis de patrones")
        print(f"\n✅ LA IA DE VPEW-AI ESTÁ ENTRENADA Y LISTA!")
    else:
        print(f"\n⚠️ Entrenamiento parcial: {success_count}/{total_models} modelos")
    
    return metadata

if __name__ == "__main__":
    main()
