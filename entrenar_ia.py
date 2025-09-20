#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ENTRENADOR DE IA PARA VPEW-AI
Sistema de entrenamiento automático con datos sintéticos y reales
"""

import os
import sys
import numpy as np
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
import logging

# Configurar path del virtualenv
venv_path = Path("C:/ProgramData/vpew-ai/venv")
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "Lib" / "site-packages"))

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VPEWTrainer:
    """
    Entrenador de modelos de IA para VPEW-AI
    Genera datos sintéticos y entrena modelos reales
    """
    
    def __init__(self):
        self.base_path = Path("C:/ProgramData/vpew-ai")
        self.models_path = self.base_path / "models"
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        # Datos de entrenamiento
        self.training_data = []
        self.training_labels = []
        
        logger.info("VPEW-AI Trainer iniciado")
    
    def generate_synthetic_data(self, n_samples=1000):
        """
        Generar datos sintéticos para entrenamiento
        Simula eventos Windows normales y maliciosos
        """
        print(f"🎲 Generando {n_samples} eventos sintéticos...")
        
        synthetic_events = []
        labels = []
        
        # Distribución de clases
        class_distribution = {
            'BENIGN': 0.7,           # 70% eventos normales
            'RECONNAISSANCE': 0.1,    # 10% reconocimiento
            'CREDENTIAL_ACCESS': 0.05, # 5% acceso credenciales
            'DEFENSE_EVASION': 0.08,  # 8% evasión
            'PERSISTENCE': 0.05,      # 5% persistencia
            'LATERAL_MOVEMENT': 0.02  # 2% movimiento lateral
        }
        
        for i in range(n_samples):
            # Seleccionar clase aleatoriamente según distribución
            rand = np.random.random()
            cumulative = 0
            selected_class = 'BENIGN'
            
            for class_name, probability in class_distribution.items():
                cumulative += probability
                if rand <= cumulative:
                    selected_class = class_name
                    break
            
            # Generar evento según la clase
            event = self._generate_event_for_class(selected_class)
            
            synthetic_events.append(event)
            labels.append(selected_class)
        
        print(f"✅ Datos sintéticos generados:")
        for class_name, count in zip(*np.unique(labels, return_counts=True)):
            print(f"   • {class_name}: {count} eventos ({count/n_samples*100:.1f}%)")
        
        return synthetic_events, labels
    
    def _generate_event_for_class(self, class_name):
        """Generar evento sintético para una clase específica"""
        base_event = {
            'event_id': 1,
            'log_type': 'sysmon',
            'time_generated': datetime.now().isoformat(),
            'computer_name': 'TRAINING-HOST',
            'process_id': np.random.randint(1000, 9999)
        }
        
        if class_name == 'BENIGN':
            # Eventos normales
            normal_processes = [
                'C:\\Windows\\System32\\notepad.exe',
                'C:\\Windows\\System32\\calc.exe',
                'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
                'C:\\Windows\\explorer.exe',
                'C:\\Windows\\System32\\svchost.exe'
            ]
            
            base_event.update({
                'image': np.random.choice(normal_processes),
                'command_line': f"{np.random.choice(['notepad.exe', 'calc.exe', 'winword.exe'])} document.txt",
                'target_user': 'normal_user'
            })
        
        elif class_name == 'RECONNAISSANCE':
            # Comandos de reconocimiento
            recon_commands = [
                'net user /domain',
                'whoami /all',
                'systeminfo',
                'ipconfig /all',
                'net view \\\\domain',
                'nltest /domain_trusts'
            ]
            
            base_event.update({
                'image': 'C:\\Windows\\System32\\net.exe',
                'command_line': np.random.choice(recon_commands),
                'target_user': 'attacker_user'
            })
        
        elif class_name == 'CREDENTIAL_ACCESS':
            # Acceso a credenciales
            base_event.update({
                'event_id': 10,  # Process access
                'image': f'C:\\temp\\{np.random.choice(["mimikatz.exe", "procdump.exe", "dumper.exe"])}',
                'command_line': np.random.choice([
                    'mimikatz.exe sekurlsa::logonpasswords',
                    'procdump.exe -ma lsass.exe lsass.dmp',
                    'dumper.exe --lsass --output creds.txt'
                ]),
                'target_image': 'C:\\Windows\\System32\\lsass.exe',
                'granted_access': '0x1010',
                'target_user': 'admin_user'
            })
        
        elif class_name == 'DEFENSE_EVASION':
            # Evasión defensiva
            encoded_commands = [
                'powershell -enc JABhAD0AJwBoAGUAbABsAG8A',
                'powershell -e SQBuAHYAbwBrAGUA',
                'powershell -EncodedCommand UwB0AGEAcgB0AC0A'
            ]
            
            base_event.update({
                'image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                'command_line': np.random.choice(encoded_commands),
                'target_user': 'compromised_user'
            })
        
        elif class_name == 'PERSISTENCE':
            # Persistencia
            base_event.update({
                'event_id': 4697,  # Service installation
                'image': 'C:\\Windows\\System32\\sc.exe',
                'command_line': f'sc create MaliciousService binPath= C:\\temp\\malware.exe',
                'service_name': f'Service{np.random.randint(1000, 9999)}',
                'target_user': 'admin_user'
            })
        
        elif class_name == 'LATERAL_MOVEMENT':
            # Movimiento lateral
            base_event.update({
                'event_id': 3,  # Network connection
                'image': 'C:\\Windows\\System32\\net.exe',
                'command_line': 'net use \\\\target-host\\C$ /user:admin password',
                'destination_ip': f'192.168.1.{np.random.randint(10, 254)}',
                'destination_port': '445',
                'target_user': 'admin_user'
            })
        
        return base_event
    
    def extract_features_for_training(self, events):
        """Extraer características para entrenamiento"""
        print("📊 Extrayendo características para entrenamiento...")
        
        feature_vectors = []
        
        for event in events:
            features = {}
            
            # Características temporales
            try:
                timestamp = datetime.fromisoformat(event['time_generated'].replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
            
            features.update({
                'hour_of_day': timestamp.hour / 24.0,  # Normalizar 0-1
                'day_of_week': timestamp.weekday() / 7.0,
                'is_business_hours': float(9 <= timestamp.hour <= 17),
                'is_weekend': float(timestamp.weekday() >= 5)
            })
            
            # Características de proceso
            image = event.get('image', '').lower()
            cmdline = event.get('command_line', '').lower()
            
            features.update({
                'process_name_length': len(image.split('\\')[-1]) / 50.0,  # Normalizar
                'is_system_process': float(any(path in image for path in ['system32', 'windows'])),
                'cmdline_length': min(len(cmdline) / 200.0, 1.0),  # Normalizar y limitar
                'has_powershell': float('powershell' in cmdline),
                'has_encoded_cmd': float('-enc' in cmdline or 'base64' in cmdline),
                'cmdline_entropy': min(self._calculate_entropy(cmdline) / 5.0, 1.0)  # Normalizar
            })
            
            # Características específicas
            target_image = event.get('target_image', '').lower()
            features.update({
                'lsass_access': float('lsass.exe' in target_image),
                'mimikatz_keywords': float(any(word in cmdline for word in ['sekurlsa', 'logonpasswords', 'mimikatz'])),
                'recon_commands': float(any(cmd in cmdline for cmd in ['net user', 'whoami', 'systeminfo'])),
                'suspicious_location': float(any(path in image for path in ['temp', 'appdata'])),
                'admin_user': float('admin' in event.get('target_user', '').lower()),
                'service_event': float(event.get('event_id') in [4697, 4698]),
                'network_event': float(bool(event.get('destination_ip'))),
                'external_ip': float(not event.get('destination_ip', '127.0.0.1').startswith(('192.168.', '10.', '172.16.', '127.'))),
                'suspicious_port': float(event.get('destination_port') in ['4444', '31337', '8080']),
                'failed_logon': float(event.get('event_id') == 4625),
                'log_clearing': float(event.get('event_id') == 1102)
            })
            
            # Convertir a vector numpy
            feature_vector = np.array(list(features.values()), dtype=np.float32)
            feature_vectors.append(feature_vector)
        
        return np.array(feature_vectors)
    
    def _calculate_entropy(self, text):
        """Calcular entropía de Shannon"""
        if not text or len(text) < 2:
            return 0.0
        
        from collections import Counter
        char_counts = Counter(text)
        entropy = 0.0
        text_len = len(text)
        
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def train_isolation_forest(self, X_normal):
        """Entrenar Isolation Forest para detección de anomalías"""
        print("🌲 Entrenando Isolation Forest...")
        
        try:
            from sklearn.ensemble import IsolationForest
            import joblib
            
            # Configurar modelo
            isolation_forest = IsolationForest(
                contamination=0.1,  # 10% de datos esperados como anómalos
                random_state=42,
                n_estimators=100
            )
            
            # Entrenar solo con datos normales
            isolation_forest.fit(X_normal)
            
            # Guardar modelo
            model_path = self.models_path / "isolation_forest.joblib"
            joblib.dump(isolation_forest, model_path)
            
            print(f"✅ Isolation Forest entrenado y guardado en {model_path}")
            return True
            
        except ImportError:
            print("❌ Scikit-learn no disponible")
            return False
        except Exception as e:
            print(f"❌ Error entrenando Isolation Forest: {e}")
            return False
    
    def train_autoencoder(self, X_normal):
        """Entrenar Autoencoder con TensorFlow"""
        print("🧠 Entrenando Autoencoder...")
        
        try:
            import tensorflow as tf
            
            # Configurar TensorFlow para evitar warnings
            tf.get_logger().setLevel('ERROR')
            
            input_dim = X_normal.shape[1]
            
            # Arquitectura del autoencoder
            input_layer = tf.keras.layers.Input(shape=(input_dim,))
            
            # Encoder
            encoded = tf.keras.layers.Dense(16, activation='relu')(input_layer)
            encoded = tf.keras.layers.Dense(8, activation='relu')(encoded)
            
            # Decoder
            decoded = tf.keras.layers.Dense(16, activation='relu')(encoded)
            decoded = tf.keras.layers.Dense(input_dim, activation='linear')(decoded)
            
            # Crear modelo
            autoencoder = tf.keras.Model(input_layer, decoded)
            autoencoder.compile(optimizer='adam', loss='mse')
            
            # Entrenar
            history = autoencoder.fit(
                X_normal, X_normal,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Guardar modelo
            model_path = self.models_path / "autoencoder.h5"
            autoencoder.save(str(model_path))
            
            final_loss = history.history['loss'][-1]
            print(f"✅ Autoencoder entrenado y guardado - Loss final: {final_loss:.4f}")
            return True
            
        except ImportError:
            print("❌ TensorFlow no disponible")
            return False
        except Exception as e:
            print(f"❌ Error entrenando Autoencoder: {e}")
            return False
    
    def train_threat_classifier(self, X_data, y_labels):
        """Entrenar clasificador de amenazas"""
        print("🎯 Entrenando clasificador de amenazas...")
        
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import LabelEncoder
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, classification_report
            import joblib
            
            # Codificar etiquetas
            label_encoder = LabelEncoder()
            y_encoded = label_encoder.fit_transform(y_labels)
            
            # Dividir datos
            X_train, X_test, y_train, y_test = train_test_split(
                X_data, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
            
            # Entrenar Random Forest
            rf_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight='balanced'
            )
            rf_classifier.fit(X_train, y_train)
            
            # Evaluar
            y_pred = rf_classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Guardar modelos
            joblib.dump(rf_classifier, self.models_path / "threat_classifier.joblib")
            joblib.dump(label_encoder, self.models_path / "label_encoder.joblib")
            
            print(f"✅ Clasificador entrenado - Precisión: {accuracy*100:.1f}%")
            
            # Mostrar reporte detallado
            class_names = label_encoder.classes_
            report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
            
            print("📊 Métricas por clase:")
            for class_name in class_names:
                if class_name in report:
                    precision = report[class_name]['precision']
                    recall = report[class_name]['recall']
                    print(f"   • {class_name}: Precisión={precision:.2f}, Recall={recall:.2f}")
            
            return True
            
        except ImportError:
            print("❌ Scikit-learn no disponible")
            return False
        except Exception as e:
            print(f"❌ Error entrenando clasificador: {e}")
            return False
    
    def collect_baseline_data(self, duration_hours=1):
        """Recolectar datos baseline del sistema actual"""
        print(f"📊 Recolectando datos baseline por {duration_hours} hora(s)...")
        
        baseline_events = []
        
        try:
            import psutil
            
            # Recolectar procesos actuales como baseline
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    if proc_info['name'] and proc_info['cmdline']:
                        event = {
                            'event_id': 1,
                            'image': proc_info['name'],
                            'command_line': ' '.join(proc_info['cmdline']),
                            'time_generated': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                            'target_user': 'system_user',
                            'baseline_event': True
                        }
                        baseline_events.append(event)
                except:
                    continue
            
            print(f"✅ {len(baseline_events)} eventos baseline recolectados")
            
            # Guardar datos baseline
            baseline_file = self.base_path / "baseline_data.json"
            with open(baseline_file, 'w', encoding='utf-8') as f:
                json.dump(baseline_events, f, indent=2, ensure_ascii=False)
            
            return baseline_events
            
        except ImportError:
            print("❌ psutil no disponible para recolección baseline")
            return []
        except Exception as e:
            print(f"❌ Error recolectando baseline: {e}")
            return []
    
    def train_all_models(self):
        """Entrenar todos los modelos de IA"""
        print("🚀 INICIANDO ENTRENAMIENTO COMPLETO DE IA")
        print("=" * 60)
        
        # 1. Generar datos sintéticos
        synthetic_events, labels = self.generate_synthetic_data(2000)
        
        # 2. Recolectar datos baseline reales
        baseline_events = self.collect_baseline_data()
        
        # 3. Combinar datos
        all_events = synthetic_events + baseline_events
        all_labels = labels + ['BENIGN'] * len(baseline_events)
        
        print(f"📊 Total de datos de entrenamiento: {len(all_events)} eventos")
        
        # 4. Extraer características
        X_data = self.extract_features_for_training(all_events)
        
        # 5. Separar datos normales para Isolation Forest
        normal_indices = [i for i, label in enumerate(all_labels) if label == 'BENIGN']
        X_normal = X_data[normal_indices]
        
        print(f"📈 Características extraídas: {X_data.shape}")
        print(f"📈 Datos normales para anomaly detection: {X_normal.shape}")
        
        # 6. Entrenar modelos
        results = {
            'isolation_forest': self.train_isolation_forest(X_normal),
            'autoencoder': self.train_autoencoder(X_normal),
            'threat_classifier': self.train_threat_classifier(X_data, all_labels)
        }
        
        # 7. Guardar metadatos de entrenamiento
        training_metadata = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(all_events),
            'synthetic_events': len(synthetic_events),
            'baseline_events': len(baseline_events),
            'feature_dimensions': X_data.shape[1],
            'class_distribution': dict(zip(*np.unique(all_labels, return_counts=True))),
            'models_trained': results,
            'training_successful': all(results.values())
        }
        
        metadata_file = self.models_path / "training_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(training_metadata, f, indent=2, ensure_ascii=False)
        
        # 8. Resumen final
        print(f"\n🎯 ENTRENAMIENTO COMPLETADO:")
        print(f"=" * 40)
        for model_name, success in results.items():
            status = "✅ EXITOSO" if success else "❌ FALLÓ"
            print(f"   • {model_name}: {status}")
        
        if all(results.values()):
            print(f"\n🚀 ¡TODOS LOS MODELOS ENTRENADOS EXITOSAMENTE!")
            print(f"   • Isolation Forest: Detección de anomalías")
            print(f"   • Autoencoder: Análisis de patrones")
            print(f"   • Random Forest: Clasificación de amenazas")
            print(f"   • Modelos guardados en: {self.models_path}")
        else:
            print(f"\n⚠️ Algunos modelos fallaron - revisar logs")
        
        return training_metadata
    
    def extract_features_for_training(self, events):
        """Extraer características numéricas para entrenamiento ML"""
        feature_vectors = []
        
        for event in events:
            features = []
            
            # Características temporales (4 features)
            try:
                timestamp = datetime.fromisoformat(event['time_generated'].replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
            
            features.extend([
                timestamp.hour / 24.0,
                timestamp.weekday() / 7.0,
                float(9 <= timestamp.hour <= 17),
                float(timestamp.weekday() >= 5)
            ])
            
            # Características de proceso (6 features)
            image = event.get('image', '').lower()
            cmdline = event.get('command_line', '').lower()
            
            features.extend([
                min(len(image.split('\\')[-1]) / 50.0, 1.0),
                float(any(path in image for path in ['system32', 'windows'])),
                min(len(cmdline) / 200.0, 1.0),
                float('powershell' in cmdline),
                float('-enc' in cmdline or 'base64' in cmdline),
                min(self._calculate_entropy(cmdline) / 5.0, 1.0)
            ])
            
            # Características de riesgo (6 features)
            target_image = event.get('target_image', '').lower()
            features.extend([
                float('lsass.exe' in target_image),
                float(any(word in cmdline for word in ['sekurlsa', 'logonpasswords', 'mimikatz'])),
                float(any(cmd in cmdline for cmd in ['net user', 'whoami', 'systeminfo'])),
                float(any(path in image for path in ['temp', 'appdata'])),
                float('admin' in event.get('target_user', '').lower()),
                float(event.get('event_id') in [4697, 4698, 4625, 1102])
            ])
            
            feature_vectors.append(features)
        
        return np.array(feature_vectors, dtype=np.float32)

def main():
    """Función principal de entrenamiento"""
    print("🧠 ENTRENADOR DE IA PARA VPEW-AI")
    print("Sistema de Entrenamiento Automático")
    print("=" * 50)
    
    trainer = VPEWTrainer()
    
    print("\n📋 OPCIONES DE ENTRENAMIENTO:")
    print("1. Entrenar todos los modelos (automático)")
    print("2. Solo generar datos sintéticos")
    print("3. Solo recolectar baseline")
    print("4. Verificar modelos existentes")
    print("5. Salir")
    
    try:
        choice = input("\nSelecciona opción (1-5): ").strip()
        
        if choice == "1":
            print("\n🚀 Iniciando entrenamiento completo...")
            metadata = trainer.train_all_models()
            
            print(f"\n📄 Metadatos guardados en: {trainer.models_path / 'training_metadata.json'}")
            
        elif choice == "2":
            events, labels = trainer.generate_synthetic_data(1000)
            print(f"✅ {len(events)} eventos sintéticos generados")
            
        elif choice == "3":
            baseline = trainer.collect_baseline_data()
            print(f"✅ {len(baseline)} eventos baseline recolectados")
            
        elif choice == "4":
            models_path = trainer.models_path
            models = ['isolation_forest.joblib', 'autoencoder.h5', 'threat_classifier.joblib']
            
            print(f"\n📁 Estado de modelos en {models_path}:")
            for model in models:
                model_file = models_path / model
                if model_file.exists():
                    size = model_file.stat().st_size
                    mtime = datetime.fromtimestamp(model_file.stat().st_mtime)
                    print(f"   ✅ {model}: {size} bytes (modificado: {mtime.strftime('%Y-%m-%d %H:%M')})")
                else:
                    print(f"   ❌ {model}: No encontrado")
            
        elif choice == "5":
            print("👋 Saliendo...")
            
        else:
            print("❌ Opción inválida")
            
    except KeyboardInterrupt:
        print("\n👋 Entrenamiento interrumpido")
    except Exception as e:
        logger.error(f"Error en entrenamiento: {e}")
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
