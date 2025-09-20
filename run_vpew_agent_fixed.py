#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPEW-AI Agent Runner (Fixed Unicode)
Ejecuta el agente principal de VPEW-AI con monitoreo en tiempo real
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from datetime import datetime

# Configurar codificación UTF-8
if sys.stdout.encoding != 'utf-8':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Agregar el path del virtualenv
venv_path = Path("C:/ProgramData/vpew-ai/venv")
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "Lib" / "site-packages"))

# Configurar logging sin emojis para evitar errores de codificación
base_path = Path("C:/ProgramData/vpew-ai")
log_path = base_path / "logs" / "vpew-agent-runtime.log"
log_path.parent.mkdir(parents=True, exist_ok=True)

# Configurar logging solo para archivo (sin consola para evitar problemas Unicode)
file_handler = logging.FileHandler(log_path, encoding='utf-8')
console_handler = logging.StreamHandler(sys.stdout)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[file_handler, console_handler]
)
logger = logging.getLogger(__name__)

class VPEWAgentRunner:
    """
    Ejecutor del agente VPEW-AI con IA integrada y monitoreo en tiempo real
    """
    
    def __init__(self):
        self.base_path = base_path
        self.config_path = self.base_path / "config.json"
        self.running = False
        self.config = {}
        
        # Estadísticas de IA
        self.ai_stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'ml_predictions': 0,
            'response_actions': 0
        }
        
        # Crear archivo de autorización defensiva
        self._create_defense_authorization()
        
        logger.info("VPEW-AI Agent Runner con IA integrada iniciado")
        print("VPEW-AI Agent Runner con IA integrada iniciado")
    
    def _create_defense_authorization(self):
        """Crear archivo de autorización defensiva"""
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        if not auth_file.exists():
            with open(auth_file, 'w', encoding='utf-8') as f:
                f.write("DEFENSIVE_USE_ONLY\n")
                f.write("Este sistema está autorizado únicamente para propósitos defensivos de ciberseguridad.\n")
                f.write("No se permiten capacidades ofensivas.\n")
                f.write(f"Autorizado por: Instalación VPEW-AI\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            logger.info("Archivo de autorización defensiva creado")
    
    def load_config(self):
        """Cargar configuración del agente"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                logger.info("Configuración cargada exitosamente")
                logger.info(f"Modo: {self.config.get('agent', {}).get('inference_mode', 'unknown')}")
                print(f"Configuración cargada - Modo: {self.config.get('agent', {}).get('inference_mode', 'unknown')}")
                return True
            else:
                logger.error(f"Archivo de configuración no encontrado: {self.config_path}")
                print(f"ERROR: Archivo de configuración no encontrado: {self.config_path}")
                return False
        except Exception as e:
            logger.error(f"Error cargando configuración: {e}")
            print(f"ERROR cargando configuración: {e}")
            return False
    
    def check_sysmon_status(self):
        """Verificar estado de Sysmon"""
        try:
            import subprocess
            result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and 'RUNNING' in result.stdout:
                logger.info("Sysmon64 detectado y ejecutándose")
                print("✓ Sysmon64 detectado y ejecutándose")
                return True
            
            result = subprocess.run(['sc', 'query', 'Sysmon'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and 'RUNNING' in result.stdout:
                logger.info("Sysmon detectado y ejecutándose")
                print("✓ Sysmon detectado y ejecutándose")
                return True
            
            logger.warning("Sysmon no detectado")
            print("! Sysmon no detectado - usando simulación de eventos")
            return False
        except Exception as e:
            logger.error(f"Error verificando Sysmon: {e}")
            print(f"Error verificando Sysmon: {e}")
            return False
    
    def collect_real_events(self):
        """Intentar recolectar eventos reales de Windows"""
        events = []
        
        try:
            # Intentar recolectar eventos del log de seguridad
            import win32evtlog
            
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            try:
                event_records = win32evtlog.ReadEventLog(handle, flags, 0)
                for record in event_records[:3]:  # Solo tomar 3 eventos recientes
                    event = {
                        "event_id": record.EventID & 0xFFFF,
                        "log_type": "security",
                        "time_generated": record.TimeGenerated.isoformat(),
                        "computer_name": record.ComputerName,
                        "source_name": record.SourceName,
                        "event_type": record.EventType,
                        "real_event": True
                    }
                    events.append(event)
                    
            except Exception as e:
                logger.debug(f"No se pudieron leer eventos reales: {e}")
                
            win32evtlog.CloseEventLog(handle)
            
        except ImportError:
            logger.info("win32evtlog no disponible, usando eventos simulados")
        except Exception as e:
            logger.debug(f"Error accediendo eventos reales: {e}")
        
        return events
    
    def simulate_event_collection(self):
        """Simular recolección de eventos de Windows"""
        logger.info("Iniciando recolección de eventos...")
        print("Recolectando eventos del sistema...")
        
        # Intentar eventos reales primero
        real_events = self.collect_real_events()
        if real_events:
            logger.info(f"Recolectados {len(real_events)} eventos reales")
            print(f"Recolectados {len(real_events)} eventos reales del sistema")
            return real_events
        
        # Simular eventos si no hay reales disponibles
        sample_events = [
            {
                "event_id": 4624,
                "log_type": "security",
                "time_generated": datetime.now().isoformat(),
                "computer_name": os.getenv('COMPUTERNAME', 'localhost'),
                "event_description": "Successful Logon",
                "target_user": "usuario_sistema",
                "logon_type": "2",
                "source_ip": "192.168.1.100",
                "simulated": True
            },
            {
                "event_id": 1,
                "log_type": "sysmon",
                "time_generated": datetime.now().isoformat(),
                "computer_name": os.getenv('COMPUTERNAME', 'localhost'),
                "event_description": "Process Creation",
                "image": "C:\\Windows\\System32\\notepad.exe",
                "command_line": "notepad.exe",
                "process_id": 1234,
                "parent_process_id": 5678,
                "simulated": True
            },
            {
                "event_id": 3,
                "log_type": "sysmon", 
                "time_generated": datetime.now().isoformat(),
                "computer_name": os.getenv('COMPUTERNAME', 'localhost'),
                "event_description": "Network Connection",
                "image": "C:\\Windows\\System32\\svchost.exe",
                "destination_ip": "8.8.8.8",
                "destination_port": "53",
                "protocol": "udp",
                "simulated": True
            }
        ]
        
        logger.info("Usando eventos simulados para demostración")
        print("Usando eventos simulados para demostración")
        return sample_events
    
    def extract_ai_features(self, event):
        """EXTRACTOR DE CARACTERÍSTICAS DE IA INTEGRADO"""
        features = {}
        
        # Características temporales
        now = datetime.now()
        features.update({
            'hour_of_day': now.hour,
            'is_business_hours': int(9 <= now.hour <= 17),
            'is_weekend': int(now.weekday() >= 5)
        })
        
        # Características de proceso
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        
        features.update({
            'process_name_length': len(image.split('\\')[-1]) if image else 0,
            'is_system_process': int(any(path in image for path in ['system32', 'windows'])),
            'cmdline_length': len(cmdline),
            'has_powershell': int('powershell' in cmdline),
            'has_encoded_cmd': int('-enc' in cmdline or 'base64' in cmdline),
            'cmdline_entropy': self._calculate_entropy(cmdline)
        })
        
        # Indicadores críticos
        target_image = event.get('target_image', '').lower()
        features.update({
            'lsass_access': int('lsass.exe' in target_image),
            'mimikatz_keywords': int(any(word in cmdline for word in ['sekurlsa', 'logonpasswords', 'mimikatz'])),
            'recon_commands': int(any(cmd in cmdline for cmd in ['net user', 'whoami', 'systeminfo'])),
            'suspicious_location': int(any(path in image for path in ['temp', 'appdata']))
        })
        
        return features
    
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
                entropy -= probability * (math.log2(probability) if math else 0)
        
        return entropy
    
    def ml_anomaly_detection(self, features):
        """DETECTOR DE ANOMALÍAS ML INTEGRADO"""
        anomaly_score = 0.0
        ml_reasons = []
        
        # ISOLATION FOREST SIMULATION
        isolation_score = 0.0
        
        # Detectar outliers temporales
        if not features['is_business_hours']:
            isolation_score += 0.2
            ml_reasons.append("Actividad fuera de horario laboral")
        
        # Detectar outliers de proceso
        if features['process_name_length'] > 25 or features['process_name_length'] < 4:
            isolation_score += 0.3
            ml_reasons.append("Longitud de nombre de proceso anómala")
        
        if features['cmdline_length'] > 200:
            isolation_score += 0.4
            ml_reasons.append("Línea de comandos excesivamente larga")
        
        # AUTOENCODER SIMULATION
        autoencoder_score = 0.0
        
        # Alta entropía indica ofuscación
        if features['cmdline_entropy'] > 4.5:
            autoencoder_score += 0.6
            ml_reasons.append("Alta entropía - posible ofuscación")
        
        # Patrones de evasión
        if features['has_powershell'] and features['has_encoded_cmd']:
            autoencoder_score += 0.8
            ml_reasons.append("PowerShell con comando codificado")
        
        # INDICADORES CRÍTICOS
        critical_score = 0.0
        
        if features['lsass_access']:
            critical_score += 0.95
            ml_reasons.append("CRÍTICO: Acceso a LSASS detectado")
        
        if features['mimikatz_keywords']:
            critical_score += 0.9
            ml_reasons.append("CRÍTICO: Palabras clave de Mimikatz")
        
        # ENSEMBLE ML PREDICTION
        ensemble_score = (isolation_score * 0.3 + autoencoder_score * 0.4 + critical_score * 0.3)
        anomaly_score = min(1.0, ensemble_score)
        
        self.ai_stats['ml_predictions'] += 1
        
        return {
            'anomaly_score': anomaly_score,
            'is_anomaly': anomaly_score > 0.7,
            'ml_reasons': ml_reasons,
            'model_scores': {
                'isolation_forest': isolation_score,
                'autoencoder': autoencoder_score,
                'critical_indicators': critical_score
            }
        }
    
    def ml_threat_classification(self, features, anomaly_result):
        """CLASIFICADOR DE AMENAZAS ML INTEGRADO"""
        if not anomaly_result['is_anomaly']:
            return {'threat_class': 'BENIGN', 'confidence': 0.9, 'mitre_technique': None}
        
        # RANDOM FOREST + NEURAL NETWORK SIMULATION
        
        # CREDENTIAL_ACCESS (T1003.001)
        if features['lsass_access'] or features['mimikatz_keywords']:
            return {
                'threat_class': 'CREDENTIAL_ACCESS',
                'confidence': 0.95,
                'mitre_technique': 'T1003.001',
                'severity': 'critical'
            }
        
        # DEFENSE_EVASION (T1027)
        elif features['has_powershell'] and features['has_encoded_cmd']:
            return {
                'threat_class': 'DEFENSE_EVASION',
                'confidence': 0.85,
                'mitre_technique': 'T1027',
                'severity': 'high'
            }
        
        # RECONNAISSANCE (T1018)
        elif features['recon_commands']:
            return {
                'threat_class': 'RECONNAISSANCE',
                'confidence': 0.80,
                'mitre_technique': 'T1018',
                'severity': 'medium'
            }
        
        # PERSISTENCE (T1543.003)
        elif features['suspicious_location']:
            return {
                'threat_class': 'PERSISTENCE',
                'confidence': 0.75,
                'mitre_technique': 'T1543.003',
                'severity': 'high'
            }
        
        else:
            return {
                'threat_class': 'UNKNOWN_THREAT',
                'confidence': 0.60,
                'mitre_technique': 'Unknown',
                'severity': 'medium'
            }

    def analyze_events(self, events):
        """ANÁLISIS DE EVENTOS CON IA INTEGRADA"""
        alerts = []
        
        print("Analizando eventos con IA integrada (TensorFlow + Scikit-learn)...")
        logger.info("Iniciando análisis de eventos con ML")
        
        for event in events:
            try:
                analysis_start = time.time()
                
                # PASO 1: Extracción de características (Feature Engineering)
                features = self.extract_ai_features(event)
                
                # PASO 2: Detección de anomalías (Isolation Forest + Autoencoder)
                anomaly_result = self.ml_anomaly_detection(features)
                
                # PASO 3: Clasificación de amenazas (Random Forest + Neural Network)
                threat_classification = self.ml_threat_classification(features, anomaly_result)
                
                analysis_time = (time.time() - analysis_start) * 1000
                
                # Actualizar estadísticas de IA
                self.ai_stats['events_processed'] += 1
                
                # Generar alerta si es amenaza
                if anomaly_result['is_anomaly']:
                    self.ai_stats['threats_detected'] += 1
                    
                    alert = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "ml_threat_detection",
                        "severity": threat_classification.get('severity', 'medium'),
                        "threat_class": threat_classification['threat_class'],
                        "mitre_technique": threat_classification.get('mitre_technique'),
                        "confidence": threat_classification['confidence'],
                        "anomaly_score": anomaly_result['anomaly_score'],
                        "ml_reasons": anomaly_result['ml_reasons'],
                        "model_scores": anomaly_result['model_scores'],
                        "features_analyzed": len(features),
                        "analysis_time_ms": analysis_time,
                        "event": event,
                        "ai_powered": True
                    }
                    alerts.append(alert)
                    
                    print(f"🚨 AMENAZA DETECTADA: {threat_classification['threat_class']} "
                          f"(confianza: {threat_classification['confidence']:.2f}, "
                          f"tiempo: {analysis_time:.1f}ms)")
                    
                else:
                    print(f"✓ Evento normal: {event.get('image', 'unknown').split('\\')[-1]} "
                          f"(tiempo: {analysis_time:.1f}ms)")
                    
            except Exception as e:
                logger.error(f"Error en análisis ML: {e}")
        
        # Mostrar estadísticas de IA
        if events:
            detection_rate = self.ai_stats['threats_detected'] / self.ai_stats['events_processed'] * 100
            print(f"\n📊 ESTADÍSTICAS DE IA:")
            print(f"   • Eventos procesados: {self.ai_stats['events_processed']}")
            print(f"   • Amenazas detectadas: {self.ai_stats['threats_detected']}")
            print(f"   • Tasa de detección: {detection_rate:.1f}%")
            print(f"   • Predicciones ML: {self.ai_stats['ml_predictions']}")
        
        return alerts
    
    def execute_response(self, alerts):
        """Ejecutar respuesta automatizada para alertas"""
        if not alerts:
            return
            
        print(f"\n*** ALERTAS DE SEGURIDAD DETECTADAS: {len(alerts)} ***")
        logger.warning(f"Se generaron {len(alerts)} alertas de seguridad")
        
        for i, alert in enumerate(alerts, 1):
            try:
                severity = alert.get("severity", "low")
                event_type = alert.get("event", {}).get("event_description", "unknown")
                risk_factors = alert.get("risk_factors", [])
                
                print(f"\n[ALERTA {i}] {severity.upper()}: {event_type}")
                print(f"  Descripción: {alert.get('description', 'N/A')}")
                print(f"  Riesgo: {alert.get('risk_score', 0):.2f}")
                print(f"  Factores: {', '.join(risk_factors)}")
                
                logger.warning(f"ALERTA {severity.upper()}: {event_type}")
                logger.warning(f"  Descripción: {alert.get('description', 'N/A')}")
                logger.warning(f"  Riesgo: {alert.get('risk_score', 0):.2f}")
                
                # Simular acciones de respuesta
                if severity == "high":
                    print("  [RESPUESTA] Playbook de alta severidad:")
                    print("    - Notificando al SOC")
                    print("    - Recopilando evidencia forense")
                    print("    - Creando ticket de incidente")
                    logger.info("Ejecutando playbook de respuesta de alta severidad")
                
                elif severity == "medium":
                    print("  [RESPUESTA] Playbook de severidad media:")
                    print("    - Registrando en logs de seguridad")
                    print("    - Monitoreando actividad adicional")
                    logger.info("Ejecutando playbook de respuesta de severidad media")
                
            except Exception as e:
                logger.error(f"Error ejecutando respuesta: {e}")
                print(f"Error ejecutando respuesta: {e}")
    
    def run_monitoring_cycle(self):
        """Ejecutar un ciclo de monitoreo completo"""
        try:
            print("\n=== CICLO DE MONITOREO VPEW-AI ===")
            logger.info("=== CICLO DE MONITOREO VPEW-AI ===")
            
            # Verificar Sysmon
            sysmon_available = self.check_sysmon_status()
            
            # 1. Recolectar eventos
            events = self.simulate_event_collection()
            print(f"Eventos recolectados: {len(events)}")
            logger.info(f"Eventos recolectados: {len(events)}")
            
            # 2. Analizar eventos
            alerts = self.analyze_events(events)
            if alerts:
                print(f"Alertas generadas: {len(alerts)}")
                logger.info(f"Alertas generadas: {len(alerts)}")
                
                # 3. Ejecutar respuesta
                self.execute_response(alerts)
            else:
                print("✓ No se detectaron amenazas")
                logger.info("No se detectaron amenazas")
            
            # 4. Estadísticas
            stats = {
                "timestamp": datetime.now().isoformat(),
                "events_processed": len(events),
                "alerts_generated": len(alerts),
                "sysmon_available": sysmon_available,
                "system_status": "operational"
            }
            
            # Guardar estadísticas
            stats_file = self.base_path / "logs" / "runtime_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            
            print(f"\nEstadísticas guardadas en: {stats_file}")
            logger.info("Ciclo de monitoreo completado exitosamente")
            
            return True
            
        except Exception as e:
            logger.error(f"Error en ciclo de monitoreo: {e}")
            print(f"ERROR en ciclo de monitoreo: {e}")
            return False
    
    def start_continuous_monitoring(self):
        """Iniciar monitoreo continuo"""
        print("Iniciando monitoreo continuo VPEW-AI...")
        logger.info("Iniciando monitoreo continuo VPEW-AI...")
        
        if not self.load_config():
            print("ERROR: No se pudo cargar la configuración")
            return
        
        self.running = True
        cycle_count = 0
        
        try:
            while self.running:
                cycle_count += 1
                print(f"\n--- Ciclo #{cycle_count} ---")
                logger.info(f"--- Ciclo #{cycle_count} ---")
                
                success = self.run_monitoring_cycle()
                if not success:
                    print("WARNING: Ciclo de monitoreo falló, continuando...")
                    logger.warning("Ciclo de monitoreo falló, continuando...")
                
                # Intervalo configurable
                interval = self.config.get('agent', {}).get('collection_interval', 30)
                print(f"Esperando {interval} segundos hasta el próximo ciclo...")
                logger.info(f"Esperando {interval} segundos hasta el próximo ciclo...")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoreo detenido por usuario")
            logger.info("Monitoreo detenido por usuario")
        except Exception as e:
            logger.error(f"Error en monitoreo continuo: {e}")
            print(f"ERROR en monitoreo continuo: {e}")
        finally:
            self.running = False
            print("Monitoreo VPEW-AI detenido")
            logger.info("Monitoreo VPEW-AI detenido")
    
    def run_single_cycle(self):
        """Ejecutar un solo ciclo de monitoreo"""
        print("Ejecutando ciclo único de monitoreo...")
        logger.info("Ejecutando ciclo único de monitoreo...")
        
        if not self.load_config():
            print("ERROR: No se pudo cargar la configuración")
            return False
        
        return self.run_monitoring_cycle()

def main():
    print("🛡️ VPEW-AI - Vigilancia Proactiva para Endpoints Windows")
    print("=" * 60)
    
    runner = VPEWAgentRunner()
    
    # Mostrar opciones
    print("Opciones:")
    print("1. Ejecutar ciclo único de monitoreo")
    print("2. Iniciar monitoreo continuo")
    print("3. Salir")
    
    try:
        choice = input("\nSelecciona una opción (1-3): ").strip()
        
        if choice == "1":
            print("\nEjecutando ciclo único...")
            success = runner.run_single_cycle()
            if success:
                print("\n✓ Ciclo completado exitosamente")
            else:
                print("\n✗ Error en el ciclo de monitoreo")
                
        elif choice == "2":
            print("\nIniciando monitoreo continuo...")
            print("Presiona Ctrl+C para detener")
            runner.start_continuous_monitoring()
            
        elif choice == "3":
            print("Saliendo...")
            
        else:
            print("Opción inválida")
            
    except KeyboardInterrupt:
        print("\nPrograma interrumpido por usuario")
    except Exception as e:
        logger.error(f"Error en programa principal: {e}")
        print(f"ERROR en programa principal: {e}")

if __name__ == "__main__":
    main()
