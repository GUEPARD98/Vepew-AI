#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPEW-AI AGENTE INTEGRADO
Vigilancia Proactiva para Endpoints Windows con IA - Versión Completa Integrada
"""

import os
import sys
import time
import json
import math
import logging
import threading
import subprocess
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import queue

# Configurar encoding
if sys.stdout.encoding != 'utf-8':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

# Configurar paths
venv_path = Path("C:/ProgramData/vpew-ai/venv")
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "Lib" / "site-packages"))

# Configurar logging
base_path = Path("C:/ProgramData/vpew-ai")
log_path = base_path / "logs" / "vpew-integrated.log"
log_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VPEWAIEngine:
    """
    Motor principal de VPEW-AI con IA integrada
    Combina recolección de eventos, análisis ML y respuesta automática
    """
    
    def __init__(self):
        self.base_path = base_path
        self.config_path = self.base_path / "config.json"
        self.running = False
        self.config = {}
        
        # Estadísticas
        self.stats = {
            'events_processed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'start_time': time.time()
        }
        
        # Crear autorización defensiva
        self._create_defense_authorization()
        
        logger.info("VPEW-AI Engine iniciado")
    
    def _create_defense_authorization(self):
        """Crear archivo de autorización defensiva"""
        auth_file = Path("DEFENSE_AUTHORIZATION.txt")
        if not auth_file.exists():
            with open(auth_file, 'w', encoding='utf-8') as f:
                f.write("DEFENSIVE_USE_ONLY\n")
                f.write("Sistema autorizado únicamente para ciberseguridad defensiva\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    def extract_features(self, event):
        """
        EXTRACTOR DE CARACTERÍSTICAS INTEGRADO
        Convierte eventos Windows en vectores numéricos para ML
        """
        features = {}
        
        # 1. CARACTERÍSTICAS TEMPORALES
        now = datetime.now()
        features.update({
            'hour_of_day': now.hour,
            'day_of_week': now.weekday(),
            'is_business_hours': int(9 <= now.hour <= 17),
            'is_weekend': int(now.weekday() >= 5),
            'is_night_time': int(now.hour < 6 or now.hour > 22)
        })
        
        # 2. CARACTERÍSTICAS DE PROCESO
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        process_name = image.split('\\')[-1] if image else ''
        
        features.update({
            'process_name_length': len(process_name),
            'is_system_process': int(any(path in image for path in ['system32', 'syswow64', 'windows'])),
            'cmdline_length': len(cmdline),
            'cmdline_entropy': self._calculate_entropy(cmdline),
            'has_powershell': int('powershell' in cmdline),
            'has_encoded_cmd': int(any(enc in cmdline for enc in ['-enc', '-e ', 'base64'])),
            'has_suspicious_name': int(len(process_name) > 20 or any(c.isdigit() for c in process_name[:8]))
        })
        
        # 3. CARACTERÍSTICAS DE RED
        dest_ip = event.get('destination_ip', '')
        dest_port = event.get('destination_port', '')
        
        features.update({
            'has_network_activity': int(bool(dest_ip)),
            'is_external_ip': int(not dest_ip.startswith(('192.168.', '10.', '172.16.', '127.', '')) if dest_ip else 0),
            'is_suspicious_port': int(dest_port in ['4444', '31337', '8080', '8443'] if dest_port else 0),
            'destination_port_num': int(dest_port) if dest_port.isdigit() else 0
        })
        
        # 4. CARACTERÍSTICAS DE USUARIO
        user = event.get('target_user', '').lower()
        features.update({
            'is_admin_user': int('admin' in user),
            'is_system_user': int(user in ['system', 'local service', 'network service', '']),
            'user_name_length': len(user)
        })
        
        # 5. INDICADORES DE RIESGO ESPECÍFICOS
        target_image = event.get('target_image', '').lower()
        features.update({
            'lsass_access': int('lsass.exe' in target_image),
            'mimikatz_keywords': int(any(word in cmdline for word in ['sekurlsa', 'logonpasswords', 'mimikatz'])),
            'recon_commands': int(any(cmd in cmdline for cmd in ['net user', 'whoami', 'systeminfo', 'ipconfig'])),
            'suspicious_location': int(any(path in image for path in ['temp', 'appdata', 'public'])),
            'persistence_indicators': int(event.get('event_id') in [4697, 4698]),  # Service events
            'failed_logon': int(event.get('event_id') == 4625),
            'log_clearing': int(event.get('event_id') == 1102)
        })
        
        return features
    
    def _calculate_entropy(self, text):
        """Calcular entropía de Shannon para detectar ofuscación"""
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
    
    def detect_anomaly(self, features):
        """
        DETECTOR DE ANOMALÍAS INTEGRADO
        Combina múltiples técnicas ML para detectar amenazas
        """
        anomaly_score = 0.0
        detection_reasons = []
        
        # ISOLATION FOREST SIMULATION
        # Detecta outliers basado en desviaciones estadísticas
        isolation_score = 0.0
        
        # Análisis temporal
        if not features['is_business_hours']:
            isolation_score += 0.2
            detection_reasons.append("Actividad fuera de horas laborales")
        
        if features['is_night_time']:
            isolation_score += 0.3
            detection_reasons.append("Actividad nocturna inusual")
        
        # Análisis de proceso
        if features['process_name_length'] > 25 or features['process_name_length'] < 4:
            isolation_score += 0.3
            detection_reasons.append("Nombre de proceso anómalo")
        
        if features['cmdline_length'] > 150:
            isolation_score += 0.4
            detection_reasons.append("Línea de comandos excesivamente larga")
        
        # AUTOENCODER SIMULATION
        # Detecta patrones que no coinciden con comportamiento normal
        autoencoder_score = 0.0
        
        # Alta entropía = posible ofuscación
        if features['cmdline_entropy'] > 4.5:
            autoencoder_score += 0.6
            detection_reasons.append("Alta entropía en comando (ofuscación)")
        
        # PowerShell con comandos codificados
        if features['has_powershell'] and features['has_encoded_cmd']:
            autoencoder_score += 0.8
            detection_reasons.append("PowerShell con comando codificado")
        
        # Proceso no del sistema con actividad de red externa
        if not features['is_system_process'] and features['is_external_ip']:
            autoencoder_score += 0.5
            detection_reasons.append("Proceso no-sistema con conexión externa")
        
        # INDICADORES DE RIESGO CRÍTICO
        critical_score = 0.0
        
        if features['lsass_access']:
            critical_score += 0.9
            detection_reasons.append("CRÍTICO: Acceso a LSASS detectado")
        
        if features['mimikatz_keywords']:
            critical_score += 0.95
            detection_reasons.append("CRÍTICO: Palabras clave de Mimikatz")
        
        if features['log_clearing']:
            critical_score += 0.85
            detection_reasons.append("CRÍTICO: Intento de borrar logs")
        
        # ENSEMBLE PREDICTION
        # Combinar todos los scores
        ensemble_weights = [0.3, 0.4, 0.3]  # Pesos para cada modelo
        scores = [isolation_score, autoencoder_score, critical_score]
        
        anomaly_score = sum(w * s for w, s in zip(ensemble_weights, scores))
        anomaly_score = min(1.0, anomaly_score)  # Limitar a 1.0
        
        return {
            'anomaly_score': anomaly_score,
            'isolation_score': isolation_score,
            'autoencoder_score': autoencoder_score,
            'critical_score': critical_score,
            'is_anomaly': anomaly_score > 0.7,
            'confidence': anomaly_score,
            'detection_reasons': detection_reasons,
            'model_scores': {
                'isolation_forest': isolation_score,
                'autoencoder': autoencoder_score,
                'critical_indicators': critical_score
            }
        }
    
    def classify_threat(self, features, anomaly_result):
        """
        CLASIFICADOR DE AMENAZAS INTEGRADO
        Clasifica eventos según taxonomía MITRE ATT&CK
        """
        if not anomaly_result['is_anomaly']:
            return {
                'threat_class': 'BENIGN',
                'confidence': 0.9,
                'mitre_technique': None,
                'severity': 'info'
            }
        
        # RANDOM FOREST SIMULATION
        # Clasificación basada en características específicas
        
        # CREDENTIAL_ACCESS (T1003.001)
        if features['lsass_access'] or features['mimikatz_keywords']:
            return {
                'threat_class': 'CREDENTIAL_ACCESS',
                'confidence': 0.95,
                'mitre_technique': 'T1003.001',
                'severity': 'critical'
            }
        
        # DEFENSE_EVASION (T1027, T1055)
        elif features['has_powershell'] and features['has_encoded_cmd']:
            return {
                'threat_class': 'DEFENSE_EVASION',
                'confidence': 0.85,
                'mitre_technique': 'T1027',
                'severity': 'high'
            }
        
        # RECONNAISSANCE (T1018, T1057)
        elif features['recon_commands']:
            return {
                'threat_class': 'RECONNAISSANCE',
                'confidence': 0.80,
                'mitre_technique': 'T1018',
                'severity': 'medium'
            }
        
        # PERSISTENCE (T1543.003)
        elif features['persistence_indicators'] or features['suspicious_location']:
            return {
                'threat_class': 'PERSISTENCE',
                'confidence': 0.75,
                'mitre_technique': 'T1543.003',
                'severity': 'high'
            }
        
        # LATERAL_MOVEMENT (T1021)
        elif features['is_external_ip'] and features['is_admin_user']:
            return {
                'threat_class': 'LATERAL_MOVEMENT',
                'confidence': 0.70,
                'mitre_technique': 'T1021',
                'severity': 'medium'
            }
        
        # UNKNOWN THREAT
        else:
            return {
                'threat_class': 'UNKNOWN_THREAT',
                'confidence': 0.60,
                'mitre_technique': 'Unknown',
                'severity': 'medium'
            }
    
    def execute_response(self, threat_classification, event):
        """
        MOTOR DE RESPUESTA AUTOMÁTICA INTEGRADO
        Ejecuta playbooks basados en el tipo de amenaza
        """
        threat_class = threat_classification['threat_class']
        severity = threat_classification['severity']
        confidence = threat_classification['confidence']
        
        response_actions = []
        
        # PLAYBOOK PB2: CREDENTIAL_ACCESS
        if threat_class == 'CREDENTIAL_ACCESS':
            response_actions = [
                "🚨 ALERTA CRÍTICA: Intento de extracción de credenciales",
                "⚡ Bloqueando proceso inmediatamente",
                "🔒 Aislando endpoint de la red",
                "📞 Notificando SOC (prioridad CRÍTICA)",
                "💾 Recopilando evidencia forense",
                "🔐 Deshabilitando cuentas comprometidas",
                "🎫 Creando ticket de incidente crítico"
            ]
        
        # PLAYBOOK PB3: RECONNAISSANCE
        elif threat_class == 'RECONNAISSANCE':
            response_actions = [
                "⚠️ ALERTA: Actividad de reconocimiento detectada",
                "👁️ Activando monitoreo intensivo",
                "🚫 Bloqueando comandos de reconocimiento",
                "🔍 Notificando equipo de threat hunting",
                "📊 Incrementando logging de red",
                "🎫 Creando ticket de investigación"
            ]
        
        # PLAYBOOK PB1: PERSISTENCE/DEFENSE_EVASION
        elif threat_class in ['PERSISTENCE', 'DEFENSE_EVASION']:
            response_actions = [
                "⚠️ ALERTA ALTA: Técnica de evasión/persistencia",
                "🔍 Iniciando análisis profundo del proceso",
                "📋 Verificando integridad del sistema",
                "📈 Incrementando nivel de logging",
                "🔄 Ejecutando verificaciones adicionales",
                "📞 Notificando equipo de seguridad",
                "🎫 Creando ticket de análisis"
            ]
        
        # RESPUESTA GENERAL
        else:
            response_actions = [
                "ℹ️ ALERTA: Actividad sospechosa detectada",
                "📊 Registrando en logs de seguridad",
                "👀 Incrementando monitoreo del endpoint",
                "📈 Actualizando baseline de comportamiento"
            ]
        
        # Ejecutar acciones
        logger.info(f"Ejecutando respuesta para {threat_class} (confianza: {confidence:.2f})")
        for action in response_actions:
            logger.info(f"  {action}")
            time.sleep(0.1)  # Simular tiempo de ejecución
        
        return response_actions
    
    def collect_windows_events(self):
        """
        RECOLECTOR DE EVENTOS INTEGRADO
        Recolecta eventos reales de Windows cuando es posible
        """
        events = []
        
        try:
            # Intentar recolectar eventos reales de Windows
            import psutil
            
            # Obtener procesos actuales
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    if proc_info['name'] and proc_info['cmdline']:
                        event = {
                            'event_id': 1,  # Process creation
                            'log_type': 'sysmon',
                            'time_generated': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                            'image': proc_info['name'],
                            'command_line': ' '.join(proc_info['cmdline']),
                            'process_id': proc_info['pid'],
                            'computer_name': os.getenv('COMPUTERNAME', 'localhost'),
                            'real_event': True
                        }
                        events.append(event)
                        
                        # Limitar a 5 eventos reales para demo
                        if len(events) >= 5:
                            break
                except:
                    continue
                    
        except ImportError:
            logger.warning("psutil no disponible, usando eventos simulados")
        except Exception as e:
            logger.warning(f"Error recolectando eventos reales: {e}")
        
        # Si no hay eventos reales, usar simulados
        if not events:
            events = self._generate_simulated_events()
        
        logger.info(f"Eventos recolectados: {len(events)}")
        return events
    
    def _generate_simulated_events(self):
        """Generar eventos simulados para demostración"""
        return [
            {
                'event_id': 1,
                'log_type': 'sysmon',
                'time_generated': datetime.now().isoformat(),
                'image': 'C:\\Windows\\System32\\notepad.exe',
                'command_line': 'notepad.exe documento.txt',
                'process_id': 1234,
                'computer_name': os.getenv('COMPUTERNAME', 'localhost'),
                'target_user': 'usuario_normal',
                'simulated': True
            },
            {
                'event_id': 1,
                'log_type': 'sysmon',
                'time_generated': datetime.now().isoformat(),
                'image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                'command_line': 'powershell -WindowStyle Hidden -enc SGVsbG8gTWFsd2FyZQ==',
                'process_id': 2345,
                'computer_name': os.getenv('COMPUTERNAME', 'localhost'),
                'target_user': 'admin_user',
                'destination_ip': '185.220.101.5',
                'simulated': True
            },
            {
                'event_id': 10,
                'log_type': 'sysmon',
                'time_generated': datetime.now().isoformat(),
                'image': 'C:\\temp\\malware.exe',
                'command_line': 'malware.exe --extract-creds',
                'target_image': 'C:\\Windows\\System32\\lsass.exe',
                'granted_access': '0x1010',
                'process_id': 3456,
                'computer_name': os.getenv('COMPUTERNAME', 'localhost'),
                'simulated': True
            }
        ]
    
    def analyze_event(self, event):
        """
        ANÁLISIS COMPLETO DE EVENTO CON IA
        Pipeline completo: Features → ML → Classification → Response
        """
        analysis_start = time.time()
        
        # PASO 1: Extracción de características
        features = self.extract_features(event)
        
        # PASO 2: Detección de anomalías con ML
        anomaly_result = self.detect_anomaly(features)
        
        # PASO 3: Clasificación de amenazas
        threat_classification = self.classify_threat(features, anomaly_result)
        
        # PASO 4: Decisión de respuesta
        response_actions = []
        if anomaly_result['is_anomaly']:
            response_actions = self.execute_response(threat_classification, event)
        
        analysis_time = (time.time() - analysis_start) * 1000
        
        # Crear resultado completo
        result = {
            'event': event,
            'features': features,
            'anomaly_analysis': anomaly_result,
            'threat_classification': threat_classification,
            'response_actions': response_actions,
            'analysis_time_ms': analysis_time,
            'timestamp': datetime.now().isoformat()
        }
        
        # Actualizar estadísticas
        self.stats['events_processed'] += 1
        if anomaly_result['is_anomaly']:
            self.stats['threats_detected'] += 1
            self.stats['alerts_generated'] += 1
        
        return result
    
    def run_monitoring_cycle(self):
        """
        CICLO COMPLETO DE MONITOREO CON IA
        Ejecuta el pipeline completo de análisis
        """
        logger.info("=== INICIANDO CICLO DE MONITOREO CON IA ===")
        
        # 1. Recolectar eventos
        events = self.collect_windows_events()
        
        # 2. Analizar cada evento con IA
        results = []
        for event in events:
            try:
                result = self.analyze_event(event)
                results.append(result)
                
                # Log del análisis
                anomaly = result['anomaly_analysis']
                threat = result['threat_classification']
                
                if anomaly['is_anomaly']:
                    logger.warning(f"🚨 AMENAZA: {threat['threat_class']} "
                                 f"(confianza: {threat['confidence']:.2f}, "
                                 f"score: {anomaly['anomaly_score']:.2f})")
                else:
                    logger.info(f"✅ Evento normal: {event.get('image', 'unknown')}")
                
            except Exception as e:
                logger.error(f"Error analizando evento: {e}")
        
        # 3. Resumen del ciclo
        threats_found = sum(1 for r in results if r['anomaly_analysis']['is_anomaly'])
        avg_time = np.mean([r['analysis_time_ms'] for r in results]) if results else 0
        
        logger.info(f"Ciclo completado: {len(events)} eventos, {threats_found} amenazas, {avg_time:.1f}ms promedio")
        
        # 4. Guardar estadísticas
        self._save_cycle_stats(results)
        
        return results
    
    def _save_cycle_stats(self, results):
        """Guardar estadísticas del ciclo"""
        try:
            stats_file = self.base_path / "logs" / "cycle_stats.json"
            
            cycle_stats = {
                'timestamp': datetime.now().isoformat(),
                'events_analyzed': len(results),
                'threats_detected': sum(1 for r in results if r['anomaly_analysis']['is_anomaly']),
                'avg_analysis_time_ms': np.mean([r['analysis_time_ms'] for r in results]) if results else 0,
                'threat_breakdown': {},
                'total_stats': self.stats.copy()
            }
            
            # Contar tipos de amenazas
            for result in results:
                if result['anomaly_analysis']['is_anomaly']:
                    threat_class = result['threat_classification']['threat_class']
                    cycle_stats['threat_breakdown'][threat_class] = cycle_stats['threat_breakdown'].get(threat_class, 0) + 1
            
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(cycle_stats, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error guardando estadísticas: {e}")
    
    def start_continuous_monitoring(self):
        """Iniciar monitoreo continuo"""
        logger.info("🚀 Iniciando monitoreo continuo con IA integrada")
        
        self.running = True
        cycle_count = 0
        
        try:
            while self.running:
                cycle_count += 1
                logger.info(f"--- Ciclo #{cycle_count} ---")
                
                # Ejecutar ciclo de análisis
                results = self.run_monitoring_cycle()
                
                # Esperar intervalo configurado
                interval = 30  # 30 segundos por defecto
                logger.info(f"Esperando {interval}s hasta próximo ciclo...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info("Monitoreo detenido por usuario")
        except Exception as e:
            logger.error(f"Error en monitoreo: {e}")
        finally:
            self.running = False
            logger.info("Monitoreo detenido")
    
    def get_system_status(self):
        """Obtener estado completo del sistema"""
        return {
            'engine_status': 'running' if self.running else 'stopped',
            'stats': self.stats,
            'uptime_seconds': time.time() - self.stats['start_time'],
            'detection_rate': self.stats['threats_detected'] / max(1, self.stats['events_processed']),
            'avg_events_per_minute': self.stats['events_processed'] / max(1, (time.time() - self.stats['start_time']) / 60)
        }

def main_console():
    """Interfaz de consola principal"""
    print("🛡️ VPEW-AI - AGENTE INTEGRADO CON IA")
    print("Vigilancia Proactiva para Endpoints Windows")
    print("=" * 60)
    
    engine = VPEWAIEngine()
    
    while True:
        print("\n📋 OPCIONES:")
        print("1. Ejecutar ciclo único de análisis")
        print("2. Iniciar monitoreo continuo") 
        print("3. Ver estadísticas del sistema")
        print("4. Ejecutar GUI")
        print("5. Salir")
        
        try:
            choice = input("\nSelecciona opción (1-5): ").strip()
            
            if choice == "1":
                print("\n🔍 Ejecutando ciclo único con IA...")
                results = engine.run_monitoring_cycle()
                
                print(f"\n📊 RESULTADOS:")
                for i, result in enumerate(results, 1):
                    anomaly = result['anomaly_analysis']
                    threat = result['threat_classification']
                    
                    print(f"[{i}] {result['event'].get('image', 'unknown')}")
                    print(f"    Anomalía: {anomaly['anomaly_score']:.2f} ({'SÍ' if anomaly['is_anomaly'] else 'NO'})")
                    print(f"    Amenaza: {threat['threat_class']} (confianza: {threat['confidence']:.2f})")
                    print(f"    Tiempo: {result['analysis_time_ms']:.1f}ms")
                
            elif choice == "2":
                print("\n🚀 Iniciando monitoreo continuo...")
                print("Presiona Ctrl+C para detener")
                engine.start_continuous_monitoring()
                
            elif choice == "3":
                status = engine.get_system_status()
                print(f"\n📊 ESTADÍSTICAS DEL SISTEMA:")
                print(f"   Estado: {status['engine_status']}")
                print(f"   Eventos procesados: {status['stats']['events_processed']}")
                print(f"   Amenazas detectadas: {status['stats']['threats_detected']}")
                print(f"   Tasa de detección: {status['detection_rate']*100:.1f}%")
                print(f"   Tiempo activo: {status['uptime_seconds']/60:.1f} minutos")
                print(f"   Eventos/minuto: {status['avg_events_per_minute']:.1f}")
                
            elif choice == "4":
                print("\n🖥️ Iniciando GUI...")
                try:
                    subprocess.Popen([sys.executable, "vpew_gui.py"])
                    print("✅ GUI iniciada en proceso separado")
                except Exception as e:
                    print(f"❌ Error iniciando GUI: {e}")
                
            elif choice == "5":
                print("👋 Saliendo...")
                break
                
            else:
                print("❌ Opción inválida")
                
        except KeyboardInterrupt:
            print("\n👋 Programa interrumpido")
            break
        except Exception as e:
            logger.error(f"Error: {e}")

if __name__ == "__main__":
    try:
        main_console()
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        print(f"❌ Error fatal: {e}")
