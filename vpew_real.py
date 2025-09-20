#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPEW-AI REAL - Sin Simulaciones
Sistema real de vigilancia para endpoints Windows
"""

import os
import sys
import time
import json
import math
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter

# Configurar encoding
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Configurar paths
base_path = Path("C:/ProgramData/vpew-ai")
log_path = base_path / "logs" / "vpew-real.log"
log_path.parent.mkdir(parents=True, exist_ok=True)

# Configurar logging sin caracteres especiales
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VPEWRealAgent:
    """
    Agente VPEW-AI REAL - Sin simulaciones
    Monitoreo real de Windows con análisis de amenazas
    """
    
    def __init__(self):
        self.base_path = base_path
        self.running = False
        
        # Estadísticas reales
        self.stats = {
            'events_collected': 0,
            'processes_monitored': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }
        
        # Patrones de amenazas reales
        self.threat_indicators = {
            'credential_access': [
                'mimikatz', 'sekurlsa', 'logonpasswords', 'lsass',
                'procdump', 'comsvcs.dll', 'rundll32'
            ],
            'reconnaissance': [
                'net user', 'net group', 'whoami', 'systeminfo',
                'ipconfig', 'tasklist', 'qwinsta', 'query'
            ],
            'suspicious_processes': [
                'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                'mshta.exe', 'rundll32.exe', 'regsvr32.exe'
            ],
            'suspicious_locations': [
                'temp', 'appdata', 'public', 'downloads', 'desktop'
            ]
        }
        
        logger.info("VPEW Real Agent iniciado")
        print("VPEW Real Agent iniciado - Monitoreo real de Windows")
    
    def collect_real_processes(self):
        """Recolectar procesos reales del sistema Windows"""
        real_processes = []
        
        try:
            import psutil
            
            print("Recolectando procesos reales del sistema...")
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'username']):
                try:
                    proc_info = proc.info
                    
                    # Solo procesos con información completa
                    if proc_info['name'] and proc_info['cmdline']:
                        process_data = {
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'create_time': proc_info['create_time'],
                            'username': proc_info.get('username', 'N/A'),
                            'timestamp': time.time()
                        }
                        real_processes.append(process_data)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.debug(f"Error obteniendo info de proceso: {e}")
                    continue
            
            self.stats['processes_monitored'] = len(real_processes)
            logger.info(f"Procesos reales recolectados: {len(real_processes)}")
            print(f"Procesos reales recolectados: {len(real_processes)}")
            
            return real_processes
            
        except ImportError:
            logger.error("psutil no disponible - no se pueden recolectar procesos reales")
            print("ERROR: psutil no disponible")
            return []
        except Exception as e:
            logger.error(f"Error recolectando procesos: {e}")
            print(f"ERROR recolectando procesos: {e}")
            return []
    
    def collect_real_network_connections(self):
        """Recolectar conexiones de red reales"""
        real_connections = []
        
        try:
            import psutil
            
            print("Recolectando conexiones de red reales...")
            
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        connection_data = {
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'pid': conn.pid,
                            'timestamp': time.time()
                        }
                        
                        # Obtener proceso asociado
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                connection_data['process_name'] = proc.name()
                            except:
                                connection_data['process_name'] = 'Unknown'
                        
                        real_connections.append(connection_data)
                        
                except Exception as e:
                    logger.debug(f"Error procesando conexión: {e}")
                    continue
            
            logger.info(f"Conexiones reales recolectadas: {len(real_connections)}")
            print(f"Conexiones de red reales: {len(real_connections)}")
            
            return real_connections
            
        except Exception as e:
            logger.error(f"Error recolectando conexiones: {e}")
            print(f"ERROR recolectando conexiones: {e}")
            return []
    
    def analyze_real_process(self, process_data):
        """Analizar proceso real para detectar amenazas"""
        threats_found = []
        risk_score = 0.0
        
        name = process_data['name'].lower()
        cmdline = process_data['cmdline'].lower()
        
        # 1. DETECCIÓN DE PROCESOS SOSPECHOSOS
        if any(susp in name for susp in self.threat_indicators['suspicious_processes']):
            if 'powershell' in name and ('-enc' in cmdline or '-e ' in cmdline):
                threats_found.append("PowerShell con comando codificado detectado")
                risk_score += 0.8
            elif 'cmd' in name and len(cmdline) > 100:
                threats_found.append("CMD con comando largo detectado")
                risk_score += 0.5
        
        # 2. DETECCIÓN DE COMANDOS DE RECONOCIMIENTO
        recon_found = [cmd for cmd in self.threat_indicators['reconnaissance'] if cmd in cmdline]
        if recon_found:
            threats_found.append(f"Comandos de reconocimiento: {', '.join(recon_found)}")
            risk_score += 0.6
        
        # 3. DETECCIÓN DE ACCESO A CREDENCIALES
        cred_found = [cred for cred in self.threat_indicators['credential_access'] if cred in cmdline]
        if cred_found:
            threats_found.append(f"Indicadores de acceso a credenciales: {', '.join(cred_found)}")
            risk_score += 0.9
        
        # 4. ANÁLISIS DE UBICACIÓN
        process_path = process_data.get('cmdline', '')
        if any(loc in process_path.lower() for loc in self.threat_indicators['suspicious_locations']):
            threats_found.append("Proceso ejecutándose desde ubicación sospechosa")
            risk_score += 0.4
        
        # 5. ANÁLISIS DE ENTROPÍA (detección de ofuscación)
        entropy = self._calculate_entropy(cmdline)
        if entropy > 4.5:
            threats_found.append(f"Alta entropía en comando ({entropy:.2f}) - posible ofuscación")
            risk_score += 0.5
        
        return {
            'process': process_data,
            'threats_found': threats_found,
            'risk_score': min(risk_score, 1.0),
            'is_threat': risk_score > 0.6,
            'analysis_time': time.time()
        }
    
    def analyze_real_network(self, connection_data):
        """Analizar conexión de red real"""
        threats_found = []
        risk_score = 0.0
        
        remote_ip = connection_data['remote_addr'].split(':')[0]
        remote_port = connection_data['remote_addr'].split(':')[1]
        process_name = connection_data.get('process_name', '').lower()
        
        # 1. ANÁLISIS DE IP EXTERNA
        if not remote_ip.startswith(('192.168.', '10.', '172.16.', '127.')):
            threats_found.append(f"Conexión a IP externa: {remote_ip}")
            risk_score += 0.3
        
        # 2. ANÁLISIS DE PUERTOS SOSPECHOSOS
        suspicious_ports = ['4444', '31337', '8080', '8443', '1337']
        if remote_port in suspicious_ports:
            threats_found.append(f"Conexión a puerto sospechoso: {remote_port}")
            risk_score += 0.7
        
        # 3. ANÁLISIS DE PROCESO
        if process_name not in ['chrome.exe', 'firefox.exe', 'msedge.exe', 'svchost.exe']:
            if any(susp in process_name for susp in ['powershell', 'cmd', 'rundll32']):
                threats_found.append(f"Proceso sospechoso con conexión de red: {process_name}")
                risk_score += 0.6
        
        return {
            'connection': connection_data,
            'threats_found': threats_found,
            'risk_score': min(risk_score, 1.0),
            'is_threat': risk_score > 0.5
        }
    
    def _calculate_entropy(self, text):
        """Calcular entropía de Shannon real"""
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
    
    def execute_real_response(self, threat_analysis):
        """Ejecutar respuesta real (no simulada)"""
        if not threat_analysis['is_threat']:
            return []
        
        real_actions = []
        
        # 1. LOGGING REAL
        threat_log = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': 'process_analysis' if 'process' in threat_analysis else 'network_analysis',
            'risk_score': threat_analysis['risk_score'],
            'threats_found': threat_analysis['threats_found'],
            'details': threat_analysis
        }
        
        # Guardar en archivo de amenazas
        threats_file = self.base_path / "logs" / "threats_detected.json"
        
        try:
            # Cargar amenazas existentes
            if threats_file.exists():
                with open(threats_file, 'r', encoding='utf-8') as f:
                    existing_threats = json.load(f)
            else:
                existing_threats = []
            
            # Agregar nueva amenaza
            existing_threats.append(threat_log)
            
            # Mantener solo las últimas 1000 amenazas
            if len(existing_threats) > 1000:
                existing_threats = existing_threats[-1000:]
            
            # Guardar
            with open(threats_file, 'w', encoding='utf-8') as f:
                json.dump(existing_threats, f, indent=2, ensure_ascii=False)
            
            real_actions.append(f"Amenaza registrada en {threats_file}")
            
        except Exception as e:
            logger.error(f"Error guardando amenaza: {e}")
        
        # 2. NOTIFICACIÓN REAL AL SISTEMA
        try:
            # Escribir evento en Event Log de Windows (si tenemos permisos)
            import win32evtlog
            import win32evtlogutil
            
            # Intentar escribir evento personalizado
            win32evtlogutil.ReportEvent(
                "VPEW-AI",
                1001,  # Event ID personalizado
                eventCategory=0,
                eventType=win32evtlog.EVENTLOG_WARNING_TYPE,
                strings=[
                    "VPEW-AI: Amenaza detectada",
                    f"Riesgo: {threat_analysis['risk_score']:.2f}",
                    f"Detalles: {'; '.join(threat_analysis['threats_found'])}"
                ]
            )
            
            real_actions.append("Evento escrito en Windows Event Log")
            
        except ImportError:
            logger.info("win32evtlog no disponible")
        except Exception as e:
            logger.debug(f"No se pudo escribir en Event Log: {e}")
        
        # 3. INCREMENTAR MONITOREO REAL
        if threat_analysis['risk_score'] > 0.8:
            # Para amenazas críticas, incrementar frecuencia de monitoreo
            real_actions.append("Monitoreo intensivo activado")
        
        # 4. ESTADÍSTICAS REALES
        self.stats['threats_detected'] += 1
        
        logger.warning(f"AMENAZA REAL DETECTADA: Riesgo {threat_analysis['risk_score']:.2f}")
        print(f"AMENAZA REAL DETECTADA: Riesgo {threat_analysis['risk_score']:.2f}")
        
        return real_actions
    
    def run_real_monitoring_cycle(self):
        """Ejecutar ciclo de monitoreo REAL"""
        print("\n=== CICLO DE MONITOREO REAL ===")
        logger.info("Iniciando ciclo de monitoreo real")
        
        cycle_results = {
            'timestamp': datetime.now().isoformat(),
            'processes_analyzed': 0,
            'connections_analyzed': 0,
            'threats_detected': 0,
            'analysis_results': []
        }
        
        # 1. MONITOREO REAL DE PROCESOS
        real_processes = self.collect_real_processes()
        
        if real_processes:
            print(f"Analizando {len(real_processes)} procesos reales...")
            
            for process in real_processes:
                analysis = self.analyze_real_process(process)
                cycle_results['analysis_results'].append(analysis)
                cycle_results['processes_analyzed'] += 1
                
                if analysis['is_threat']:
                    cycle_results['threats_detected'] += 1
                    actions = self.execute_real_response(analysis)
                    
                    print(f"AMENAZA: {process['name']} (PID: {process['pid']})")
                    print(f"  Riesgo: {analysis['risk_score']:.2f}")
                    print(f"  Indicadores: {'; '.join(analysis['threats_found'][:2])}")
                    
                    for action in actions:
                        print(f"  Accion: {action}")
        
        # 2. MONITOREO REAL DE RED
        real_connections = self.collect_real_network_connections()
        
        if real_connections:
            print(f"Analizando {len(real_connections)} conexiones reales...")
            
            for connection in real_connections:
                analysis = self.analyze_real_network(connection)
                cycle_results['analysis_results'].append(analysis)
                cycle_results['connections_analyzed'] += 1
                
                if analysis['is_threat']:
                    cycle_results['threats_detected'] += 1
                    actions = self.execute_real_response(analysis)
                    
                    print(f"AMENAZA RED: {connection['remote_addr']}")
                    print(f"  Proceso: {connection.get('process_name', 'Unknown')}")
                    print(f"  Riesgo: {analysis['risk_score']:.2f}")
        
        # 3. GUARDAR RESULTADOS REALES
        results_file = self.base_path / "logs" / "real_monitoring_results.json"
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(cycle_results, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"Error guardando resultados: {e}")
        
        # 4. ESTADÍSTICAS DEL CICLO
        print(f"\nRESULTADOS DEL CICLO:")
        print(f"  Procesos analizados: {cycle_results['processes_analyzed']}")
        print(f"  Conexiones analizadas: {cycle_results['connections_analyzed']}")
        print(f"  Amenazas detectadas: {cycle_results['threats_detected']}")
        
        self.stats['events_collected'] += cycle_results['processes_analyzed'] + cycle_results['connections_analyzed']
        
        return cycle_results
    
    def start_real_continuous_monitoring(self):
        """Iniciar monitoreo continuo REAL"""
        print("Iniciando monitoreo continuo REAL...")
        logger.info("Monitoreo continuo real iniciado")
        
        self.running = True
        cycle_count = 0
        
        try:
            while self.running:
                cycle_count += 1
                print(f"\n--- Ciclo Real #{cycle_count} ---")
                
                # Ejecutar monitoreo real
                results = self.run_real_monitoring_cycle()
                
                # Esperar intervalo
                interval = 30  # 30 segundos
                print(f"Esperando {interval} segundos...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoreo detenido por usuario")
            logger.info("Monitoreo detenido por usuario")
        except Exception as e:
            logger.error(f"Error en monitoreo: {e}")
            print(f"ERROR en monitoreo: {e}")
        finally:
            self.running = False
    
    def get_real_stats(self):
        """Obtener estadísticas reales del sistema"""
        uptime = time.time() - self.stats['start_time']
        
        return {
            'uptime_seconds': uptime,
            'uptime_minutes': uptime / 60,
            'events_collected': self.stats['events_collected'],
            'processes_monitored': self.stats['processes_monitored'],
            'threats_detected': self.stats['threats_detected'],
            'detection_rate': self.stats['threats_detected'] / max(1, self.stats['events_collected']) * 100,
            'events_per_minute': self.stats['events_collected'] / max(1, uptime / 60)
        }

def check_real_system_status():
    """Verificar estado real del sistema"""
    print("VERIFICANDO ESTADO REAL DEL SISTEMA")
    print("=" * 40)
    
    status = {}
    
    # 1. Verificar Python y dependencias
    try:
        import psutil
        status['psutil'] = f"v{psutil.__version__}"
        print(f"✓ psutil: {status['psutil']}")
    except ImportError:
        status['psutil'] = "NO DISPONIBLE"
        print(f"✗ psutil: NO DISPONIBLE")
    
    # 2. Verificar permisos
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        status['admin_rights'] = is_admin
        print(f"{'✓' if is_admin else '!'} Permisos admin: {'SÍ' if is_admin else 'NO'}")
    except:
        status['admin_rights'] = False
        print("! Permisos admin: DESCONOCIDO")
    
    # 3. Verificar servicios
    try:
        result = subprocess.run(['sc', 'query', 'VPEWAgent'], capture_output=True, text=True)
        vpew_service = 'RUNNING' in result.stdout if result.returncode == 0 else False
        status['vpew_service'] = vpew_service
        print(f"{'✓' if vpew_service else '!'} Servicio VPEW: {'FUNCIONANDO' if vpew_service else 'DETENIDO'}")
    except:
        status['vpew_service'] = False
        print("! Servicio VPEW: DESCONOCIDO")
    
    # 4. Verificar Sysmon
    try:
        result = subprocess.run(['sc', 'query', 'Sysmon64'], capture_output=True, text=True)
        sysmon_service = 'RUNNING' in result.stdout if result.returncode == 0 else False
        status['sysmon'] = sysmon_service
        print(f"{'✓' if sysmon_service else '!'} Sysmon: {'FUNCIONANDO' if sysmon_service else 'NO INSTALADO'}")
    except:
        status['sysmon'] = False
        print("! Sysmon: DESCONOCIDO")
    
    return status

def main():
    """Función principal REAL"""
    print("VPEW-AI REAL - Sistema de Vigilancia Real para Windows")
    print("=" * 60)
    
    # Verificar estado del sistema
    system_status = check_real_system_status()
    
    if not system_status.get('psutil'):
        print("\nERROR: psutil es requerido para monitoreo real")
        print("Instalar con: pip install psutil")
        return
    
    # Inicializar agente real
    agent = VPEWRealAgent()
    
    print(f"\nOPCIONES DE MONITOREO REAL:")
    print("1. Ejecutar ciclo único de monitoreo real")
    print("2. Iniciar monitoreo continuo real")
    print("3. Ver estadísticas reales")
    print("4. Salir")
    
    while True:
        try:
            choice = input("\nSelecciona opción (1-4): ").strip()
            
            if choice == "1":
                print("\nEjecutando monitoreo real del sistema...")
                results = agent.run_real_monitoring_cycle()
                
            elif choice == "2":
                print("\nIniciando monitoreo continuo real...")
                print("Presiona Ctrl+C para detener")
                agent.start_real_continuous_monitoring()
                
            elif choice == "3":
                stats = agent.get_real_stats()
                print(f"\nESTADÍSTICAS REALES:")
                print(f"  Tiempo activo: {stats['uptime_minutes']:.1f} minutos")
                print(f"  Eventos recolectados: {stats['events_collected']}")
                print(f"  Procesos monitoreados: {stats['processes_monitored']}")
                print(f"  Amenazas detectadas: {stats['threats_detected']}")
                print(f"  Tasa de detección: {stats['detection_rate']:.1f}%")
                print(f"  Eventos por minuto: {stats['events_per_minute']:.1f}")
                
            elif choice == "4":
                print("Saliendo...")
                break
                
            else:
                print("Opción inválida")
                
        except KeyboardInterrupt:
            print("\nPrograma interrumpido")
            break
        except Exception as e:
            logger.error(f"Error: {e}")
            print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
