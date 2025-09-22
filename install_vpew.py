#!/usr/bin/env python3
"""
VPEW-AI Dynamic Windows Installation Script
Configura y ejecuta VPEW-AI automáticamente en Windows
"""

import os
import sys
import json
import subprocess
import platform
import psutil
import shutil
import venv
import logging
from pathlib import Path
from datetime import datetime
import winreg
import ctypes

# Configurar logging
log_path = Path("install.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class VPEWInstaller:
    def __init__(self):
        self.base_path = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / 'vpew-ai'
        self.venv_path = self.base_path / 'venv'
        self.config_path = self.base_path / 'config.json'
        self.validation_report = {
            'timestamp': datetime.now().isoformat(),
            'host_info': {},
            'dependencies': {},
            'service_status': {},
            'sysmon_installed': False,
            'errors': [],
            'recommendations': [],
            'installation_paths': {}
        }
        
        logger.info("Iniciando instalación dinámica de VPEW-AI")
    
    def detect_environment(self):
        """Detectar entorno del sistema Windows"""
        try:
            logger.info("Detectando entorno del sistema...")
            
            # Información básica del sistema
            host_info = {
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'hostname': platform.node(),
                'python_version': platform.python_version()
            }
            
            # Información de recursos
            memory = psutil.virtual_memory()
            host_info.update({
                'total_ram_gb': round(memory.total / (1024**3), 2),
                'available_ram_gb': round(memory.available / (1024**3), 2),
                'cpu_cores': psutil.cpu_count(logical=False),
                'cpu_threads': psutil.cpu_count(logical=True),
                'disk_free_gb': round(shutil.disk_usage(self.base_path.parent).free / (1024**3), 2)
            })
            
            # Detectar GPU (básico)
            try:
                import wmi
                c = wmi.WMI()
                gpus = []
                for gpu in c.Win32_VideoController():
                    if gpu.Name and 'nvidia' in gpu.Name.lower():
                        gpus.append({'name': gpu.Name, 'type': 'nvidia'})
                    elif gpu.Name and 'amd' in gpu.Name.lower():
                        gpus.append({'name': gpu.Name, 'type': 'amd'})
                host_info['gpus'] = gpus
                host_info['has_gpu'] = len(gpus) > 0
            except:
                host_info['gpus'] = []
                host_info['has_gpu'] = False
            
            # Verificar permisos de administrador
            try:
                host_info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                host_info['is_admin'] = False
            
            self.validation_report['host_info'] = host_info
            logger.info(f"Sistema detectado: {host_info['os']} {host_info['os_version']}")
            logger.info(f"RAM: {host_info['total_ram_gb']}GB, CPU: {host_info['cpu_cores']} cores")
            logger.info(f"GPU disponible: {host_info['has_gpu']}, Admin: {host_info['is_admin']}")
            
            return host_info
            
        except Exception as e:
            error_msg = f"Error detectando entorno: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return {}
    
    def create_virtualenv(self):
        """Crear virtualenv en %PROGRAMDATA%\\vpew-ai\\venv"""
        try:
            logger.info(f"Creando virtualenv en {self.venv_path}")
            
            # Crear directorio base
            self.base_path.mkdir(parents=True, exist_ok=True)
            
            # Crear virtualenv si no existe
            if not self.venv_path.exists():
                venv.create(self.venv_path, with_pip=True)
                logger.info("Virtualenv creado exitosamente")
            else:
                logger.info("Virtualenv ya existe, reutilizando")
            
            # Verificar python del venv
            python_exe = self.venv_path / 'Scripts' / 'python.exe'
            if python_exe.exists():
                self.validation_report['installation_paths']['python_venv'] = str(python_exe)
                logger.info(f"Python virtualenv: {python_exe}")
                return True
            else:
                raise Exception("No se pudo crear el virtualenv correctamente")
                
        except Exception as e:
            error_msg = f"Error creando virtualenv: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return False
    
    def install_dependencies(self):
        """Instalar dependencias desde requirements.txt"""
        try:
            logger.info("Instalando dependencias...")
            
            python_exe = self.venv_path / 'Scripts' / 'python.exe'
            pip_exe = self.venv_path / 'Scripts' / 'pip.exe'
            
            # Actualizar pip
            subprocess.run([str(python_exe), '-m', 'pip', 'install', '--upgrade', 'pip'], 
                         check=True, capture_output=True, text=True)
            
            # Instalar dependencias básicas
            basic_deps = [
                'psutil>=5.9.0',
                'requests>=2.28.0',
                'cryptography>=3.4.8',
                'pyyaml>=6.0',
                'numpy>=1.21.0',
                'scikit-learn>=1.1.0',
                'flask>=2.2.0',
                'wmi>=1.5.1'
            ]
            
            # Instalar TensorFlow solo si hay suficiente RAM
            host_info = self.validation_report['host_info']
            if host_info.get('total_ram_gb', 0) >= 4:
                basic_deps.append('tensorflow-cpu>=2.10.0')
                self.validation_report['dependencies']['tensorflow'] = 'installed'
            else:
                self.validation_report['dependencies']['tensorflow'] = 'skipped_low_memory'
                self.validation_report['recommendations'].append(
                    "TensorFlow no instalado debido a RAM insuficiente (<4GB)"
                )
            
            # Instalar dependencias
            for dep in basic_deps:
                try:
                    result = subprocess.run([str(pip_exe), 'install', dep], 
                                          check=True, capture_output=True, text=True)
                    self.validation_report['dependencies'][dep.split('>=')[0]] = 'installed'
                except subprocess.CalledProcessError as e:
                    self.validation_report['dependencies'][dep.split('>=')[0]] = 'failed'
                    logger.warning(f"Falló instalación de {dep}: {e}")
            
            # Instalar el paquete VPEW-AI si existe
            if Path('setup.py').exists():
                subprocess.run([str(pip_exe), 'install', '-e', '.'], 
                             check=True, capture_output=True, text=True)
                self.validation_report['dependencies']['vpew-ai'] = 'installed'
            
            logger.info("Dependencias instaladas exitosamente")
            return True
            
        except Exception as e:
            error_msg = f"Error instalando dependencias: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return False
    
    def create_config(self):
        """Crear config.json dinámico basado en recursos del sistema"""
        try:
            logger.info("Creando configuración dinámica...")
            
            host_info = self.validation_report['host_info']
            
            # Determinar modo de inferencia
            if host_info.get('has_gpu', False) and host_info.get('total_ram_gb', 0) >= 8:
                inference_mode = 'edge'
                collection_interval = 5
                max_cpu_usage = 15
            elif host_info.get('total_ram_gb', 0) >= 4:
                inference_mode = 'backend'
                collection_interval = 10
                max_cpu_usage = 10
            else:
                inference_mode = 'minimal'
                collection_interval = 30
                max_cpu_usage = 5
            
            config = {
                'agent': {
                    'endpoint_id': f"vpew-{host_info.get('hostname', 'unknown')}",
                    'inference_mode': inference_mode,
                    'collection_interval': collection_interval
                },
                'performance': {
                    'max_cpu_usage': max_cpu_usage,
                    'max_memory_usage': min(512, int(host_info.get('total_ram_gb', 2) * 128)),
                    'processing_threads': min(2, host_info.get('cpu_cores', 1))
                },
                'ml': {
                    'enabled': host_info.get('total_ram_gb', 0) >= 4,
                    'anomaly_threshold': 0.7,
                    'model_path': str(self.base_path / 'models')
                },
                'logging': {
                    'level': 'INFO',
                    'file': str(self.base_path / 'logs' / 'vpew-agent.log'),
                    'max_file_size': '10MB'
                },
                'paths': {
                    'base_path': str(self.base_path),
                    'venv_path': str(self.venv_path),
                    'config_path': str(self.config_path)
                }
            }
            
            # Guardar configuración
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.validation_report['installation_paths']['config'] = str(self.config_path)
            logger.info(f"Configuración creada: modo {inference_mode}")
            return True
            
        except Exception as e:
            error_msg = f"Error creando configuración: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return False
    
    def check_sysmon(self):
        """Verificar si Sysmon está instalado"""
        try:
            logger.info("Verificando instalación de Sysmon...")
            
            # Verificar servicio Sysmon
            try:
                result = subprocess.run(['sc', 'query', 'Sysmon'], 
                                      capture_output=True, text=True)
                if result.returncode == 0 and 'RUNNING' in result.stdout:
                    self.validation_report['sysmon_installed'] = True
                    logger.info("Sysmon encontrado y ejecutándose")
                else:
                    self.validation_report['sysmon_installed'] = False
                    logger.warning("Sysmon no encontrado")
            except:
                # Verificar Sysmon64
                result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                                      capture_output=True, text=True)
                if result.returncode == 0 and 'RUNNING' in result.stdout:
                    self.validation_report['sysmon_installed'] = True
                    logger.info("Sysmon64 encontrado y ejecutándose")
                else:
                    self.validation_report['sysmon_installed'] = False
                    logger.warning("Sysmon no encontrado")
            
            if not self.validation_report['sysmon_installed']:
                self.validation_report['recommendations'].append(
                    "Sysmon no está instalado. Se recomienda instalarlo para telemetría avanzada."
                )
                self.validation_report['recommendations'].append(
                    "Comando: Sysmon64.exe -accepteula -i config\\sysmon_config.xml"
                )
            
            return True
            
        except Exception as e:
            error_msg = f"Error verificando Sysmon: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return False
    
    def create_windows_service(self):
        """Crear servicio Windows VPEWAgent"""
        try:
            logger.info("Creando servicio Windows VPEWAgent...")
            
            if not self.validation_report['host_info'].get('is_admin', False):
                self.validation_report['recommendations'].append(
                    "Se requieren permisos de administrador para crear el servicio Windows"
                )
                self.validation_report['service_status']['created'] = False
                self.validation_report['service_status']['reason'] = 'no_admin_permissions'
                return False
            
            # Crear script de servicio
            service_script = self.base_path / 'vpew_service.py'
            service_content = f'''#!/usr/bin/env python3
"""
VPEW-AI Windows Service
"""
import sys
sys.path.insert(0, r"{self.venv_path / 'Lib' / 'site-packages'}")

import servicemanager
import socket
import sys
import win32event
import win32service
import win32serviceutil
import time
import subprocess
from pathlib import Path

class VPEWService(win32serviceutil.ServiceFramework):
    _svc_name_ = "VPEWAgent"
    _svc_display_name_ = "VPEW-AI Security Agent"
    _svc_description_ = "Vigilancia Proactiva para Endpoints Windows con IA"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_alive = True
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_alive = False
    
    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))
        self.main()
    
    def main(self):
        python_exe = r"{self.venv_path / 'Scripts' / 'python.exe'}"
        config_file = r"{self.config_path}"
        
        while self.is_alive:
            try:
                # Aquí iría la ejecución del agente VPEW-AI
                # Por ahora solo loggeamos que está funcionando
                servicemanager.LogInfoMsg("VPEW-AI Agent running...")
                time.sleep(60)
            except Exception as e:
                servicemanager.LogErrorMsg(f"Error en VPEW-AI Agent: {{e}}")
                time.sleep(30)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(VPEWService)
'''
            
            with open(service_script, 'w') as f:
                f.write(service_content)
            
            # Instalar servicio usando pywin32
            try:
                python_exe = self.venv_path / 'Scripts' / 'python.exe'
                result = subprocess.run([
                    str(python_exe), str(service_script), 'install'
                ], capture_output=True, text=True, check=True)
                
                self.validation_report['service_status']['created'] = True
                self.validation_report['service_status']['name'] = 'VPEWAgent'
                self.validation_report['service_status']['script_path'] = str(service_script)
                logger.info("Servicio Windows creado exitosamente")
                
                # Intentar iniciar el servicio
                try:
                    subprocess.run(['sc', 'start', 'VPEWAgent'], 
                                 capture_output=True, text=True, check=True)
                    self.validation_report['service_status']['running'] = True
                    logger.info("Servicio iniciado exitosamente")
                except:
                    self.validation_report['service_status']['running'] = False
                    logger.warning("Servicio creado pero no se pudo iniciar automáticamente")
                
                return True
                
            except subprocess.CalledProcessError as e:
                self.validation_report['service_status']['created'] = False
                self.validation_report['service_status']['error'] = str(e)
                logger.error(f"Error creando servicio: {e}")
                return False
            
        except Exception as e:
            error_msg = f"Error creando servicio Windows: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            self.validation_report['service_status']['created'] = False
            return False
    
    def create_directories(self):
        """Crear directorios necesarios"""
        try:
            directories = [
                self.base_path / 'logs',
                self.base_path / 'models',
                self.base_path / 'certs',
                self.base_path / 'config'
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                self.validation_report['installation_paths'][directory.name] = str(directory)
            
            logger.info("Directorios creados exitosamente")
            return True
            
        except Exception as e:
            error_msg = f"Error creando directorios: {e}"
            logger.error(error_msg)
            self.validation_report['errors'].append(error_msg)
            return False
    
    def run_installation(self):
        """Ejecutar instalación completa"""
        logger.info("=== INICIANDO INSTALACIÓN VPEW-AI ===")
        
        # 1. Detectar entorno
        self.detect_environment()
        
        # 2. Crear virtualenv
        if not self.create_virtualenv():
            return False
        
        # 3. Crear directorios
        self.create_directories()
        
        # 4. Instalar dependencias
        if not self.install_dependencies():
            return False
        
        # 5. Crear configuración
        if not self.create_config():
            return False
        
        # 6. Verificar Sysmon
        self.check_sysmon()
        
        # 7. Crear servicio Windows
        self.create_windows_service()
        
        # Rutas finales
        self.validation_report['installation_paths']['logs'] = str(self.base_path / 'logs')
        self.validation_report['installation_paths']['install_log'] = str(log_path.absolute())
        
        # Resumen final
        if len(self.validation_report['errors']) == 0:
            logger.info("=== INSTALACIÓN COMPLETADA EXITOSAMENTE ===")
            self.validation_report['installation_status'] = 'success'
        else:
            logger.warning("=== INSTALACIÓN COMPLETADA CON ADVERTENCIAS ===")
            self.validation_report['installation_status'] = 'partial'
        
        return True

def main():
    installer = VPEWInstaller()
    installer.run_installation()
    
    # Guardar reporte de validación
    report_path = installer.base_path / 'validation_report.json'
    with open(report_path, 'w') as f:
        json.dump(installer.validation_report, f, indent=2)
    
    # Mostrar resumen en consola
    print("\n" + "="*60)
    print("VPEW-AI INSTALLATION SUMMARY")
    print("="*60)
    
    # Leer y mostrar install.log resumido
    if log_path.exists():
        with open(log_path, 'r') as f:
            log_lines = f.readlines()
            print("INSTALL.LOG (últimas 20 líneas):")
            print("-" * 40)
            for line in log_lines[-20:]:
                print(line.strip())
    
    print("\n" + "="*60)
    print("VALIDATION_REPORT.JSON:")
    print("="*60)
    print(json.dumps(installer.validation_report, indent=2))
    
    return installer.validation_report

if __name__ == "__main__":
    main()
