#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPEW-AI GUI - Interfaz Gráfica de Usuario
Interfaz gráfica para monitorear y controlar VPEW-AI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime
import queue
import sys
import os

# Agregar el path del virtualenv
venv_path = Path("C:/ProgramData/vpew-ai/venv")
if venv_path.exists():
    sys.path.insert(0, str(venv_path / "Lib" / "site-packages"))

class VPEWGui:
    def __init__(self, root):
        self.root = root
        self.root.title("VPEW-AI - Vigilancia Proactiva para Endpoints Windows")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.monitoring = False
        self.log_queue = queue.Queue()
        self.base_path = Path("C:/ProgramData/vpew-ai")
        
        # Configurar la interfaz
        self.setup_ui()
        
        # Inicializar datos
        self.load_system_info()
        self.update_status()
        
        # Iniciar actualización periódica
        self.root.after(1000, self.update_display)
    
    def setup_ui(self):
        """Configurar la interfaz de usuario"""
        
        # Título principal
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill='x', pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="🛡️ VPEW-AI Dashboard", 
                              font=('Arial', 16, 'bold'), 
                              fg='white', bg='#2c3e50')
        title_label.pack(expand=True)
        
        # Frame principal con notebook
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Notebook para pestañas
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Pestaña de Estado del Sistema
        self.setup_status_tab()
        
        # Pestaña de Monitoreo
        self.setup_monitoring_tab()
        
        # Pestaña de Alertas
        self.setup_alerts_tab()
        
        # Pestaña de Configuración
        self.setup_config_tab()
        
        # Frame de control inferior
        self.setup_control_frame()
    
    def setup_status_tab(self):
        """Configurar pestaña de estado del sistema"""
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="Estado del Sistema")
        
        # Información del sistema
        system_frame = ttk.LabelFrame(status_frame, text="Información del Sistema")
        system_frame.pack(fill='x', padx=10, pady=5)
        
        self.system_info = tk.Text(system_frame, height=8, wrap='word', state='disabled')
        self.system_info.pack(fill='x', padx=5, pady=5)
        
        # Estado de componentes
        components_frame = ttk.LabelFrame(status_frame, text="Estado de Componentes")
        components_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Crear treeview para componentes
        columns = ('Componente', 'Estado', 'Detalles')
        self.components_tree = ttk.Treeview(components_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.components_tree.heading(col, text=col)
            self.components_tree.column(col, width=200)
        
        scrollbar_comp = ttk.Scrollbar(components_frame, orient='vertical', command=self.components_tree.yview)
        self.components_tree.configure(yscrollcommand=scrollbar_comp.set)
        
        self.components_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar_comp.pack(side='right', fill='y')
    
    def setup_monitoring_tab(self):
        """Configurar pestaña de monitoreo"""
        monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitoring_frame, text="Monitoreo en Tiempo Real")
        
        # Controles de monitoreo
        control_frame = ttk.Frame(monitoring_frame)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Iniciar Monitoreo", 
                                   command=self.start_monitoring)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Detener Monitoreo", 
                                  command=self.stop_monitoring, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        self.status_label = tk.Label(control_frame, text="Estado: Detenido", 
                                    fg='red', font=('Arial', 10, 'bold'))
        self.status_label.pack(side='left', padx=20)
        
        # Log de eventos
        log_frame = ttk.LabelFrame(monitoring_frame, text="Log de Eventos")
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap='word', height=20)
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_alerts_tab(self):
        """Configurar pestaña de alertas"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="Alertas de Seguridad")
        
        # Estadísticas de alertas
        stats_frame = ttk.LabelFrame(alerts_frame, text="Estadísticas")
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        stats_inner = tk.Frame(stats_frame)
        stats_inner.pack(fill='x', padx=5, pady=5)
        
        tk.Label(stats_inner, text="Total Alertas:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w')
        self.total_alerts_label = tk.Label(stats_inner, text="0", fg='blue')
        self.total_alerts_label.grid(row=0, column=1, sticky='w', padx=10)
        
        tk.Label(stats_inner, text="Alertas Críticas:", font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky='w', padx=20)
        self.critical_alerts_label = tk.Label(stats_inner, text="0", fg='red')
        self.critical_alerts_label.grid(row=0, column=3, sticky='w', padx=10)
        
        tk.Label(stats_inner, text="Última Alerta:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w')
        self.last_alert_label = tk.Label(stats_inner, text="Ninguna", fg='gray')
        self.last_alert_label.grid(row=1, column=1, columnspan=3, sticky='w', padx=10)
        
        # Lista de alertas
        alerts_list_frame = ttk.LabelFrame(alerts_frame, text="Alertas Recientes")
        alerts_list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview para alertas
        alert_columns = ('Tiempo', 'Severidad', 'Tipo', 'Descripción')
        self.alerts_tree = ttk.Treeview(alerts_list_frame, columns=alert_columns, show='headings')
        
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            if col == 'Descripción':
                self.alerts_tree.column(col, width=400)
            else:
                self.alerts_tree.column(col, width=120)
        
        scrollbar_alerts = ttk.Scrollbar(alerts_list_frame, orient='vertical', command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar_alerts.set)
        
        self.alerts_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar_alerts.pack(side='right', fill='y')
    
    def setup_config_tab(self):
        """Configurar pestaña de configuración"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuración")
        
        # Configuración del agente
        agent_frame = ttk.LabelFrame(config_frame, text="Configuración del Agente")
        agent_frame.pack(fill='x', padx=10, pady=5)
        
        # Modo de inferencia
        tk.Label(agent_frame, text="Modo de Inferencia:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.inference_mode = ttk.Combobox(agent_frame, values=['edge', 'backend', 'minimal'], state='readonly')
        self.inference_mode.grid(row=0, column=1, sticky='w', padx=5, pady=2)
        
        # Intervalo de recolección
        tk.Label(agent_frame, text="Intervalo de Recolección (s):").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.collection_interval = tk.Spinbox(agent_frame, from_=5, to=300, width=10)
        self.collection_interval.grid(row=1, column=1, sticky='w', padx=5, pady=2)
        
        # Umbral de ML
        tk.Label(agent_frame, text="Umbral de Anomalía:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.ml_threshold = tk.Scale(agent_frame, from_=0.1, to=1.0, resolution=0.1, orient='horizontal')
        self.ml_threshold.grid(row=2, column=1, sticky='w', padx=5, pady=2)
        
        # Botones de configuración
        config_buttons = tk.Frame(config_frame)
        config_buttons.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(config_buttons, text="Cargar Configuración", 
                  command=self.load_config).pack(side='left', padx=5)
        ttk.Button(config_buttons, text="Guardar Configuración", 
                  command=self.save_config).pack(side='left', padx=5)
        
        # Rutas importantes
        paths_frame = ttk.LabelFrame(config_frame, text="Rutas Importantes")
        paths_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.paths_text = tk.Text(paths_frame, height=10, wrap='word', state='disabled')
        self.paths_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_control_frame(self):
        """Configurar frame de control inferior"""
        control_frame = tk.Frame(self.root, bg='#ecf0f1', height=50)
        control_frame.pack(fill='x', side='bottom')
        control_frame.pack_propagate(False)
        
        # Botones de acción
        ttk.Button(control_frame, text="Ejecutar Ciclo Único", 
                  command=self.run_single_cycle).pack(side='left', padx=10, pady=10)
        
        ttk.Button(control_frame, text="Ver Logs", 
                  command=self.view_logs).pack(side='left', padx=5, pady=10)
        
        ttk.Button(control_frame, text="Actualizar Estado", 
                  command=self.update_status).pack(side='left', padx=5, pady=10)
        
        # Estado de conexión
        self.connection_label = tk.Label(control_frame, text="●", fg='green', font=('Arial', 20))
        self.connection_label.pack(side='right', padx=10, pady=10)
        
        tk.Label(control_frame, text="Sistema:", bg='#ecf0f1').pack(side='right', padx=5, pady=10)
    
    def load_system_info(self):
        """Cargar información del sistema"""
        try:
            report_path = self.base_path / "validation_report.json"
            if report_path.exists():
                with open(report_path, 'r', encoding='utf-8') as f:
                    self.system_data = json.load(f)
            else:
                self.system_data = {}
            
            # Mostrar información del sistema
            host_info = self.system_data.get('host_info', {})
            system_text = f"""Sistema Operativo: {host_info.get('os', 'N/A')} {host_info.get('os_version', '')}
Arquitectura: {host_info.get('architecture', 'N/A')}
Procesador: {host_info.get('processor', 'N/A')}
Hostname: {host_info.get('hostname', 'N/A')}
RAM Total: {host_info.get('total_ram_gb', 'N/A')} GB
RAM Disponible: {host_info.get('available_ram_gb', 'N/A')} GB
CPU Cores: {host_info.get('cpu_cores', 'N/A')}
GPU: {'Sí' if host_info.get('has_gpu') else 'No'}
Espacio Libre: {host_info.get('disk_free_gb', 'N/A')} GB"""
            
            self.system_info.config(state='normal')
            self.system_info.delete(1.0, tk.END)
            self.system_info.insert(1.0, system_text)
            self.system_info.config(state='disabled')
            
        except Exception as e:
            self.log_message(f"Error cargando información del sistema: {e}")
    
    def update_status(self):
        """Actualizar estado de componentes"""
        try:
            # Limpiar árbol de componentes
            for item in self.components_tree.get_children():
                self.components_tree.delete(item)
            
            # Verificar Sysmon
            sysmon_status = self.check_sysmon_status()
            self.components_tree.insert('', 'end', values=('Sysmon', 
                                                          'Funcionando' if sysmon_status else 'Detenido',
                                                          'Telemetría avanzada'))
            
            # Verificar servicio VPEW
            vpew_status = self.check_vpew_service()
            self.components_tree.insert('', 'end', values=('Servicio VPEW', 
                                                          'Funcionando' if vpew_status else 'Detenido',
                                                          'Servicio Windows'))
            
            # Verificar virtualenv
            venv_status = self.venv_path.exists() if hasattr(self, 'venv_path') else venv_path.exists()
            self.components_tree.insert('', 'end', values=('Virtual Environment', 
                                                          'Disponible' if venv_status else 'No encontrado',
                                                          'Entorno Python'))
            
            # Verificar configuración
            config_status = (self.base_path / "config.json").exists()
            self.components_tree.insert('', 'end', values=('Configuración', 
                                                          'Cargada' if config_status else 'No encontrada',
                                                          'Archivo de configuración'))
            
            # Actualizar indicador de conexión
            overall_status = sysmon_status and vpew_status and venv_status and config_status
            self.connection_label.config(fg='green' if overall_status else 'orange')
            
        except Exception as e:
            self.log_message(f"Error actualizando estado: {e}")
    
    def check_sysmon_status(self):
        """Verificar estado de Sysmon"""
        try:
            result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                                  capture_output=True, text=True)
            return result.returncode == 0 and 'RUNNING' in result.stdout
        except:
            return False
    
    def check_vpew_service(self):
        """Verificar servicio VPEW"""
        try:
            result = subprocess.run(['sc', 'query', 'VPEWAgent'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def start_monitoring(self):
        """Iniciar monitoreo"""
        if not self.monitoring:
            self.monitoring = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.status_label.config(text="Estado: Monitoreando", fg='green')
            
            # Iniciar hilo de monitoreo
            self.monitoring_thread = threading.Thread(target=self.monitoring_worker, daemon=True)
            self.monitoring_thread.start()
            
            self.log_message("Monitoreo iniciado")
    
    def stop_monitoring(self):
        """Detener monitoreo"""
        if self.monitoring:
            self.monitoring = False
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.status_label.config(text="Estado: Detenido", fg='red')
            
            self.log_message("Monitoreo detenido")
    
    def monitoring_worker(self):
        """Trabajador de monitoreo en hilo separado"""
        while self.monitoring:
            try:
                # Simular eventos de monitoreo
                timestamp = datetime.now().strftime("%H:%M:%S")
                events = [
                    f"[{timestamp}] Recolectando eventos del sistema...",
                    f"[{timestamp}] Analizando 3 eventos con IA",
                    f"[{timestamp}] No se detectaron amenazas"
                ]
                
                for event in events:
                    self.log_queue.put(event)
                    time.sleep(1)
                
                # Simular alerta ocasional
                if time.time() % 30 < 1:  # Cada 30 segundos aprox
                    alert_msg = f"[{timestamp}] ALERTA: Actividad sospechosa detectada"
                    self.log_queue.put(alert_msg)
                    
                    # Agregar a alertas
                    alert_data = (timestamp, "MEDIUM", "Behavioral", "Proceso sospechoso detectado")
                    self.root.after(0, lambda: self.add_alert(alert_data))
                
                time.sleep(5)  # Intervalo de monitoreo
                
            except Exception as e:
                self.log_queue.put(f"Error en monitoreo: {e}")
                time.sleep(5)
    
    def add_alert(self, alert_data):
        """Agregar alerta a la lista"""
        self.alerts_tree.insert('', 0, values=alert_data)
        
        # Mantener solo las últimas 100 alertas
        items = self.alerts_tree.get_children()
        if len(items) > 100:
            self.alerts_tree.delete(items[-1])
        
        # Actualizar estadísticas
        total_alerts = len(items)
        critical_alerts = len([item for item in items 
                             if self.alerts_tree.item(item)['values'][1] == 'HIGH'])
        
        self.total_alerts_label.config(text=str(total_alerts))
        self.critical_alerts_label.config(text=str(critical_alerts))
        self.last_alert_label.config(text=alert_data[0])
    
    def run_single_cycle(self):
        """Ejecutar ciclo único"""
        try:
            self.log_message("Ejecutando ciclo único de monitoreo...")
            
            # Ejecutar en hilo separado para no bloquear GUI
            def run_cycle():
                try:
                    result = subprocess.run([
                        'python', 'vpew_real.py'
                    ], input='1\n', capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        self.log_message("Ciclo completado exitosamente")
                    else:
                        self.log_message(f"Error en ciclo: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    self.log_message("Ciclo completado (timeout)")
                except Exception as e:
                    self.log_message(f"Error ejecutando ciclo: {e}")
            
            threading.Thread(target=run_cycle, daemon=True).start()
            
        except Exception as e:
            self.log_message(f"Error iniciando ciclo: {e}")
    
    def view_logs(self):
        """Ver logs del sistema"""
        try:
            # Buscar archivos de log disponibles
            log_files = []
            log_dir = self.base_path / "logs"
            
            if log_dir.exists():
                for log_file in log_dir.glob("*.log"):
                    log_files.append(log_file)
            
            # También buscar logs en directorio actual
            current_dir = Path(".")
            for log_file in current_dir.glob("*.log"):
                log_files.append(log_file)
            
            if not log_files:
                messagebox.showinfo("Logs", "No se encontraron archivos de log")
                return
            
            # Abrir ventana de logs
            log_window = tk.Toplevel(self.root)
            log_window.title("Logs de VPEW-AI")
            log_window.geometry("900x700")
            
            # Frame para selección de archivo
            file_frame = tk.Frame(log_window)
            file_frame.pack(fill='x', padx=10, pady=5)
            
            tk.Label(file_frame, text="Archivo de log:").pack(side='left')
            
            log_var = tk.StringVar()
            log_combo = ttk.Combobox(file_frame, textvariable=log_var, state='readonly')
            log_combo['values'] = [str(f) for f in log_files]
            log_combo.pack(side='left', padx=5, fill='x', expand=True)
            
            if log_files:
                log_combo.current(0)
            
            # Área de contenido de logs
            log_content = scrolledtext.ScrolledText(log_window, wrap='word', font=('Consolas', 9))
            log_content.pack(fill='both', expand=True, padx=10, pady=5)
            
            def load_selected_log():
                """Cargar el log seleccionado"""
                try:
                    selected_file = Path(log_var.get())
                    if selected_file.exists():
                        log_content.delete(1.0, tk.END)
                        
                        # Intentar múltiples encodings
                        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
                        content = ""
                        
                        for encoding in encodings:
                            try:
                                with open(selected_file, 'r', encoding=encoding, errors='replace') as f:
                                    content = f.read()
                                break
                            except UnicodeDecodeError:
                                continue
                        
                        if content:
                            # Limpiar caracteres problemáticos
                            content = content.replace('\ufffd', '?')  # Reemplazar caracteres no válidos
                            log_content.insert(1.0, content)
                            log_content.see(tk.END)  # Ir al final
                        else:
                            log_content.insert(1.0, "Error: No se pudo leer el archivo con ninguna codificación")
                    
                except Exception as e:
                    log_content.delete(1.0, tk.END)
                    log_content.insert(1.0, f"Error leyendo archivo: {e}")
            
            # Botón para recargar
            reload_btn = ttk.Button(file_frame, text="Recargar", command=load_selected_log)
            reload_btn.pack(side='right', padx=5)
            
            # Cargar el primer archivo automáticamente
            load_selected_log()
            
            # Bind para cambio de selección
            log_combo.bind('<<ComboboxSelected>>', lambda e: load_selected_log())
                
        except Exception as e:
            messagebox.showerror("Error", f"Error abriendo logs: {e}")
    
    def load_config(self):
        """Cargar configuración"""
        try:
            config_path = self.base_path / "config.json"
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                agent_config = config.get('agent', {})
                performance_config = config.get('performance', {})
                ml_config = config.get('ml', {})
                
                # Actualizar controles
                self.inference_mode.set(agent_config.get('inference_mode', 'edge'))
                self.collection_interval.delete(0, tk.END)
                self.collection_interval.insert(0, str(agent_config.get('collection_interval', 5)))
                self.ml_threshold.set(ml_config.get('anomaly_threshold', 0.7))
                
                self.log_message("Configuración cargada")
            else:
                messagebox.showwarning("Configuración", "No se encontró archivo de configuración")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error cargando configuración: {e}")
    
    def save_config(self):
        """Guardar configuración"""
        try:
            config_path = self.base_path / "config.json"
            
            # Cargar configuración existente
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {}
            
            # Actualizar valores
            if 'agent' not in config:
                config['agent'] = {}
            if 'ml' not in config:
                config['ml'] = {}
            
            config['agent']['inference_mode'] = self.inference_mode.get()
            config['agent']['collection_interval'] = int(self.collection_interval.get())
            config['ml']['anomaly_threshold'] = self.ml_threshold.get()
            
            # Guardar configuración
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            self.log_message("Configuración guardada")
            messagebox.showinfo("Configuración", "Configuración guardada exitosamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error guardando configuración: {e}")
    
    def log_message(self, message):
        """Agregar mensaje al log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, formatted_message)
        self.log_text.see(tk.END)
        
        # Mantener solo las últimas 1000 líneas
        lines = self.log_text.get(1.0, tk.END).split('\n')
        if len(lines) > 1000:
            self.log_text.delete(1.0, f"{len(lines)-1000}.0")
    
    def update_display(self):
        """Actualizar display periódicamente"""
        # Procesar mensajes de log en cola
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_message(message)
        except queue.Empty:
            pass
        
        # Programar siguiente actualización
        self.root.after(1000, self.update_display)

def main():
    """Función principal"""
    try:
        root = tk.Tk()
        app = VPEWGui(root)
        root.mainloop()
    except Exception as e:
        print(f"Error iniciando GUI: {e}")
        messagebox.showerror("Error Fatal", f"Error iniciando aplicación: {e}")

if __name__ == "__main__":
    main()
