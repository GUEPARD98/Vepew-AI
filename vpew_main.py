#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPEW-AI MAIN - Punto de entrada principal
Sistema de vigilancia proactiva para endpoints Windows con IA
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Punto de entrada principal de VPEW-AI"""
    print("🛡️ VPEW-AI - Vigilancia Proactiva para Endpoints Windows")
    print("=" * 60)
    
    print("📋 SELECCIONA MODO DE EJECUCIÓN:")
    print("1. 🖥️ Interfaz Gráfica (GUI) - Recomendado")
    print("2. 💻 Monitoreo Real del Sistema")
    print("3. ⚙️ Instalación/Configuración")
    print("4. 📊 Ver Documentación")
    print("5. 🚪 Salir")
    
    try:
        choice = input("\nSelecciona opción (1-5): ").strip()
        
        if choice == "1":
            print("🖥️ Iniciando Interfaz Gráfica...")
            subprocess.run([sys.executable, "vpew_gui.py"])
            
        elif choice == "2":
            print("💻 Iniciando Monitoreo Real...")
            subprocess.run([sys.executable, "vpew_real.py"])
            
        elif choice == "3":
            print("⚙️ Iniciando Instalación...")
            subprocess.run([sys.executable, "install_vpew.py"])
            
        elif choice == "4":
            print("📊 Documentación disponible:")
            print("   • README.md - Manual completo")
            print("   • DEPLOYMENT.md - Guía de despliegue")
            print("   • IA_ARCHITECTURE.md - Arquitectura de IA")
            print("   • PROYECTO_COMPLETADO.md - Resumen completo")
            
        elif choice == "5":
            print("👋 Saliendo...")
            
        else:
            print("❌ Opción inválida")
            
    except KeyboardInterrupt:
        print("\n👋 Programa interrumpido")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
