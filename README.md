# VPEW-AI: Vigilancia Proactiva para Endpoints Windows con IA

## 1. Resumen Ejecutivo

### Descripción de la herramienta VPEW-AI

VPEW-AI (Vigilancia Proactiva para Endpoints Windows con IA) es un sistema de protección avanzada diseñado para defender 500 endpoints Windows (Windows 10/11 y Server 2016–2019) mediante la aplicación de inteligencia artificial y análisis comportamental. La herramienta adopta una mentalidad ofensiva para anticipar y neutralizar amenazas antes de que causen daño.

### Objetivos principales de protección

- **Detección temprana**: Identificar amenazas en las primeras fases del kill chain
- **Respuesta automatizada**: Ejecutar contramedidas inmediatas ante indicadores de compromiso
- **Inteligencia adaptativa**: Aprender de patrones de ataque para mejorar la detección
- **Visibilidad completa**: Proporcionar telemetría detallada de toda la infraestructura
- **Cumplimiento normativo**: Mantener registros auditables y conformidad legal

### Principios de seguridad aplicados

1. **Planificar**: Análisis proactivo de vectores de amenaza y superficies de ataque
2. **Prevenir**: Implementación de controles preventivos basados en inteligencia de amenazas
3. **Detectar**: Monitoreo continuo con correlación de eventos y análisis ML
4. **Responder**: Automatización de respuesta a incidentes con playbooks predefinidos
5. **Mejorar**: Retroalimentación continua y reentrenamiento de modelos ML

## 2. Tabla de Fases de Ataque → Indicadores Defensivos

| Fase | Objetivo del Atacante | Indicadores Defensivos VPEW-AI | Fuentes de Telemetría |
|------|----------------------|--------------------------------|----------------------|
| **Reconocimiento** | Enumerar red y usuarios | - Monitoreo de comandos de red secuenciales<br>- Correlación de eventos Sysmon<br>- Detección de escaneo de puertos | - Sysmon EventID 1 (Process Creation)<br>- EventID 4624 (Logon)<br>- Network connections |
| **Acceso** | Obtener credenciales | - Monitoreo de acceso a LSASS<br>- Alertas de SAM dump<br>- Detección de ataques de fuerza bruta | - EventID 4625 (Failed Logon)<br>- Sysmon EventID 10 (Process Access)<br>- Memory dumps |
| **Persistencia** | Mantener acceso | - Monitoreo de creación de servicios<br>- Verificación de integridad de binarios<br>- Detección de modificaciones de registro | - EventID 4697 (Service Install)<br>- Sysmon EventID 13 (Registry)<br>- File integrity monitoring |
| **Movimiento Lateral** | Expandir control | - Alertas de autenticaciones remotas<br>- Bloqueo de PowerShell sospechoso<br>- Monitoreo de conexiones laterales | - EventID 4624 (Remote Logon)<br>- Sysmon EventID 3 (Network)<br>- WMI activity logs |
| **Cleanup** | Borrar rastros | - Monitoreo de borrado de logs<br>- Detección de limpieza de artefactos<br>- Alertas de modificación de evidencia | - EventID 1102 (Log Clear)<br>- File deletion events<br>- Timeline analysis |

## 3. Arquitectura Modular y Comunicación Segura

### Componentes principales

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     SENSOR      │    │     BACKEND      │    │  CONSOLA DE     │
│   (Endpoint)    │◄──►│   (SOF-ELK)      │◄──►│   GESTIÓN       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                       ▲                       ▲
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  MOTOR DE       │    │   INTELIGENCIA   │    │   RESPUESTA     │
│  REGLAS/ML      │    │   DE AMENAZAS    │    │  AUTOMATIZADA   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Comunicación segura

- **Protocolo**: TLS 1.2+ con autenticación mutua (mTLS)
- **PKI**: Infraestructura de clave pública con certificados X.509
- **Cifrado**: AES-256-GCM para datos en tránsito
- **Integridad**: HMAC-SHA256 para verificación de mensajes
- **Autenticación**: Certificados de cliente únicos por endpoint

## 4. Lenguajes y Librerías Windows/ML

### Lenguajes principales
- **Python 3.10+**: Core del sistema, análisis ML y orquestación
- **C/C++**: Componentes de bajo nivel, hooks del sistema, performance crítica

### Librerías especializadas

#### Windows Integration
- **Win32 API**: Acceso directo al sistema operativo
- **WMI (Windows Management Instrumentation)**: Telemetría del sistema
- **psutil**: Monitoreo de procesos y recursos
- **pywin32**: Interfaz Python-Windows

#### Machine Learning & Analytics
- **TensorFlow/Keras**: Modelos de deep learning
- **Scikit-Learn**: Algoritmos ML clásicos
- **NumPy/Pandas**: Manipulación de datos
- **PyParsing**: Análisis de logs y eventos

#### Security & Communication
- **cryptography**: Funciones criptográficas
- **requests**: Comunicación HTTP/HTTPS
- **logging**: Sistema de logs estructurado

## 5. Telemetría (Event Logs, Sysmon, ETW, SIEM/EDR)

### Windows Event Logs (IDs relevantes)
- **4624**: Successful logon (análisis de patrones de acceso)
- **4625**: Failed logon (detección de ataques de fuerza bruta)
- **4697**: Service installation (persistencia)
- **1102**: Security log cleared (evasión/cleanup)

### Sysmon Events
- **EventID 1**: Process creation (ejecución de malware)
- **EventID 3**: Network connection (C2 communication)
- **EventID 10**: Process access (LSASS dumping)
- **EventID 13**: Registry value set (persistencia)

### ETW (Event Tracing for Windows)
- **Bajo overhead**: Mínimo impacto en performance
- **Tiempo real**: Stream de eventos en vivo
- **Kernel events**: Acceso a eventos de bajo nivel

### Integración SIEM/EDR
- **SOF-ELK**: Stack de Elasticsearch, Logstash, Kibana
- **SIEM corporativo**: Conectores estándar (Syslog, API REST)
- **Formato CEF/LEEF**: Normalización de eventos

## 6. Reglas Sigma Conceptuales (5 Reglas)

### R1: Reconocimiento - Comandos de red secuenciales
```yaml
title: Sequential Network Reconnaissance Commands
description: Detects sequential execution of network reconnaissance commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\net.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\ping.exe'
    timeframe: 60s
    condition: selection | count() > 3
level: medium
```

### R2: Acceso a SAM/LSASS - Extracción de credenciales
```yaml
title: LSASS Memory Access for Credential Extraction
description: Detects access to LSASS memory for credential dumping
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: 
            - '0x1010'
            - '0x1038'
            - '0x143a'
    condition: selection
level: high
```

### R3: Integridad de binarios críticos
```yaml
title: Critical System Binary Modification
description: Detects modification of critical system binaries
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '\system32\'
            - '\syswow64\'
        Image|endswith:
            - '.exe'
            - '.dll'
            - '.sys'
    condition: selection
level: high
```

### R4: Conexión saliente C2
```yaml
title: Suspicious Outbound C2 Communication
description: Detects potential command and control communication
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Protocol: 'tcp'
        DestinationPort:
            - 443
            - 80
            - 8080
    filter:
        Image|contains: 
            - 'chrome.exe'
            - 'firefox.exe'
            - 'iexplore.exe'
    condition: selection and not filter
level: medium
```

### R5: Autenticaciones masivas contra cuentas deshabilitadas
```yaml
title: Mass Authentication Against Disabled Accounts
description: Detects brute force attacks against disabled accounts
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4625
        Status: '0xC0000072'  # Account disabled
    timeframe: 300s
    condition: selection | count() > 10
level: high
```

## 7. Esqueleto de Proyecto (Código Python)

### Estructura del proyecto
```
vpew-ai/
├── src/
│   ├── __init__.py
│   ├── sensor/
│   │   ├── __init__.py
│   │   ├── agent.py
│   │   ├── collectors/
│   │   │   ├── __init__.py
│   │   │   ├── event_collector.py
│   │   │   ├── sysmon_collector.py
│   │   │   └── etw_collector.py
│   │   └── processors/
│   │       ├── __init__.py
│   │       └── feature_extractor.py
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── anomaly_detector.py
│   │   │   └── threat_classifier.py
│   │   └── training/
│   │       ├── __init__.py
│   │       └── trainer.py
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── sigma_engine.py
│   │   └── rules/
│   │       ├── reconnaissance.yml
│   │       ├── credential_access.yml
│   │       ├── persistence.yml
│   │       ├── lateral_movement.yml
│   │       └── defense_evasion.yml
│   ├── backend/
│   │   ├── __init__.py
│   │   ├── api_server.py
│   │   ├── database.py
│   │   └── elk_connector.py
│   ├── communication/
│   │   ├── __init__.py
│   │   ├── secure_channel.py
│   │   └── pki_manager.py
│   └── response/
│       ├── __init__.py
│       ├── playbook_engine.py
│       └── playbooks/
│           ├── binary_integrity.py
│           ├── credential_extraction.py
│           └── reconnaissance.py
├── config/
│   ├── sysmon_config.xml
│   ├── ml_models.yaml
│   └── deployment.yaml
├── tests/
├── docs/
├── requirements.txt
└── setup.py
```

## 8. Plan de Pruebas (8 Casos) + Playbooks de Respuesta (3)

### Casos de Prueba (P1-P8)

#### P1: Escaneo de red
- **Objetivo**: Validar detección de reconocimiento
- **Escenario**: Ejecución secuencial de nmap, netstat, ping
- **Resultado esperado**: Alerta R1 en <2s

#### P2: Extracción de credenciales
- **Objetivo**: Detectar acceso a LSASS
- **Escenario**: Simulación de mimikatz/procdump
- **Resultado esperado**: Alerta R2 + bloqueo automático

#### P3: Persistencia con servicios
- **Objetivo**: Monitoreo de creación de servicios
- **Escenario**: Instalación de servicio malicioso
- **Resultado esperado**: Alerta + verificación de integridad

#### P4: Evasión AV/EDR
- **Objetivo**: Detectar técnicas de evasión
- **Escenario**: Ofuscación, process hollowing
- **Resultado esperado**: Detección por análisis comportamental

#### P5: Hardening validado
- **Objetivo**: Verificar configuración de seguridad
- **Escenario**: Audit de configuraciones
- **Resultado esperado**: Compliance report

#### P6: Intento de borrar logs
- **Objetivo**: Detectar cleanup activities
- **Escenario**: wevtutil cl Security
- **Resultado esperado**: Alerta R5 + backup automático

#### P7: Validación defensiva
- **Objetivo**: Verificar controles defensivos
- **Escenario**: Red team simulation
- **Resultado esperado**: Coverage >80% MITRE ATT&CK

#### P8: Evasión blackbox
- **Objetivo**: Prueba sin conocimiento previo
- **Escenario**: Ataque externo simulado
- **Resultado esperado**: Detección en kill chain temprano

### Playbooks de Respuesta

#### PB1: Violación de integridad binaria
```python
def binary_integrity_response(alert):
    # 1. Aislar endpoint afectado
    # 2. Crear snapshot forense
    # 3. Restaurar desde backup verificado
    # 4. Análisis de impacto
    # 5. Reporte ejecutivo
```

#### PB2: Extracción de credenciales
```python
def credential_extraction_response(alert):
    # 1. Bloqueo inmediato de cuentas comprometidas
    # 2. Forzar cambio de contraseñas
    # 3. Análisis de accesos laterales
    # 4. Invalidar tokens/tickets Kerberos
    # 5. Monitoreo extendido
```

#### PB3: Barrido/reconocimiento anómalo
```python
def reconnaissance_response(alert):
    # 1. Análisis de patrones de red
    # 2. Identificación de origen
    # 3. Bloqueo de IP/segmentos sospechosos
    # 4. Refuerzo de monitoreo
    # 5. Threat hunting proactivo
```

## 9. Métricas de Calidad

### Indicadores de Rendimiento
- **Latencia de detección**: <2 segundos
- **Retención de logs**: >90 días
- **Falsos positivos**: <1%
- **Cobertura MITRE ATT&CK**: ≥80%

### Métricas Operacionales
- **Disponibilidad del sistema**: 99.9%
- **Throughput de eventos**: 10,000 EPS
- **Tiempo de respuesta API**: <100ms
- **Precisión de ML**: >95%

## 10. Roadmap de Despliegue

### Fase 1: Laboratorio (4 semanas)
- **Semana 1-2**: Hardening y configuración base
- **Semana 3**: Configuración Sysmon optimizada
- **Semana 4**: Entrenamiento ML base con datasets

### Fase 2: Piloto (6 semanas)
- **Semana 1-2**: Despliegue en 20 endpoints críticos
- **Semana 3-4**: Validación en campo y ajustes
- **Semana 5**: Optimización reglas Sigma
- **Semana 6**: Pruebas de carga y performance

### Fase 3: Producción (8 semanas)
- **Semana 1-4**: Despliegue masivo en 480 endpoints
- **Semana 5-6**: Integración completa con SIEM
- **Semana 7-8**: Capacitación SOC y documentación

### Fase 4: Operación continua (Trimestral)
- **Mes 1**: Reentrenamiento de modelos ML
- **Mes 2**: Ajuste de métricas y umbrales
- **Mes 3**: Revisión de cobertura ATT&CK y nuevas amenazas

---

## Configuración Inicial de Sysmon

La configuración de Sysmon es crítica para obtener la telemetría necesaria. Ver `config/sysmon_config.xml` para la configuración completa.

## Disclaimer Legal

**Uso exclusivo en defensa corporativa**. Esta herramienta no ejecuta exploits ni payloads ofensivos. Su uso requiere conformidad con políticas corporativas y normativas legales aplicables. El sistema está diseñado exclusivamente para protección defensiva y no debe utilizarse para actividades ofensivas o no autorizadas.
