# VPEW-AI Deployment Guide

## Guía de Despliegue Completa

Esta guía proporciona instrucciones detalladas para desplegar VPEW-AI en un entorno de producción siguiendo las mejores prácticas de seguridad.

## Prerrequisitos del Sistema

### Hardware Mínimo
- **Endpoints**: 2GB RAM, 1GB espacio libre, CPU dual-core
- **Backend**: 8GB RAM, 100GB espacio libre, CPU quad-core
- **Red**: Conectividad TLS 1.2+ entre endpoints y backend

### Software Requerido
- **Windows**: 10/11 o Server 2016-2019
- **Python**: 3.10 o superior
- **Sysmon**: Versión 13.0 o superior (recomendado)
- **PowerShell**: 5.1 o superior

## Fase 1: Preparación del Laboratorio (4 semanas)

### Semana 1-2: Hardening y Configuración Base

#### 1. Preparar Infraestructura PKI

```powershell
# Crear directorio de certificados
mkdir C:\VPEW-AI\certs

# Generar CA privada (usar HSM en producción)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# Generar certificados de cliente para cada endpoint
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

#### 2. Configurar Sysmon

```powershell
# Descargar e instalar Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Instalar con configuración VPEW-AI
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i config\sysmon_config.xml
```

#### 3. Hardening del Sistema

```powershell
# Habilitar logging avanzado
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

# Configurar retención de logs
wevtutil sl Security /ms:134217728  # 128MB
wevtutil sl System /ms:67108864     # 64MB
wevtutil sl Application /ms:67108864 # 64MB

# Habilitar PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

### Semana 3: Configuración de Sysmon Optimizada

#### Validar Configuración Sysmon

```powershell
# Verificar instalación
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10

# Monitorear rendimiento
Get-Counter "\Process(Sysmon64)\% Processor Time"
Get-Counter "\Process(Sysmon64)\Working Set"
```

### Semana 4: Entrenamiento ML Base

#### Preparar Datos de Entrenamiento

```python
# Recopilar datos baseline durante 1 semana
python src/vpew_ai/ml/training/trainer.py --collect-baseline --duration 7d

# Entrenar modelos iniciales
python src/vpew_ai/ml/training/trainer.py --train-anomaly-detector
python src/vpew_ai/ml/training/trainer.py --train-threat-classifier
```

## Fase 2: Piloto (6 semanas)

### Semana 1-2: Despliegue en 20 Endpoints Críticos

#### Instalación del Agente

```powershell
# En cada endpoint
git clone https://github.com/empresa/vpew-ai.git
cd vpew-ai

# Instalar dependencias
pip install -r requirements.txt
pip install -e .

# Configurar agente
cp config/agent_config.yaml.template config/agent_config.yaml
# Editar configuración específica del endpoint

# Copiar certificados
copy \\server\certs\client.crt certs\
copy \\server\certs\client.key certs\
copy \\server\certs\ca.crt certs\

# Instalar como servicio Windows
python setup.py install_service
```

#### Configuración del Backend

```bash
# En servidor backend
python src/vpew_ai/backend/api_server.py --host 0.0.0.0 --port 8443 --ssl-cert certs/server.crt --ssl-key certs/server.key
```

### Semana 3-4: Validación en Campo

#### Tests de Integración

```powershell
# Ejecutar tests de validación
python tests/test_integration.py

# Verificar conectividad
python -c "from vpew_ai.communication import SecureChannel; sc = SecureChannel('certs/client.crt', 'certs/client.key', 'certs/ca.crt'); print(sc.test_connection('https://backend:8443'))"
```

#### Monitoreo de Rendimiento

```powershell
# Monitorear agente VPEW-AI
Get-Counter "\Process(python)\% Processor Time"
Get-Counter "\Process(python)\Working Set"

# Verificar logs
Get-Content logs/vpew-agent.log -Tail 50
```

### Semana 5: Optimización de Reglas Sigma

#### Ajuste de Falsos Positivos

```python
# Analizar falsos positivos
python scripts/analyze_false_positives.py --days 7

# Ajustar umbrales
python scripts/tune_sigma_rules.py --false-positive-rate 0.01
```

### Semana 6: Pruebas de Carga

#### Test de Carga

```python
# Simular carga de eventos
python tests/load_test.py --endpoints 20 --events-per-second 1000 --duration 3600
```

## Fase 3: Producción (8 semanas)

### Semana 1-4: Despliegue Masivo

#### Automatización del Despliegue

```powershell
# Script de despliegue masivo
$endpoints = Get-Content "endpoints.txt"

foreach ($endpoint in $endpoints) {
    Invoke-Command -ComputerName $endpoint -ScriptBlock {
        # Instalar VPEW-AI
        & "\\server\scripts\install_vpew_agent.ps1"
    }
}
```

#### Monitoreo Centralizado

```python
# Dashboard de monitoreo
python src/vpew_ai/backend/dashboard.py --port 8080
```

### Semana 5-6: Integración SIEM

#### Configurar Envío a ELK

```yaml
# config/elk_config.yaml
elasticsearch:
  hosts: ["elk-cluster:9200"]
  index_template: "vpew-ai-events"
  
logstash:
  host: "logstash:5044"
  protocol: "beats"
```

#### Configurar Alertas

```json
{
  "trigger": {
    "schedule": {
      "interval": "1m"
    }
  },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": ["vpew-ai-*"],
        "body": {
          "query": {
            "bool": {
              "filter": [
                {"range": {"@timestamp": {"gte": "now-5m"}}},
                {"term": {"severity": "high"}}
              ]
            }
          }
        }
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": ["soc@empresa.com"],
        "subject": "VPEW-AI High Severity Alert",
        "body": "High severity threat detected: {{ctx.payload.hits.total}}"
      }
    }
  }
}
```

### Semana 7-8: Capacitación SOC

#### Material de Capacitación

1. **Introducción a VPEW-AI**
   - Arquitectura y componentes
   - Tipos de amenazas detectadas
   - Interfaz de usuario

2. **Análisis de Alertas**
   - Interpretación de alertas ML
   - Validación de reglas Sigma
   - Escalación de incidentes

3. **Respuesta a Incidentes**
   - Playbooks automatizados
   - Investigación manual
   - Contención y remediación

#### Ejercicios Prácticos

```powershell
# Simulación de amenazas para entrenamiento
python scripts/threat_simulation.py --scenario reconnaissance
python scripts/threat_simulation.py --scenario credential_access
python scripts/threat_simulation.py --scenario persistence
```

## Fase 4: Operación Continua

### Mantenimiento Mensual

#### Mes 1: Reentrenamiento ML

```python
# Recopilar nuevos datos
python src/vpew_ai/ml/training/data_collector.py --period 30d

# Reentrenar modelos
python src/vpew_ai/ml/training/trainer.py --retrain --incremental

# Validar rendimiento
python src/vpew_ai/ml/evaluation/model_validator.py
```

#### Mes 2: Ajuste de Métricas

```python
# Analizar métricas de rendimiento
python scripts/performance_analysis.py --period 30d

# Ajustar umbrales
python scripts/threshold_tuning.py --target-fpr 0.01

# Actualizar configuración
python scripts/update_agent_config.py --config-version 1.1
```

#### Mes 3: Revisión ATT&CK

```python
# Evaluar cobertura MITRE ATT&CK
python scripts/attack_coverage_analysis.py

# Identificar gaps
python scripts/coverage_gap_analysis.py

# Desarrollar nuevas reglas
python scripts/rule_generator.py --techniques T1003,T1055,T1078
```

## Métricas de Calidad

### KPIs Operacionales

```python
# Script de métricas diarias
python scripts/daily_metrics.py

# Métricas esperadas:
# - Latencia detección: <2s (objetivo: <1s)
# - Falsos positivos: <1% (objetivo: <0.5%)
# - Disponibilidad: >99.9%
# - Cobertura ATT&CK: >80% (objetivo: >90%)
```

### Alertas de Salud del Sistema

```yaml
# config/health_alerts.yaml
metrics:
  - name: "agent_offline"
    condition: "last_seen > 5m"
    severity: "warning"
    
  - name: "high_false_positive_rate"
    condition: "false_positive_rate > 0.02"
    severity: "critical"
    
  - name: "low_detection_coverage"
    condition: "attack_coverage < 0.75"
    severity: "warning"
```

## Troubleshooting

### Problemas Comunes

#### Agente No Conecta

```powershell
# Verificar conectividad
Test-NetConnection -ComputerName backend.empresa.com -Port 8443

# Verificar certificados
certlm.msc

# Verificar logs
Get-EventLog -LogName Application -Source "VPEW-AI"
```

#### Alto Consumo de Recursos

```powershell
# Ajustar configuración
$config = Get-Content config/agent_config.yaml | ConvertFrom-Yaml
$config.collection.interval = 10  # Reducir frecuencia
$config.performance.max_cpu_usage = 5  # Limitar CPU
$config | ConvertTo-Yaml | Set-Content config/agent_config.yaml
```

#### Falsos Positivos

```python
# Analizar y ajustar reglas
python scripts/false_positive_analysis.py --rule-id vpew-r1-reconnaissance
python scripts/rule_tuner.py --rule-id vpew-r1-reconnaissance --target-fpr 0.005
```

## Seguridad

### Mejores Prácticas

1. **Certificados**
   - Renovar certificados cada 12 meses
   - Usar HSM para claves CA
   - Implementar rotación automática

2. **Comunicaciones**
   - Solo TLS 1.2+
   - Validar certificados siempre
   - Usar mTLS en producción

3. **Acceso**
   - Principio de menor privilegio
   - Autenticación multifactor
   - Auditoría de accesos

### Monitoreo de Seguridad

```python
# Verificación diaria de seguridad
python scripts/security_check.py
# - Validar integridad de certificados
# - Verificar configuraciones de seguridad
# - Auditar accesos al sistema
```

## Backup y Recuperación

### Backup Diario

```powershell
# Script de backup
$backupPath = "\\backup-server\vpew-ai\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $backupPath -Force

# Backup configuraciones
Copy-Item -Path "config\*" -Destination "$backupPath\config\" -Recurse

# Backup modelos ML
Copy-Item -Path "models\*" -Destination "$backupPath\models\" -Recurse

# Backup certificados
Copy-Item -Path "certs\*" -Destination "$backupPath\certs\" -Recurse
```

### Procedimiento de Recuperación

```powershell
# En caso de fallo del sistema
$restoreDate = "2024-01-15"
$backupPath = "\\backup-server\vpew-ai\$restoreDate"

# Restaurar configuraciones
Copy-Item -Path "$backupPath\config\*" -Destination "config\" -Recurse -Force

# Restaurar modelos
Copy-Item -Path "$backupPath\models\*" -Destination "models\" -Recurse -Force

# Reiniciar servicios
Restart-Service "VPEW-AI Agent"
```

---

## Contacto y Soporte

**Equipo SOC**: soc@empresa.com
**Soporte Técnico**: soporte-vpew@empresa.com
**Emergencias**: +1-800-SOC-HELP

Para más información, consulte la documentación completa en el repositorio del proyecto.
