# AI-Powered Honeypot & Incident Response System


---

Sistema de detección y respuesta a incidentes basado en honeypot e inteligencia artificial, desarrollado como Trabajo Fin de Máster (TFM).

El objetivo del proyecto es demostrar la viabilidad de una plataforma de ciberseguridad capaz de **detectar, clasificar y responder automáticamente a ataques en tiempo real** utilizando únicamente herramientas open source.

---

## 🚀 Vista general

<img width="1892" height="652" alt="Captura de pantalla 2026-06-25 154629" src="https://github.com/user-attachments/assets/04ad1adc-b3e7-4525-a0b3-e9a502a0a403" />


Plataforma completa desplegada con Docker Compose que integra:

- Simulación de ataques (Red Team)
- Detección mediante Machine Learning
- Respuesta automática (Blue Team)
- Monitorización y visualización en tiempo real

---

## 🧠 Características

- Honeypot web realista (Flask)
- Detección automática de tráfico malicioso
- Clasificación con Machine Learning
- Respuesta automática en tiempo real
- Bloqueo dinámico de IPs
- Geolocalización de atacantes (GeoLite2)
- Generación automática de informes PDF
- Dashboard de monitorización (Grafana)
- Simulación de ataques Red Team
- Mapeo MITRE ATT&CK
- Arquitectura completamente dockerizada

---

## 🏗️ Arquitectura

### Honeypot (Flask)
Endpoints trampa:
- `/admin`
- `/login`
- `/wp-login`
- `/.env`
- `/phpmyadmin`
- `/config.php`

Captura y registra toda la actividad sospechosa.

---

### Backend (FastAPI)

- Procesamiento de eventos en tiempo real
- Inferencia del modelo de ML
- Geolocalización de IPs
- Generación de informes PDF
- API REST

---

### Worker

- Procesa logs cada 3 segundos
- Conecta honeypot ↔ backend
- Envío de eventos en tiempo real

---

### Grafana

- Métricas en tiempo real
- Incidentes detectados
- Distribución de ataques
- Visualización geográfica

---

## 🤖 Machine Learning

Modelos evaluados:

- Random Forest ✅ (seleccionado)
- XGBoost
- SVM
- MLP

### Dataset

- 4.200 muestras sintéticas
- Balanceado con SMOTE
- 14 features HTTP

### Features

- URL length
- Payload entropy
- User-Agent
- Request frequency per IP
- SQLi indicators
- XSS indicators
- Path Traversal
- Command Injection

### Clases

- Normal
- SQL Injection
- XSS
- Path Traversal
- Command Injection
- Brute Force
- Scanner / Bot

---

## ⚔️ Red Team Simulation

Herramientas utilizadas:

- Nmap
- Nikto
- SQLMap
- Hydra
- Searchsploit
- Curl manual attacks

### MITRE ATT&CK

| Técnica | Descripción |
|----------|-------------|
| T1595 | Active Scanning |
| T1190 | Exploit Public-Facing Application |
| T1110 | Brute Force |

---

## 🛡️ Blue Team Response

| Confianza | Acción |
|----------|--------|
| ≥ 90% | Bloqueo automático de IP |
| 70–89% | Alerta en dashboard |
| < 70% | Registro para análisis |

Cada incidente genera:

- Clasificación automática
- Evidencia del ataque
- Geolocalización
- Informe PDF

---

## 📊 Resultados

- +427 incidentes detectados
- 399 informes PDF generados
- 102 alertas registradas
- 7 IPs bloqueadas automáticamente
- 7 tipos de ataque clasificados
- Integración MITRE ATT&CK

---

## ⚠️ Limitaciones

Hydra puede clasificarse como Scanner/Bot debido al peso del User-Agent en el modelo.

### Trabajo futuro:
- Dataset real
- Rebalanceo de clases
- Feature engineering avanzado
- Nuevos modelos

---

## 🧰 Tecnologías

Python · Flask · FastAPI · Scikit-learn · Docker · Grafana · GeoLite2 · Pandas · NumPy · Kali Linux

---

## ⚙️ Instalación

```bash
git clone https://github.com/AlexHurtado04/TFM.git
cd TFM
docker compose up --build
```

---

## 🌐 Servicios

- Honeypot → http://localhost:5000  
- API → http://localhost:8000  
- Grafana → http://localhost:3000  

---

## 📁 Estructura

```
TFM/
├── honeypot/
├── backend/
├── worker/
├── grafana/
├── models/
├── datasets/
├── reports/
├── docs/
└── docker-compose.yml
```

---

## 👨‍💻 Autor

Alex Hurtado  
TFM – Máster en Ciberseguridad
