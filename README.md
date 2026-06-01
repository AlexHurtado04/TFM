# TFM — Sistema WAF/Honeypot con clasificación de ataques mediante IA

**Alejandro Hurtado Ramírez — Curso Profesional de Ciberseguridad — UNIR**

---

## ⚠️ Aviso legal

Este sistema está diseñado **exclusivamente para uso académico y en entorno local controlado**.
Todos los ataques simulados se realizan **únicamente contra la infraestructura Docker de este proyecto**.
Queda prohibido su uso contra sistemas de terceros o en producción.

---

## Arquitectura

```
[Tú / Kali Linux]
      │
      │  HTTP (ataques simulados)
      ▼
┌─────────────────┐     logs      ┌──────────────────┐
│  Honeypot web   │ ────────────► │  Backend FastAPI  │
│  :8080          │               │  + Modelo IA      │
│  (endpoints     │               │  :8000            │
│   trampa)       │               │                   │
└─────────────────┘               │  Geolocalización  │
                                  │  Informe PDF       │
                                  └──────────────────┘
                                          │
                                          ▼
                                  ┌──────────────────┐
                                  │  Grafana          │
                                  │  Dashboard :3000  │
                                  └──────────────────┘
```

---

## Requisitos

- Docker + Docker Compose
- Python 3.11 (para entrenar el modelo)
- 4 GB RAM mínimo
- Kali Linux (máquina atacante)

---

## Instalación paso a paso

### 1. Clonar el repositorio
```bash
git clone https://github.com/AlexHurtado04/TFM.git
cd TFM
```

### 2. Crear el archivo .env
```bash
cp .env.example .env
# Edita .env y añade tu API key de AbuseIPDB
```

### 3. Descargar las bases de datos GeoLite2 (MaxMind)
- Regístrate gratis en https://www.maxmind.com/en/geolite2/signup
- Descarga **GeoLite2-City.mmdb** y **GeoLite2-ASN.mmdb**
- Cópialos a la carpeta `geoip/`:
```bash
mkdir -p geoip
cp ~/Descargas/GeoLite2-City.mmdb geoip/
cp ~/Descargas/GeoLite2-ASN.mmdb geoip/
```

### 4. Entrenar el modelo de IA
```bash
cd backend
pip install -r requirements.txt
python train_model.py
cd ..
```

### 5. Arrancar todos los servicios
```bash
docker compose up --build -d
```

### 6. Verificar que todo está activo
```bash
docker compose ps
```

---

## URLs del sistema

| Servicio | URL | Descripción |
|---|---|---|
| Honeypot | http://localhost:8080 | Web señuelo |
| Backend IA | http://localhost:8000 | API de clasificación |
| Dashboard | http://localhost:3000 | Grafana (admin/tfm2024) |
| Informes | `./reports/` | PDFs generados por incidente |

---

## Ver logs en tiempo real

```bash
# Worker procesando ataques
docker logs -f tfm-worker

# Honeypot recibiendo peticiones
docker logs -f tfm-honeypot

# Backend clasificando
docker logs -f tfm-backend
```

---

## Ver informes generados

```bash
ls -la reports/
```

Los PDFs se generan automáticamente en la carpeta `reports/` cada vez que el modelo detecta un ataque.

---

## Parar el sistema

```bash
docker compose down
```
