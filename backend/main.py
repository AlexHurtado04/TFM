from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import os
import json
import datetime
import math
import re
import joblib
import numpy as np
from pathlib import Path
from typing import Optional
import geoip2.database
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm

app = FastAPI(title="TFM - Sistema de Clasificación de Ataques")

REPORTS_DIR = "/reports"
LOGS_DIR    = "/data"
MODEL_PATH  = "/model/classifier.joblib"
GEOIP_PATH  = "/geoip/GeoLite2-City.mmdb"
GEOASN_PATH = "/geoip/GeoLite2-ASN.mmdb"

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR,    exist_ok=True)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

# ─────────────────────────────────────────────
# MODELO IA — carga en memoria al arrancar
# ─────────────────────────────────────────────

model = None
if Path(MODEL_PATH).exists():
    model = joblib.load(MODEL_PATH)

ATTACK_LABELS = [
    "Normal",
    "SQL Injection",
    "XSS",
    "Path Traversal",
    "Command Injection",
    "Brute Force",
    "Scanner/Bot"
]

# ─────────────────────────────────────────────
# EXTRACCIÓN DE FEATURES
# ─────────────────────────────────────────────

def extract_features(log: dict) -> np.ndarray:
    path    = log.get("path", "")
    payload = log.get("payload", "")
    ua      = log.get("user_agent", "")
    qs      = log.get("query_string", "")
    full    = path + " " + payload + " " + qs

    # Longitud
    url_len     = len(path)
    payload_len = len(payload)

    # Número de parámetros
    num_params = payload.count("&") + qs.count("&") + 1 if (payload or qs) else 0

    # Caracteres especiales
    special_chars = sum(full.count(c) for c in ["'", '"', "<", ">", "/", "\\", ";", "|", "`"])

    # Patrones SQL
    sql_keywords = ["union", "select", "insert", "update", "delete", "drop", "exec",
                    "or 1=1", "' or", "-- ", "/*", "xp_", "information_schema"]
    sql_score = sum(1 for k in sql_keywords if k in full.lower())

    # Patrones XSS
    xss_keywords = ["<script", "onerror", "onload", "alert(", "javascript:", "eval(",
                    "document.cookie", "window.location", "innerHTML"]
    xss_score = sum(1 for k in xss_keywords if k in full.lower())

    # Path traversal
    traversal_score = full.count("../") + full.count("..\\") + full.count("%2e%2e")

    # Command injection
    cmd_keywords = [";", "&&", "||", "|", "`", "$(", "wget ", "curl ", "chmod ", "bash ", "sh "]
    cmd_score = sum(1 for k in cmd_keywords if k in full)

    # Entropía del payload
    entropy = 0.0
    if payload:
        freq = {}
        for c in payload:
            freq[c] = freq.get(c, 0) + 1
        for f in freq.values():
            p = f / len(payload)
            entropy -= p * math.log2(p)

    # User-Agent sospechoso
    bad_agents = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "hydra",
                  "dirbuster", "gobuster", "wfuzz", "burpsuite", "python-requests",
                  "curl", "wget", "scrapy", "metasploit"]
    ua_suspicious = int(any(b in ua.lower() for b in bad_agents))

    # Método HTTP
    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "OPTIONS": 5}
    method_enc = method_map.get(log.get("method", "GET"), 0)

    # Frecuencias
    freq_1  = log.get("freq_1min",  0)
    freq_5  = log.get("freq_5min",  0)
    freq_15 = log.get("freq_15min", 0)

    return np.array([[
        url_len, payload_len, num_params, special_chars,
        sql_score, xss_score, traversal_score, cmd_score,
        entropy, ua_suspicious, method_enc,
        freq_1, freq_5, freq_15
    ]])

# ─────────────────────────────────────────────
# GEOLOCALIZACIÓN
# ─────────────────────────────────────────────

def geolocate(ip: str) -> dict:
    result = {
        "country": "Desconocido",
        "country_code": "XX",
        "city": "Desconocido",
        "lat": 0.0,
        "lon": 0.0,
        "asn": "Desconocido",
        "org": "Desconocido",
        "is_tor": False,
        "abuse_score": 0,
        "abuse_reports": 0
    }

    # Ignora IPs locales
    if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "::1":
        result["country"] = "Local"
        result["city"]    = "Localhost"
        return result

    # GeoLite2 City
    if Path(GEOIP_PATH).exists():
        try:
            with geoip2.database.Reader(GEOIP_PATH) as reader:
                r = reader.city(ip)
                result["country"]      = r.country.name or "Desconocido"
                result["country_code"] = r.country.iso_code or "XX"
                result["city"]         = r.city.name or "Desconocido"
                result["lat"]          = float(r.location.latitude  or 0)
                result["lon"]          = float(r.location.longitude or 0)
        except:
            pass

    # GeoLite2 ASN
    if Path(GEOASN_PATH).exists():
        try:
            with geoip2.database.Reader(GEOASN_PATH) as reader:
                r = reader.asn(ip)
                result["asn"] = f"AS{r.autonomous_system_number}"
                result["org"] = r.autonomous_system_organization or "Desconocido"
        except:
            pass

    # AbuseIPDB
    if ABUSEIPDB_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=3
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                result["abuse_score"]   = d.get("abuseConfidenceScore", 0)
                result["abuse_reports"] = d.get("totalReports", 0)
                result["is_tor"]        = d.get("isTor", False)
        except:
            pass

    return result

# ─────────────────────────────────────────────
# GENERACIÓN DE INFORME PDF
# ─────────────────────────────────────────────

def generate_pdf_report(log: dict, geo: dict, attack_type: str, confidence: float, action: str) -> str:
    incident_id = log.get("id", "N/A")
    filename    = f"{REPORTS_DIR}/incidente_{incident_id}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc    = SimpleDocTemplate(filename, pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # Estilos personalizados
    title_style = ParagraphStyle("title", parent=styles["Heading1"],
                                 fontSize=18, textColor=colors.HexColor("#1a237e"),
                                 spaceAfter=6)
    section_style = ParagraphStyle("section", parent=styles["Heading2"],
                                   fontSize=13, textColor=colors.HexColor("#283593"),
                                   spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("body", parent=styles["Normal"],
                                fontSize=10, leading=16)
    alert_style = ParagraphStyle("alert", parent=styles["Normal"],
                                 fontSize=11, textColor=colors.white,
                                 backColor=colors.HexColor("#c62828"),
                                 borderPadding=8, leading=16)

    # Severidad
    severity_color = {
        "Normal":           "#4caf50",
        "Scanner/Bot":      "#ff9800",
        "Brute Force":      "#f44336",
        "XSS":              "#f44336",
        "SQL Injection":    "#b71c1c",
        "Path Traversal":   "#f44336",
        "Command Injection":"#b71c1c",
    }.get(attack_type, "#f44336")

    # ── CABECERA ──
    story.append(Paragraph("🔴 INFORME DE INCIDENTE DE SEGURIDAD", title_style))
    story.append(Paragraph(f"<b>ID Incidente:</b> #{incident_id} &nbsp;&nbsp; "
                           f"<b>Fecha:</b> {log.get('timestamp','')[:19].replace('T',' ')} UTC",
                           body_style))
    story.append(HRFlowable(width="100%", thickness=2,
                            color=colors.HexColor("#1a237e"), spaceAfter=12))

    # ── ALERTA TIPO DE ATAQUE ──
    story.append(Paragraph(
        f"⚠️  ATAQUE DETECTADO: {attack_type.upper()}  —  Confianza: {confidence:.1f}%  —  Acción: {action}",
        ParagraphStyle("alert2", parent=styles["Normal"],
                       fontSize=11, textColor=colors.white,
                       backColor=colors.HexColor(severity_color),
                       borderPadding=10, leading=18)
    ))
    story.append(Spacer(1, 14))

    # ── INFORMACIÓN DEL ATACANTE ──
    story.append(Paragraph("1. INFORMACIÓN DEL ATACANTE", section_style))

    flag_map = {
        "ES":"🇪🇸","US":"🇺🇸","RU":"🇷🇺","CN":"🇨🇳","DE":"🇩🇪",
        "FR":"🇫🇷","BR":"🇧🇷","IN":"🇮🇳","NL":"🇳🇱","GB":"🇬🇧",
        "UA":"🇺🇦","TR":"🇹🇷","KR":"🇰🇷","JP":"🇯🇵","IT":"🇮🇹"
    }
    flag = flag_map.get(geo.get("country_code","XX"), "🌍")

    attacker_data = [
        ["Campo", "Valor"],
        ["Dirección IP",       log.get("ip", "N/A")],
        ["País",               f"{flag} {geo.get('country','Desconocido')}"],
        ["Ciudad",             geo.get("city", "Desconocido")],
        ["Coordenadas",        f"{geo.get('lat',0):.4f}, {geo.get('lon',0):.4f}"],
        ["ASN / ISP",          f"{geo.get('asn','?')} — {geo.get('org','Desconocido')}"],
        ["Score AbuseIPDB",    f"{geo.get('abuse_score',0)}/100 ({geo.get('abuse_reports',0)} reportes)"],
        ["Nodo Tor",           "⚠️ SÍ — ubicación no fiable" if geo.get("is_tor") else "No"],
    ]

    t = Table(attacker_data, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
        ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 10),
        ("BACKGROUND",   (0,1), (-1,-1), colors.HexColor("#f5f5f5")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#e8eaf6")]),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#bdbdbd")),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # ── DETALLES DEL ATAQUE ──
    story.append(Paragraph("2. DETALLES DEL ATAQUE", section_style))

    attack_data = [
        ["Campo",           "Valor"],
        ["Tipo de ataque",  attack_type],
        ["Confianza IA",    f"{confidence:.1f}%"],
        ["Endpoint",        log.get("path", "N/A")[:80]],
        ["Método HTTP",     log.get("method", "N/A")],
        ["User-Agent",      (log.get("user_agent","N/A") or "N/A")[:80]],
        ["Referer",         (log.get("referer","—") or "—")[:80]],
    ]

    t2 = Table(attack_data, colWidths=[5*cm, 12*cm])
    t2.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#283593")),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#e8eaf6")]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#bdbdbd")),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(t2)
    story.append(Spacer(1, 14))

    # ── PAYLOAD CAPTURADO ──
    if log.get("payload"):
        story.append(Paragraph("3. PAYLOAD CAPTURADO", section_style))
        payload_text = log["payload"][:1000].replace("<","&lt;").replace(">","&gt;")
        story.append(Paragraph(
            payload_text,
            ParagraphStyle("code", parent=styles["Code"],
                           fontSize=9, backColor=colors.HexColor("#263238"),
                           textColor=colors.HexColor("#a5d6a7"),
                           borderPadding=10, leading=14)
        ))
        story.append(Spacer(1, 14))

    # ── CONTEXTO / FRECUENCIA ──
    story.append(Paragraph("4. CONTEXTO — ACTIVIDAD DE LA IP", section_style))

    ctx_data = [
        ["Ventana temporal",  "Peticiones desde esta IP"],
        ["Último 1 minuto",   str(log.get("freq_1min",  0))],
        ["Últimos 5 minutos", str(log.get("freq_5min",  0))],
        ["Últimos 15 minutos",str(log.get("freq_15min", 0))],
    ]
    t3 = Table(ctx_data, colWidths=[7*cm, 10*cm])
    t3.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#37474f")),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#eceff1")]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#bdbdbd")),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(t3)
    story.append(Spacer(1, 14))

    # ── ACCIÓN TOMADA ──
    story.append(Paragraph("5. ACCIÓN TOMADA", section_style))
    action_color = "#c62828" if "Bloqueada" in action else "#e65100" if "Alerta" in action else "#1b5e20"
    story.append(Paragraph(
        f"✅ {action}",
        ParagraphStyle("action", parent=styles["Normal"],
                       fontSize=11, textColor=colors.white,
                       backColor=colors.HexColor(action_color),
                       borderPadding=10, leading=18)
    ))
    story.append(Spacer(1, 20))

    # ── PIE ──
    story.append(HRFlowable(width="100%", thickness=1,
                            color=colors.HexColor("#bdbdbd"), spaceBefore=8))
    story.append(Paragraph(
        f"Generado automáticamente por TFM-SecuritySystem · "
        f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        ParagraphStyle("footer", parent=styles["Normal"],
                       fontSize=8, textColor=colors.grey, alignment=1)
    ))

    doc.build(story)
    return filename

# ─────────────────────────────────────────────
# ENDPOINT PRINCIPAL — analiza un log
# ─────────────────────────────────────────────

class LogEntry(BaseModel):
    id:          str
    timestamp:   str
    ip:          str
    method:      str
    path:        str
    endpoint_type: str
    user_agent:  Optional[str] = ""
    referer:     Optional[str] = ""
    query_string:Optional[str] = ""
    payload:     Optional[str] = ""
    freq_1min:   int = 0
    freq_5min:   int = 0
    freq_15min:  int = 0

@app.post("/analyze")
async def analyze(entry: LogEntry, background_tasks: BackgroundTasks):
    log = entry.dict()

    # 1. Geolocalizar
    geo = geolocate(log["ip"])

    # 2. Clasificar con IA
    if model is not None:
        features    = extract_features(log)
        pred        = model.predict(features)[0]
        proba       = model.predict_proba(features)[0]
        attack_type = ATTACK_LABELS[pred]
        confidence  = float(max(proba)) * 100
    else:
        # Sin modelo entrenado aún — usa heurísticas básicas
        attack_type, confidence = classify_heuristic(log)

    # 3. Decidir acción
    if attack_type == "Normal":
        action = "Registrado — tráfico normal"
    elif confidence >= 90:
        action = f"IP Bloqueada automáticamente (confianza {confidence:.1f}%)"
    elif confidence >= 70:
        action = f"Alerta generada en dashboard (confianza {confidence:.1f}%)"
    else:
        action = f"Registrado como sospechoso para revisión manual (confianza {confidence:.1f}%)"

    # 4. Guardar resultado
    result = {
        **log,
        "geo":         geo,
        "attack_type": attack_type,
        "confidence":  confidence,
        "action":      action
    }
    with open(f"{LOGS_DIR}/classified_{log['id']}.json", "w") as f:
        json.dump(result, f, indent=2)

    # 5. Generar PDF en background si es ataque
    if attack_type != "Normal":
        background_tasks.add_task(
            generate_pdf_report, log, geo, attack_type, confidence, action
        )

    return result

# ─────────────────────────────────────────────
# HEURÍSTICAS — cuando no hay modelo entrenado
# ─────────────────────────────────────────────

def classify_heuristic(log: dict) -> tuple:
    full = (log.get("path","") + " " + log.get("payload","") + " " + log.get("query_string","")).lower()
    ua   = log.get("user_agent","").lower()

    sql_kw  = ["union select","or 1=1","' or","information_schema","xp_cmd","drop table","insert into"]
    xss_kw  = ["<script","onerror=","alert(","javascript:","document.cookie"]
    trav_kw = ["../","..\\","%2e%2e","etc/passwd","etc/shadow"]
    cmd_kw  = [";ls","&&cat","|whoami","$(id)","bash -i","wget http","curl http"]
    scan_ua = ["sqlmap","nikto","nmap","masscan","hydra","burp","dirbuster","gobuster","zgrab","python-requests"]
    bf_ep   = ["wp-login","admin","phpmyadmin","api/v1/login"]

    if any(k in full for k in sql_kw):   return "SQL Injection",    92.0
    if any(k in full for k in xss_kw):   return "XSS",              88.0
    if any(k in full for k in trav_kw):  return "Path Traversal",   85.0
    if any(k in full for k in cmd_kw):   return "Command Injection", 87.0
    if any(k in ua   for k in scan_ua):  return "Scanner/Bot",       91.0
    if any(k in full for k in bf_ep) and log.get("freq_1min",0) > 5:
                                          return "Brute Force",       83.0
    return "Normal", 95.0

# ─────────────────────────────────────────────
# ENDPOINTS AUXILIARES
# ─────────────────────────────────────────────

@app.get("/reports")
def list_reports():
    files = sorted(Path(REPORTS_DIR).glob("*.pdf"), reverse=True)
    return [{"filename": f.name, "size_kb": round(f.stat().st_size/1024,1)} for f in files[:50]]

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}
