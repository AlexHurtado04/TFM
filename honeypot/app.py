from flask import Flask, request, jsonify, render_template_string
import json
import os
import datetime
import hashlib
from collections import defaultdict
import threading

app = Flask(__name__)

# Almacenamiento en memoria de logs (se persiste en archivo)
logs = []
ip_request_count = defaultdict(list)
logs_lock = threading.Lock()

LOGS_FILE = "/data/honeypot_logs.json"
os.makedirs("/data", exist_ok=True)

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────

def save_log(entry):
    with logs_lock:
        logs.append(entry)
        with open(LOGS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def get_request_frequency(ip):
    now = datetime.datetime.utcnow()
    with logs_lock:
        times = ip_request_count[ip]
        # Limpia entradas viejas
        times = [t for t in times if (now - t).seconds < 900]
        ip_request_count[ip] = times
        times.append(now)
    last_1min  = sum(1 for t in times if (now - t).seconds < 60)
    last_5min  = sum(1 for t in times if (now - t).seconds < 300)
    last_15min = len(times)
    return last_1min, last_5min, last_15min

def build_log_entry(endpoint_type):
    ip = get_ip()
    freq_1, freq_5, freq_15 = get_request_frequency(ip)
    payload = ""
    if request.method == "POST":
        try:
            payload = request.get_data(as_text=True)[:2000]
        except:
            payload = ""

    entry = {
        "id": hashlib.md5(f"{ip}{datetime.datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip": ip,
        "method": request.method,
        "path": request.full_path,
        "endpoint_type": endpoint_type,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "headers": dict(request.headers),
        "query_string": request.query_string.decode("utf-8", errors="replace"),
        "payload": payload,
        "freq_1min": freq_1,
        "freq_5min": freq_5,
        "freq_15min": freq_15,
        "classification": None,
        "action": None
    }
    return entry

# ─────────────────────────────────────────────
# PÁGINA PRINCIPAL — parece una web corporativa
# ─────────────────────────────────────────────

INDEX_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>CorpSec Solutions — Seguridad Empresarial</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Segoe UI', sans-serif; background:#f5f5f5; color:#333; }
  header { background:#1a237e; color:white; padding:18px 40px; display:flex; justify-content:space-between; align-items:center; }
  header h1 { font-size:22px; letter-spacing:1px; }
  nav a { color:#90caf9; margin-left:24px; text-decoration:none; font-size:14px; }
  .hero { background:linear-gradient(135deg,#1a237e,#283593); color:white; padding:80px 40px; text-align:center; }
  .hero h2 { font-size:36px; margin-bottom:16px; }
  .hero p { font-size:16px; opacity:0.85; max-width:600px; margin:0 auto 30px; }
  .btn { background:#42a5f5; color:white; padding:12px 32px; border:none; border-radius:4px; font-size:15px; cursor:pointer; text-decoration:none; display:inline-block; }
  .cards { display:flex; gap:24px; padding:40px; justify-content:center; flex-wrap:wrap; }
  .card { background:white; border-radius:8px; padding:28px; width:260px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
  .card h3 { color:#1a237e; margin-bottom:10px; }
  footer { background:#263238; color:#aaa; text-align:center; padding:20px; font-size:13px; margin-top:40px; }
</style>
</head>
<body>
<header>
  <h1>🔒 CorpSec Solutions</h1>
  <nav>
    <a href="/">Inicio</a>
    <a href="/portal">Portal</a>
    <a href="/admin">Admin</a>
    <a href="/contacto">Contacto</a>
  </nav>
</header>
<div class="hero">
  <h2>Protegemos tu empresa</h2>
  <p>Soluciones avanzadas de ciberseguridad para empresas de todos los tamaños. Monitorización 24/7, respuesta a incidentes y cumplimiento normativo.</p>
  <a href="/portal" class="btn">Acceder al portal</a>
</div>
<div class="cards">
  <div class="card"><h3>🛡️ Firewall Avanzado</h3><p>Protección perimetral con reglas personalizadas y detección de anomalías.</p></div>
  <div class="card"><h3>📊 SIEM Integrado</h3><p>Correlación de eventos en tiempo real con alertas automáticas.</p></div>
  <div class="card"><h3>🔍 Threat Intelligence</h3><p>Feeds actualizados con IoCs y geolocalización de amenazas.</p></div>
</div>
<footer>© 2025 CorpSec Solutions S.L. — Todos los derechos reservados | CIF: B-12345678</footer>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family:'Segoe UI',sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }}
  .box {{ background:white; padding:40px; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.1); width:360px; }}
  .box h2 {{ color:#1a237e; margin-bottom:24px; text-align:center; }}
  input {{ width:100%; padding:10px 14px; margin-bottom:16px; border:1px solid #ddd; border-radius:4px; font-size:14px; }}
  button {{ width:100%; padding:12px; background:#1a237e; color:white; border:none; border-radius:4px; font-size:15px; cursor:pointer; }}
  .error {{ color:#c62828; font-size:13px; margin-bottom:12px; text-align:center; display:{error_display}; }}
  .logo {{ text-align:center; font-size:28px; margin-bottom:16px; }}
</style>
</head>
<body>
<div class="box">
  <div class="logo">{logo}</div>
  <h2>{title}</h2>
  <p class="error">Usuario o contraseña incorrectos</p>
  <form method="POST">
    <input type="text" name="username" placeholder="Usuario" required>
    <input type="password" name="password" placeholder="Contraseña" required>
    <button type="submit">Entrar</button>
  </form>
</div>
</body>
</html>
"""

ENV_CONTENT = """
# CorpSec Solutions — Environment Configuration
# DO NOT SHARE THIS FILE

DB_HOST=10.0.1.45
DB_PORT=5432
DB_NAME=corpsec_prod
DB_USER=admin
DB_PASSWORD=C0rpS3c_2024!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=eu-west-1

STRIPE_SECRET_KEY=sk_live_EXAMPLEKEY123456789
JWT_SECRET=sup3r_s3cr3t_jwt_k3y_2024
ADMIN_PASSWORD=Admin@2024!

SMTP_HOST=smtp.corpsec.local
SMTP_USER=noreply@corpsec.local
SMTP_PASS=Smtp_P4ss_2024
"""

# ─────────────────────────────────────────────
# RUTAS TRAMPA
# ─────────────────────────────────────────────

@app.route("/")
def index():
    entry = build_log_entry("homepage")
    save_log(entry)
    return INDEX_HTML

@app.route("/portal", methods=["GET", "POST"])
def portal():
    entry = build_log_entry("portal_login")
    save_log(entry)
    error = "block" if request.method == "POST" else "none"
    return render_template_string(LOGIN_HTML, title="Portal Clientes", logo="🔒", error_display=error)

@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/", methods=["GET", "POST"])
def admin():
    entry = build_log_entry("admin_panel")
    save_log(entry)
    error = "block" if request.method == "POST" else "none"
    return render_template_string(LOGIN_HTML, title="Panel de Administración", logo="⚙️", error_display=error)

@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    entry = build_log_entry("wordpress_login")
    save_log(entry)
    error = "block" if request.method == "POST" else "none"
    return render_template_string(LOGIN_HTML, title="WordPress — Acceder", logo="🌐", error_display=error)

@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
def wp_admin():
    entry = build_log_entry("wordpress_admin")
    save_log(entry)
    return render_template_string(LOGIN_HTML, title="WordPress Admin", logo="🌐", error_display="none")

@app.route("/.env")
def env_file():
    entry = build_log_entry("env_file")
    save_log(entry)
    return ENV_CONTENT, 200, {"Content-Type": "text/plain"}

@app.route("/config.php")
def config_php():
    entry = build_log_entry("config_php")
    save_log(entry)
    content = "<?php\n$db_host = '10.0.1.45';\n$db_user = 'admin';\n$db_pass = 'C0rpS3c_2024!';\n$db_name = 'corpsec_prod';\n?>"
    return content, 200, {"Content-Type": "text/plain"}

@app.route("/backup.zip")
def backup_zip():
    entry = build_log_entry("backup_file")
    save_log(entry)
    return "PK\x03\x04", 200, {"Content-Type": "application/zip", "Content-Disposition": "attachment; filename=backup.zip"}

@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
def phpmyadmin():
    entry = build_log_entry("phpmyadmin")
    save_log(entry)
    error = "block" if request.method == "POST" else "none"
    return render_template_string(LOGIN_HTML, title="phpMyAdmin", logo="🗄️", error_display=error)

@app.route("/api/v1/users", methods=["GET", "POST"])
def api_users():
    entry = build_log_entry("api_users")
    save_log(entry)
    fake_users = [
        {"id": 1, "username": "admin", "email": "admin@corpsec.local", "role": "superadmin"},
        {"id": 2, "username": "jgarcia", "email": "j.garcia@corpsec.local", "role": "editor"},
        {"id": 3, "username": "mlopez", "email": "m.lopez@corpsec.local", "role": "viewer"},
    ]
    return jsonify({"status": "ok", "users": fake_users, "total": 3})

@app.route("/api/v1/login", methods=["POST"])
def api_login():
    entry = build_log_entry("api_login")
    save_log(entry)
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route("/shell", methods=["GET", "POST"])
@app.route("/cmd", methods=["GET", "POST"])
@app.route("/console", methods=["GET", "POST"])
def shell():
    entry = build_log_entry("shell_access")
    save_log(entry)
    return jsonify({"error": "Forbidden"}), 403

@app.route("/server-status")
def server_status():
    entry = build_log_entry("server_status")
    save_log(entry)
    return """<html><body>
    <h1>Apache Server Status</h1>
    <p>Server uptime: 127 days 4 hours</p>
    <p>Total requests: 1,482,301</p>
    <p>Version: Apache/2.4.51 (Ubuntu)</p>
    </body></html>"""

# Captura todo lo demás
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def catch_all(path):
    entry = build_log_entry("unknown_path")
    save_log(entry)
    return jsonify({"error": "Not found"}), 404

# ─────────────────────────────────────────────
# API INTERNA — para que el backend lea los logs
# ─────────────────────────────────────────────

@app.route("/internal/logs", methods=["GET"])
def get_logs():
    limit = int(request.args.get("limit", 100))
    with logs_lock:
        return jsonify(logs[-limit:])

@app.route("/internal/stats")
def get_stats():
    with logs_lock:
        total = len(logs)
        by_type = defaultdict(int)
        for l in logs:
            by_type[l["endpoint_type"]] += 1
    return jsonify({"total": total, "by_endpoint": dict(by_type)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
