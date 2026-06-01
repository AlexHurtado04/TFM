"""
Worker: lee los logs nuevos del honeypot y los envía al backend de IA.
Corre en bucle continuo dentro de Docker.
"""
import requests
import time
import json
import os
import datetime

HONEYPOT_URL = "http://honeypot:8080/internal/logs"
BACKEND_URL  = "http://backend:8000/analyze"
STATE_FILE   = "/data/worker_state.json"

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_processed": 0}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def run():
    print(f"[{datetime.datetime.utcnow().isoformat()}] Worker arrancado. Monitorizando honeypot...")
    state = load_state()

    while True:
        try:
            # Obtener logs del honeypot
            resp = requests.get(HONEYPOT_URL, params={"limit": 200}, timeout=5)
            if resp.status_code == 200:
                logs = resp.json()
                new_logs = logs[state["last_processed"]:]

                for log in new_logs:
                    try:
                        r = requests.post(BACKEND_URL, json=log, timeout=10)
                        if r.status_code == 200:
                            result = r.json()
                            attack = result.get("attack_type", "?")
                            conf   = result.get("confidence", 0)
                            action = result.get("action", "?")
                            ip     = log.get("ip", "?")
                            geo    = result.get("geo", {})
                            country = geo.get("country", "?")
                            print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] "
                                  f"IP: {ip} ({country}) | "
                                  f"Ataque: {attack} ({conf:.0f}%) | "
                                  f"Acción: {action}")
                    except Exception as e:
                        print(f"  Error procesando log: {e}")

                if new_logs:
                    state["last_processed"] += len(new_logs)
                    save_state(state)

        except Exception as e:
            print(f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] Error conectando con honeypot: {e}")

        time.sleep(3)  # Revisa cada 3 segundos

if __name__ == "__main__":
    time.sleep(10)  # Espera a que los otros servicios arranquen
    run()
