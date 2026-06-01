"""
TFM - Entrenamiento del modelo de clasificación de ataques
Ejecutar una vez para generar el modelo: python train_model.py
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
import xgboost as xgb
import joblib
import json
import os
import math

LABELS = ["Normal", "SQL Injection", "XSS", "Path Traversal",
          "Command Injection", "Brute Force", "Scanner/Bot"]

# ─────────────────────────────────────────────
# GENERACIÓN DE DATASET SINTÉTICO DE ENTRENAMIENTO
# (sustituir por CICIDS2017 real cuando esté disponible)
# ─────────────────────────────────────────────

def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

def make_sample(label):
    """Genera un vector de features sintético para cada clase."""
    rng = np.random

    if label == "Normal":
        return [
            rng.randint(10, 60),   # url_len
            rng.randint(0, 50),    # payload_len
            rng.randint(0, 3),     # num_params
            rng.randint(0, 2),     # special_chars
            0, 0, 0, 0,            # sql, xss, traversal, cmd
            rng.uniform(1, 3),     # entropy
            0,                     # ua_suspicious
            rng.choice([0, 1]),    # method
            rng.randint(1, 5),     # freq_1min
            rng.randint(1, 10),    # freq_5min
            rng.randint(1, 20),    # freq_15min
        ]
    elif label == "SQL Injection":
        return [
            rng.randint(60, 200),
            rng.randint(50, 500),
            rng.randint(2, 8),
            rng.randint(5, 15),
            rng.randint(3, 8),     # sql_score alto
            0,
            0,
            rng.randint(0, 2),
            rng.uniform(3.5, 5.0),
            rng.choice([0, 1]),
            rng.choice([0, 1]),
            rng.randint(1, 8),
            rng.randint(1, 15),
            rng.randint(1, 30),
        ]
    elif label == "XSS":
        return [
            rng.randint(50, 180),
            rng.randint(30, 400),
            rng.randint(1, 6),
            rng.randint(6, 20),
            0,
            rng.randint(2, 7),     # xss_score alto
            0,
            0,
            rng.uniform(3.0, 5.0),
            rng.choice([0, 1]),
            rng.choice([0, 1]),
            rng.randint(1, 6),
            rng.randint(1, 12),
            rng.randint(1, 25),
        ]
    elif label == "Path Traversal":
        return [
            rng.randint(40, 150),
            rng.randint(0, 100),
            rng.randint(0, 4),
            rng.randint(4, 12),
            0, 0,
            rng.randint(2, 6),     # traversal_score alto
            0,
            rng.uniform(2.5, 4.5),
            rng.choice([0, 1]),
            0,
            rng.randint(1, 5),
            rng.randint(1, 10),
            rng.randint(1, 20),
        ]
    elif label == "Command Injection":
        return [
            rng.randint(40, 160),
            rng.randint(20, 300),
            rng.randint(1, 5),
            rng.randint(8, 20),
            rng.randint(0, 2),
            0, 0,
            rng.randint(3, 8),     # cmd_score alto
            rng.uniform(3.5, 5.5),
            rng.choice([0, 1]),
            rng.choice([0, 1]),
            rng.randint(1, 6),
            rng.randint(1, 12),
            rng.randint(1, 25),
        ]
    elif label == "Brute Force":
        return [
            rng.randint(15, 50),
            rng.randint(20, 80),
            rng.randint(1, 3),
            rng.randint(0, 3),
            0, 0, 0, 0,
            rng.uniform(2.0, 3.5),
            rng.choice([0, 1]),
            1,                     # POST
            rng.randint(10, 30),   # freq muy alta
            rng.randint(20, 80),
            rng.randint(30, 150),
        ]
    elif label == "Scanner/Bot":
        return [
            rng.randint(10, 80),
            rng.randint(0, 30),
            rng.randint(0, 2),
            rng.randint(0, 4),
            rng.randint(0, 2),
            rng.randint(0, 1),
            rng.randint(0, 2),
            0,
            rng.uniform(1.5, 3.5),
            1,                     # ua_suspicious = 1
            0,
            rng.randint(5, 20),
            rng.randint(10, 50),
            rng.randint(15, 100),
        ]

def generate_dataset(n_per_class=500):
    rows, label_col = [], []
    for i, label in enumerate(LABELS):
        for _ in range(n_per_class):
            rows.append(make_sample(label))
            label_col.append(i)
    cols = ["url_len","payload_len","num_params","special_chars",
            "sql_score","xss_score","traversal_score","cmd_score",
            "entropy","ua_suspicious","method",
            "freq_1min","freq_5min","freq_15min"]
    df = pd.DataFrame(rows, columns=cols)
    df["label"] = label_col
    return df

# ─────────────────────────────────────────────
# ENTRENAMIENTO Y EVALUACIÓN
# ─────────────────────────────────────────────

print("=" * 60)
print("TFM — Entrenamiento del modelo de clasificación de ataques")
print("=" * 60)

print("\n[1/5] Generando dataset de entrenamiento...")
df = generate_dataset(n_per_class=600)
print(f"      Dataset: {len(df)} muestras, {len(df.columns)-1} features")
print(f"      Distribución por clase:")
for i, label in enumerate(LABELS):
    print(f"        {label}: {(df['label']==i).sum()} muestras")

X = df.drop("label", axis=1).values
y = df["label"].values

print("\n[2/5] Dividiendo dataset (70/15/15)...")
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
X_val, X_test, y_val, y_test     = train_test_split(X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42)
print(f"      Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

print("\n[3/5] Aplicando SMOTE para balanceo de clases...")
smote = SMOTE(random_state=42)
X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)
print(f"      Muestras tras SMOTE: {len(X_train_sm)}")

print("\n[4/5] Entrenando y evaluando 4 modelos...")
scaler = MinMaxScaler()
X_train_sc = scaler.fit_transform(X_train_sm)
X_val_sc   = scaler.transform(X_val)
X_test_sc  = scaler.transform(X_test)

models = {
    "Random Forest": RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1),
    "XGBoost":       xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                                        use_label_encoder=False, eval_metric="mlogloss",
                                        random_state=42, n_jobs=-1),
    "SVM":           SVC(kernel="rbf", C=10, gamma="scale", probability=True, random_state=42),
    "MLP":           MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=500,
                                   random_state=42, early_stopping=True),
}

results = {}
for name, clf in models.items():
    clf.fit(X_train_sc, y_train_sm)
    y_pred  = clf.predict(X_val_sc)
    f1_mac  = f1_score(y_val, y_pred, average="macro")
    results[name] = {"model": clf, "f1_macro": f1_mac}
    print(f"      {name:20s} → F1 macro (val): {f1_mac:.4f}")

best_name = max(results, key=lambda k: results[k]["f1_macro"])
best_clf  = results[best_name]["model"]
print(f"\n      ✅ Mejor modelo: {best_name} (F1 macro val: {results[best_name]['f1_macro']:.4f})")

print("\n[5/5] Evaluación final en test set...")
y_pred_test = best_clf.predict(X_test_sc)
print("\n" + classification_report(y_test, y_pred_test, target_names=LABELS))

cm = confusion_matrix(y_test, y_pred_test)
print("Matriz de confusión:")
print(cm)

# ─────────────────────────────────────────────
# GUARDAR MODELO Y MÉTRICAS
# ─────────────────────────────────────────────

os.makedirs("/model", exist_ok=True)

# Guardar pipeline completo (scaler + modelo)
pipeline = Pipeline([("scaler", scaler), ("clf", best_clf)])
joblib.dump(pipeline, "/model/classifier.joblib")
print(f"\n✅ Modelo guardado en /model/classifier.joblib")

# Guardar métricas para la memoria del TFM
metrics = {
    "best_model": best_name,
    "f1_macro_val": results[best_name]["f1_macro"],
    "f1_macro_test": float(f1_score(y_test, y_pred_test, average="macro")),
    "all_models": {k: v["f1_macro"] for k, v in results.items()},
    "confusion_matrix": cm.tolist(),
    "labels": LABELS
}
with open("/model/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)
print("✅ Métricas guardadas en /model/metrics.json")
print("\n" + "="*60)
print("Entrenamiento completado. Puedes arrancar el sistema.")
print("="*60)
