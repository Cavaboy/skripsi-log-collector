# ==========================================
# SKRIPSI BAB 4.6: EVALUASI RULES FP-GROWTH
# Rules: Sup 0.01, Conf 0.30, v3.0
# ==========================================

import pandas as pd
import numpy as np
import ast
import re
import os
import json
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from collections import defaultdict

# ==========================================
# KONFIGURASI PATH
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(SCRIPT_DIR, "../.."))
DATA_DIR = os.path.join(PROJECT_ROOT, "Data")

MASTER_DATASET = os.path.join(DATA_DIR, "Master_Dataset_Gabungan_v3.0.csv")
RULES_FILE = os.path.join(DATA_DIR, "rules", "Rules_Sup0.01_Conf0.3_v3.0.csv")
OUTPUT_DIR = SCRIPT_DIR  # Output to the same test_run folder

TARGET_LABELS = [
    "NORMAL",
    "LINK_FAILURE",
    "UPSTREAM_FAILURE",
    "DDOS_ATTACK",
    "BROADCAST_STORM",
]

RANDOM_STATE = 42
TEST_SIZE = 0.20
TARGET_TEST_PER_CLASS = 500  # 20% of 2500 = 500 per class, total ~2500

# ==========================================
# 1. STOPWORDS (sama persis dengan 02_data_cleaning.py)
# ==========================================
STOPWORDS = {
    "ether1", "ether2", "ether3", "ether4", "ether5", "ether6", "ether7",
    "loading", "info", "input", "in", "out", "message", "log", "by",
    "from", "to", "via", "changed", "set", "connection-state", "new",
    "time", "date", "identity", "forward", "zone", "firewall", "router",
    "system", "script", "debug", "topics", "active", "inactive",
    "assigned", "deassigned", "address", "status", "state", "detected",
    "using", "packet", "rule", "up", "running", "full", "established",
    "connected", "reachable", "designated", "backup", "installed",
    "added", "exchange", "route", "version", "change", "created",
    "init", "twoway", "2-way", "exstart", "waiting", "negotiation",
    "lsdb", "bdr", "dr", "instance", "account", "user", "logged",
    "rebooted", "shutdown", "console", "ttys0", "api", "rest-api",
    "dhcp", "dhcp-client", "monitor", "event", "size", "simple",
    "got", "other", "monitor", "host", "rto",
    "153", "130", "132", "133", "168", "192", "255",
}


# ==========================================
# 2. FUNGSI PREPROCESSING (identik dgn pipeline)
# ==========================================
def clean_text(text):
    """Cleaning + Case Folding + Stopwords Removal (identik dgn 02_data_cleaning.py)"""
    if not isinstance(text, str):
        return []
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s\-]", " ", text)
    words = text.split()
    filtered_words = [w for w in words if w not in STOPWORDS and len(w) > 2]
    return filtered_words


def preprocess_master_dataset(filepath):
    """Baca master dataset mentah dan terapkan preprocessing."""
    print(f"[1/5] Membaca Master Dataset: {filepath}")
    df = pd.read_csv(filepath)
    print(f"      Data Awal: {len(df)} baris, Kolom: {df.columns.tolist()}")

    # Tentukan kolom label
    if "Label" in df.columns:
        label_col = "Label"
    elif "Skenario" in df.columns:
        label_col = "Skenario"
    else:
        raise ValueError("Kolom 'Label' atau 'Skenario' tidak ditemukan!")

    print(f"      Kolom Label: '{label_col}'")
    print(f"      Distribusi Label Awal:")
    for lbl, cnt in df[label_col].value_counts().items():
        print(f"        {lbl}: {cnt}")

    # Gabungkan kolom teks (sama seperti 02_data_cleaning.py)
    df["full_text"] = (
        df["source_router"].astype(str)
        + " "
        + df["topics"].astype(str)
        + " "
        + df["message"].astype(str)
    )

    # Terapkan cleaning
    df["items"] = df["full_text"].apply(clean_text)

    # Hapus baris kosong setelah cleaning
    initial_len = len(df)
    df = df[df["items"].map(len) > 0]
    dropped = initial_len - len(df)
    print(f"      Baris dibuang (kosong setelah cleaning): {dropped}")
    print(f"      Data Bersih: {len(df)} baris")

    return df[[label_col, "items"]].rename(columns={label_col: "Label"})


# ==========================================
# 3. SPLIT & BALANCING
# ==========================================
def split_and_balance(df, test_size=TEST_SIZE, target_per_class_train=2500,
                      target_per_class_test=500):
    """
    Stratified split 80/20, lalu balancing:
    - Training: 2500 per kelas (untuk verifikasi, tidak dipakai langsung di sini)
    - Testing:  500 per kelas = total ~2500 data uji seimbang
    """
    print(f"\n[2/5] Splitting Data (Train: {1-test_size:.0%}, Test: {test_size:.0%})")

    # Stratified split
    df_train, df_test = train_test_split(
        df, test_size=test_size, random_state=RANDOM_STATE, stratify=df["Label"]
    )
    print(f"      Train (raw): {len(df_train)} baris")
    print(f"      Test (raw):  {len(df_test)} baris")

    # --- Balancing Training Set (2500 per kelas) ---
    train_balanced_list = []
    for label in TARGET_LABELS:
        subset = df_train[df_train["Label"] == label]
        count = len(subset)
        if count >= target_per_class_train:
            resampled = subset.sample(n=target_per_class_train, random_state=RANDOM_STATE)
        else:
            resampled = subset.sample(n=target_per_class_train, replace=True, random_state=RANDOM_STATE)
        train_balanced_list.append(resampled)
    df_train_balanced = pd.concat(train_balanced_list).sample(
        frac=1, random_state=RANDOM_STATE
    ).reset_index(drop=True)

    # --- Balancing Test Set (500 per kelas = ~2500 total) ---
    test_balanced_list = []
    for label in TARGET_LABELS:
        subset = df_test[df_test["Label"] == label]
        count = len(subset)
        if count >= target_per_class_test:
            resampled = subset.sample(n=target_per_class_test, random_state=RANDOM_STATE)
        else:
            resampled = subset.sample(n=target_per_class_test, replace=True, random_state=RANDOM_STATE)
        test_balanced_list.append(resampled)
    df_test_balanced = pd.concat(test_balanced_list).sample(
        frac=1, random_state=RANDOM_STATE
    ).reset_index(drop=True)

    print(f"\n      Train Balanced: {len(df_train_balanced)} baris")
    for lbl in TARGET_LABELS:
        print(f"        {lbl}: {len(df_train_balanced[df_train_balanced['Label'] == lbl])}")

    print(f"\n      Test Balanced (DATA UJI): {len(df_test_balanced)} baris")
    for lbl in TARGET_LABELS:
        print(f"        {lbl}: {len(df_test_balanced[df_test_balanced['Label'] == lbl])}")

    return df_train_balanced, df_test_balanced


# ==========================================
# 4. LOAD RULES & PARSE
# ==========================================
def load_rules(rules_path):
    """Load dan parse rules dari CSV FP-Growth."""
    print(f"\n[3/5] Memuat Rules: {os.path.basename(rules_path)}")
    df_rules = pd.read_csv(rules_path)
    print(f"      Total Rules Awal: {len(df_rules)}")

    # Parse antecedents dan consequents dari string representasi list
    def parse_list_str(s):
        if pd.isna(s):
            return []
        try:
            return ast.literal_eval(str(s))
        except:
            return []

    df_rules["antecedents_parsed"] = df_rules["antecedents"].apply(parse_list_str)
    df_rules["consequents_parsed"] = df_rules["consequents"].apply(parse_list_str)

    # Ekstrak label diagnosis dari consequents
    # Consequents bisa berisi campuran kata + label, misal: ['UPSTREAM_FAILURE', '3600']
    def extract_diagnosis(consequents):
        for item in consequents:
            item_upper = str(item).upper()
            if item_upper in TARGET_LABELS:
                return item_upper
        return None

    df_rules["diagnosis"] = df_rules["consequents_parsed"].apply(extract_diagnosis)

    # Filter hanya rules yang punya diagnosis valid
    df_rules = df_rules.dropna(subset=["diagnosis"])
    print(f"      Rules dengan Diagnosis Valid: {len(df_rules)}")

    # Statistik per diagnosis
    for lbl in TARGET_LABELS:
        cnt = len(df_rules[df_rules["diagnosis"] == lbl])
        print(f"        {lbl}: {cnt} rules")

    # Hapus label dari antecedents (pastikan antecedent murni berisi kata kunci)
    def clean_antecedents(row):
        antecedents = row["antecedents_parsed"]
        # Buang elemen yang merupakan label target
        cleaned = [item for item in antecedents if str(item).upper() not in TARGET_LABELS]
        return set(cleaned)

    df_rules["antecedents_set"] = df_rules.apply(clean_antecedents, axis=1)

    # Filter rules dengan antecedents kosong
    df_rules = df_rules[df_rules["antecedents_set"].map(len) > 0]
    print(f"      Rules Final (antecedents non-kosong): {len(df_rules)}")

    # Sort by confidence desc, lift desc (prioritas matching)
    df_rules = df_rules.sort_values(
        ["confidence", "lift"], ascending=[False, False]
    ).reset_index(drop=True)

    return df_rules


# ==========================================
# 5. PATTERN MATCHING: INFERENSI
# ==========================================
def predict_with_rules(df_test, df_rules):
    """
    Pattern matching: untuk setiap log uji, cari rule yang antecedent-nya
    subset dari items log, lalu ambil prediksi dengan confidence tertinggi.
    """
    print(f"\n[4/5] Pattern Matching pada {len(df_test)} data uji...")

    # Pre-convert rules ke list of dicts untuk kecepatan
    rules_list = []
    for _, rule in df_rules.iterrows():
        rules_list.append({
            "antecedents": rule["antecedents_set"],
            "diagnosis": rule["diagnosis"],
            "confidence": float(rule.get("confidence", 0)),
            "lift": float(rule.get("lift", 0)),
            "support": float(rule.get("support", 0)),
        })

    # Build inverted index untuk kecepatan
    token_to_rules = defaultdict(list)
    for idx, rule in enumerate(rules_list):
        for token in rule["antecedents"]:
            token_to_rules[token].append(idx)

    predictions = []
    match_count = 0
    no_match_count = 0
    match_details = []  # Untuk analisis detail

    for i, (_, row) in enumerate(df_test.iterrows()):
        items = row["items"]
        if isinstance(items, str):
            items = ast.literal_eval(items)
        items_set = set(items)

        # Cari candidate rules via inverted index
        candidate_indices = set()
        for token in items_set:
            if token in token_to_rules:
                for rule_idx in token_to_rules[token]:
                    candidate_indices.add(rule_idx)

        # Cek matching: antecedent subset dari items
        best_rule = None
        best_conf = -1.0
        best_lift = -1.0

        for rule_idx in candidate_indices:
            rule = rules_list[rule_idx]
            if rule["antecedents"].issubset(items_set):
                conf = rule["confidence"]
                lift = rule["lift"]
                # Pilih rule terbaik: confidence tertinggi, tie-break oleh lift
                if conf > best_conf or (conf == best_conf and lift > best_lift):
                    best_rule = rule
                    best_conf = conf
                    best_lift = lift

        if best_rule is not None:
            predictions.append(best_rule["diagnosis"])
            match_count += 1
            match_details.append({
                "actual": row["Label"],
                "predicted": best_rule["diagnosis"],
                "confidence": best_conf,
                "lift": best_lift,
                "matched": True,
            })
        else:
            # Tidak ada rule yang cocok — fallback: prediksi "NORMAL"
            # (Karena jika tidak ada anomali terdeteksi, asumsi NORMAL)
            predictions.append("NORMAL")
            no_match_count += 1
            match_details.append({
                "actual": row["Label"],
                "predicted": "NORMAL",
                "confidence": 0.0,
                "lift": 0.0,
                "matched": False,
            })

        if (i + 1) % 500 == 0:
            print(f"      Progres: {i+1}/{len(df_test)} data diproses...")

    df_test = df_test.copy()
    df_test["Prediksi"] = predictions

    print(f"      Selesai! Matched: {match_count}, No-Match (fallback NORMAL): {no_match_count}")

    return df_test, match_details


# ==========================================
# 6. EVALUASI & OUTPUT
# ==========================================
def evaluate_and_output(df_result, match_details, output_dir):
    """Generate Confusion Matrix & Metrics, simpan ke file."""
    print(f"\n[5/5] Menghitung Metrik Evaluasi...")

    y_actual = df_result["Label"].values
    y_pred = df_result["Prediksi"].values

    # ---- CONFUSION MATRIX ----
    cm = confusion_matrix(y_actual, y_pred, labels=TARGET_LABELS)
    cm_df = pd.DataFrame(cm, index=TARGET_LABELS, columns=TARGET_LABELS)

    print("\n" + "=" * 70)
    print("CONFUSION MATRIX (5x5)")
    print("=" * 70)
    print(cm_df.to_string())

    # ---- CLASSIFICATION METRICS ----
    accuracy = accuracy_score(y_actual, y_pred)
    precision_per_class = precision_score(y_actual, y_pred, labels=TARGET_LABELS, average=None, zero_division=0)
    recall_per_class = recall_score(y_actual, y_pred, labels=TARGET_LABELS, average=None, zero_division=0)
    f1_per_class = f1_score(y_actual, y_pred, labels=TARGET_LABELS, average=None, zero_division=0)

    # Weighted averages
    precision_weighted = precision_score(y_actual, y_pred, labels=TARGET_LABELS, average="weighted", zero_division=0)
    recall_weighted = recall_score(y_actual, y_pred, labels=TARGET_LABELS, average="weighted", zero_division=0)
    f1_weighted = f1_score(y_actual, y_pred, labels=TARGET_LABELS, average="weighted", zero_division=0)

    # Macro averages
    precision_macro = precision_score(y_actual, y_pred, labels=TARGET_LABELS, average="macro", zero_division=0)
    recall_macro = recall_score(y_actual, y_pred, labels=TARGET_LABELS, average="macro", zero_division=0)
    f1_macro = f1_score(y_actual, y_pred, labels=TARGET_LABELS, average="macro", zero_division=0)

    metrics_data = []
    for i, label in enumerate(TARGET_LABELS):
        metrics_data.append({
            "Kelas": label,
            "Precision": round(precision_per_class[i], 4),
            "Recall": round(recall_per_class[i], 4),
            "F1-Score": round(f1_per_class[i], 4),
        })

    metrics_df = pd.DataFrame(metrics_data)

    print("\n" + "=" * 70)
    print("REKAPITULASI METRIK EVALUASI")
    print("=" * 70)
    print(f"Accuracy Keseluruhan: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(metrics_df.to_string(index=False))
    print(f"\nRata-rata Macro:    Precision={precision_macro:.4f}  Recall={recall_macro:.4f}  F1={f1_macro:.4f}")
    print(f"Rata-rata Weighted: Precision={precision_weighted:.4f}  Recall={recall_weighted:.4f}  F1={f1_weighted:.4f}")

    # ==========================================
    # GENERATE MARKDOWN OUTPUT
    # ==========================================

    # --- Markdown: Confusion Matrix ---
    md_cm = "## Tabel 4.X — Confusion Matrix (5×5)\n\n"
    md_cm += "**Konfigurasi:** Support = 0.01, Confidence = 0.30 | Data Uji = 2.500 baris seimbang (500/kelas)\n\n"
    md_cm += "| **Aktual \\ Prediksi** | " + " | ".join(f"**{lbl}**" for lbl in TARGET_LABELS) + " |\n"
    md_cm += "|" + "---|" * (len(TARGET_LABELS) + 1) + "\n"
    for i, label in enumerate(TARGET_LABELS):
        row_vals = " | ".join(str(cm[i][j]) for j in range(len(TARGET_LABELS)))
        md_cm += f"| **{label}** | {row_vals} |\n"

    # --- Markdown: Metrics Table ---
    md_metrics = "## Tabel 4.X — Rekapitulasi Metrik Evaluasi\n\n"
    md_metrics += "**Konfigurasi:** Support = 0.01, Confidence = 0.30 | Data Uji = 2.500 baris seimbang (500/kelas)\n\n"
    md_metrics += "| **Kelas** | **Precision** | **Recall** | **F1-Score** |\n"
    md_metrics += "|---|---|---|---|\n"
    for _, row in metrics_df.iterrows():
        md_metrics += f"| {row['Kelas']} | {row['Precision']:.4f} | {row['Recall']:.4f} | {row['F1-Score']:.4f} |\n"

    md_metrics += f"| **Rata-rata (Macro)** | **{precision_macro:.4f}** | **{recall_macro:.4f}** | **{f1_macro:.4f}** |\n"
    md_metrics += f"| **Rata-rata (Weighted)** | **{precision_weighted:.4f}** | **{recall_weighted:.4f}** | **{f1_weighted:.4f}** |\n"
    md_metrics += f"\n**Accuracy Keseluruhan: {accuracy:.4f} ({accuracy*100:.2f}%)**\n"

    # ==========================================
    # SIMPAN FILE OUTPUT
    # ==========================================

    # 1. Confusion Matrix Markdown
    cm_md_path = os.path.join(output_dir, "confusion_matrix.md")
    with open(cm_md_path, "w", encoding="utf-8") as f:
        f.write(md_cm)
    print(f"\n[OK] Confusion Matrix disimpan: {cm_md_path}")

    # 2. Metrics Markdown
    metrics_md_path = os.path.join(output_dir, "metrics_evaluasi.md")
    with open(metrics_md_path, "w", encoding="utf-8") as f:
        f.write(md_metrics)
    print(f"[OK] Metrics disimpan: {metrics_md_path}")

    # 3. Detailed results CSV
    result_csv_path = os.path.join(output_dir, "hasil_prediksi_detail.csv")
    df_result.to_csv(result_csv_path, index=False)
    print(f"[OK] Detail Prediksi disimpan: {result_csv_path}")

    # 4. Confusion Matrix CSV
    cm_csv_path = os.path.join(output_dir, "confusion_matrix.csv")
    cm_df.to_csv(cm_csv_path)
    print(f"[OK] Confusion Matrix CSV disimpan: {cm_csv_path}")

    # 5. Summary JSON
    summary = {
        "timestamp": datetime.now().isoformat(),
        "rules_file": "Rules_Sup0.01_Conf0.3_v3.0.csv",
        "test_samples": len(df_result),
        "accuracy": round(accuracy, 4),
        "precision_macro": round(precision_macro, 4),
        "recall_macro": round(recall_macro, 4),
        "f1_macro": round(f1_macro, 4),
        "precision_weighted": round(precision_weighted, 4),
        "recall_weighted": round(recall_weighted, 4),
        "f1_weighted": round(f1_weighted, 4),
        "matched_count": sum(1 for d in match_details if d["matched"]),
        "no_match_count": sum(1 for d in match_details if not d["matched"]),
    }
    summary_path = os.path.join(output_dir, "evaluation_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[OK] Summary disimpan: {summary_path}")

    return md_cm, md_metrics, accuracy


# ==========================================
# MAIN
# ==========================================
def main():
    print("=" * 70)
    print("  EVALUASI RULES FP-GROWTH — BAB 4.6")
    print("  Rules: Support=0.01, Confidence=0.30, v3.0")
    print("=" * 70)

    # Step 1: Preprocessing
    df_clean = preprocess_master_dataset(MASTER_DATASET)

    # Step 2: Split & Balance
    df_train, df_test = split_and_balance(df_clean)

    # Step 3: Load Rules
    df_rules = load_rules(RULES_FILE)

    # Step 4: Inference (Pattern Matching)
    df_result, match_details = predict_with_rules(df_test, df_rules)

    # Step 5: Evaluate & Output
    md_cm, md_metrics, accuracy = evaluate_and_output(df_result, match_details, OUTPUT_DIR)

    print("\n" + "=" * 70)
    print("  EVALUASI SELESAI!")
    print("=" * 70)
    print(f"\n--- CONFUSION MATRIX (Markdown) ---\n")
    print(md_cm)
    print(f"\n--- METRIK EVALUASI (Markdown) ---\n")
    print(md_metrics)


if __name__ == "__main__":
    main()
