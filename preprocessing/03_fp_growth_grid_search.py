# ==========================================
# SKRIPSI: GRID SEARCH (SAFE MODE - MAX LEN 4)
# ==========================================

import pandas as pd
import ast
import gc
import time
import glob
import re
import os
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import fpgrowth, association_rules

try:
    from google.colab import files
    IN_COLAB = True
except ImportError:
    IN_COLAB = False

# --- KONFIGURASI ---
# Range Support & Confidence (Tetap sama seperti rencana Anda)
SUPPORT_RANGE = [0.01, 0.05, 0.1, 0.15]
CONFIDENCE_RANGE = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

# PEMBATAS UKURAN FILE (SOLUSI UTAMA)
# Max Len 4 artinya: Maksimal kombinasi 3 kata penyebab + 1 diagnosis.
# Contoh: {link, ether2, down} -> {LINK_FAILURE}
MAX_LEN_LIMIT = 4

TARGET_COUNT = 2500

# ==========================================
# KONFIGURASI VERSI OTOMATIS
# ==========================================
MAJOR_VERSION = 3

if IN_COLAB:
    data_dir = "."
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.normpath(os.path.join(script_dir, "../Data"))

existing_files = glob.glob(os.path.join(data_dir, f"Data_Siap_Mining_v{MAJOR_VERSION}.*.csv"))
minor_versions = []
for f in existing_files:
    basename = os.path.basename(f)
    match = re.search(rf"v{MAJOR_VERSION}\.(\d+)\.csv$", basename)
    if match:
        minor_versions.append(int(match.group(1)))

if not minor_versions:
    print(f"❌ ERROR: Tidak ada Data_Siap_Mining_v{MAJOR_VERSION}.*.csv di direktori {data_dir}!")
    exit()

latest_minor = max(minor_versions)
CURRENT_VERSION = f"v{MAJOR_VERSION}.{latest_minor}"
INPUT_FILE = os.path.join(data_dir, f"Data_Siap_Mining_{CURRENT_VERSION}.csv")

print(f"Versi terdeteksi: {CURRENT_VERSION}")

print(" Loading & Balancing Data (Target: 1000)...")
try:
    df = pd.read_csv(INPUT_FILE)
except FileNotFoundError:
    print(f"❌ ERROR: File '{INPUT_FILE}' tidak ditemukan!")
    raise

label_col = 'Label' if 'Label' in df.columns else 'diagnosis'
unique_labels = df[label_col].unique()

# Balancing
df_balanced_list = []
for label in unique_labels:
    df_subset = df[df[label_col] == label]
    count = len(df_subset)
    if count >= TARGET_COUNT:
        df_resampled = df_subset.sample(n=TARGET_COUNT, random_state=42)
    else:
        df_resampled = df_subset.sample(n=TARGET_COUNT, replace=True, random_state=42)
    df_balanced_list.append(df_resampled)

df_balanced = pd.concat(df_balanced_list).sample(frac=1, random_state=42).reset_index(drop=True)

# Encoding
print("Encoding Transaksi...")
transactions = []
for _, row in df_balanced.iterrows():
    try:
        items = ast.literal_eval(row['items']) if isinstance(row['items'], str) else row['items']
        items.append(row[label_col])
        transactions.append(items)
    except:
        continue

te = TransactionEncoder()
te_ary = te.fit(transactions).transform(transactions)
df_encoded = pd.DataFrame(te_ary, columns=te.columns_)
print(f"Data Siap! Total Transaksi: {len(df_encoded)}")

TARGET_LABELS = ['NORMAL', 'UPSTREAM_FAILURE', 'LINK_FAILURE', 'DDOS_ATTACK', 'BROADCAST_STORM']
summary_results = []
generated_files = []

print(f"GRID SEARCH (Max Length: {MAX_LEN_LIMIT})...")
print("="*60)

for min_sup in SUPPORT_RANGE:
    print(f"\n⛏️ Mining Itemsets (Support: {min_sup}, MaxLen: {MAX_LEN_LIMIT})...")
    try:
        # PENAMBAHAN PARAMETER max_len DI SINI
        frequent_itemsets = fpgrowth(df_encoded, min_support=min_sup, use_colnames=True, max_len=MAX_LEN_LIMIT)
        print(f"   -> Itemset ditemukan: {len(frequent_itemsets)}")
    except Exception as e:
        print(f"   ❌ Gagal Mining: {e}")
        continue

    for min_conf in CONFIDENCE_RANGE:
        print(f"   ⚙️ Generating Rules (Conf: {min_conf})...", end=" ")

        try:
            rules = association_rules(frequent_itemsets, metric="confidence", min_threshold=min_conf)

            # Filter Rules
            final_rules = rules[rules['consequents'].apply(lambda x: any(label in x for label in TARGET_LABELS))].copy()

            # Formatting
            final_rules['antecedents'] = final_rules['antecedents'].apply(lambda x: list(x))
            final_rules['consequents'] = final_rules['consequents'].apply(lambda x: list(x))
            final_rules = final_rules.sort_values(['lift', 'confidence'], ascending=[False, False])

            # Statistik
            stats = {
                'Support': min_sup,
                'Confidence': min_conf,
                'Total_Rules': len(final_rules)
            }
            for label in TARGET_LABELS:
                count = len(final_rules[final_rules['consequents'].astype(str).str.contains(label)])
                stats[label] = count

            summary_results.append(stats)
            print(f"-> Rules: {len(final_rules)}")

            # Simpan File
            filename = f"Rules_Sup{min_sup}_Conf{min_conf}_{CURRENT_VERSION}.csv"
            final_rules.to_csv(filename, index=False)
            generated_files.append(filename)

        except Exception as e:
            print(f"❌ Gagal Rule Gen: {e}")

print("\n" + "="*80)
print("📊 REKAPITULASI HASIL (FILE LEBIH KECIL & RAPI)")
print("="*80)

summary_df = pd.DataFrame(summary_results)
cols = ['Support', 'Confidence', 'Total_Rules'] + TARGET_LABELS
summary_df = summary_df[cols]
print(summary_df.to_string(index=False))

print("\n" + "="*80)
if IN_COLAB:
    print("💾 MENDOWNLOAD SEMUA FILE DARI COLAB...")
    for file_name in generated_files:
        try:
            files.download(file_name)
            time.sleep(30)
        except:
            pass
else:
    print(f"💾 SEMUA FILE TELAH DISIMPAN LOKAL.")
