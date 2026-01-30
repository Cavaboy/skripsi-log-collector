import pandas as pd
import re

# Load Master Dataset
input_file = "../Data/Master_Dataset_Gabungan.csv"
df = pd.read_csv(input_file)

print(f"Data Awal: {len(df)} baris")


# ==========================================
# FUNGSI PEMBERSIH (CLEANING)
# ==========================================
def clean_text(text):
    if not isinstance(text, str):
        return ""

    # 1. Ubah ke huruf kecil (Lowercase)
    text = text.lower()

    # 2. Hapus karakter aneh (selain huruf, angka, spasi, dan dash -)
    # Kita pertahankan spasi agar kata tidak nempel
    text = re.sub(r"[^a-z0-9\s\-]", " ", text)

    # 3. Hapus kata-kata sampah (Stopwords) yang tidak penting
    # Kata-kata ini sering muncul tapi tidak membawa makna diagnosis
    stopwords = [
        "info",
        "input",
        "in",
        "out",
        "message",
        "log",
        "by",
        "from",
        "to",
        "via",
        "changed",
        "set",
        "connection-state",
        "new",
    ]

    words = text.split()
    filtered_words = [w for w in words if w not in stopwords and len(w) > 2]

    return filtered_words


# ==========================================
# EKSEKUSI CLEANING
# ==========================================
print("Sedang membersihkan data...")

# Kita gabungkan kolom 'source_router', 'topics', dan 'message' jadi satu kalimat utuh
# Agar AI bisa mengaitkan Router mana + Topik apa + Pesan apa
df["full_text"] = df["source_router"] + " " + df["topics"] + " " + df["message"]

# Terapkan cleaning
df["items"] = df["full_text"].apply(clean_text)

# Hapus baris yang kosong setelah dibersihkan (jika ada)
df = df[df["items"].map(len) > 0]

# ==========================================
# SIMPAN HASIL TRANSAKSI
# ==========================================
# Kita hanya butuh kolom 'items' (transaksi) dan 'Label' (target)
final_df = df[["Label", "items"]]

output_file = "../Data/Data_Siap_Mining.csv"
final_df.to_csv(output_file, index=False)

print("=" * 50)
print(f"✅ PREPROCESSING SELESAI!")
print(f"File tersimpan: {output_file}")
print("\nContoh Data Bersih (5 Teratas):")
print(final_df.head())
print("=" * 50)
