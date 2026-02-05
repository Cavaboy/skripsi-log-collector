import pandas as pd
import re
import os

# ==========================================
# KONFIGURASI
# ==========================================
INPUT_FILE = "../Data/Master_Dataset_Gabungan.csv"
OUTPUT_FILE = "../Data/Data_Siap_Mining_revisi.csv"

# 1. STOPWORDS (KATA SAMPAH)
STOPWORDS = {
    # --- STOPWORDS UMUM ---
    "ether1", "ether2", "ether3", "ether4", "ether5", "ether6", "ether7", 
    "loading", "info", "input", "in", "out", "message", "log", "by", "from", 
    "to", "via", "changed", "set", "connection-state", "new", "time", "date", 
    "identity", "forward", "zone", "firewall", "router", "system", "script", 
    "debug", "topics", "active", "inactive", "assigned", "deassigned", "address", 
    "status", "state", "detected", "using", "packet", "rule", "up", "running", 
    "full", "established", "connected", "reachable", "designated", "backup", 
    "installed", "added", "exchange",
    
    "route", "version", "change", "created", "init", "twoway", "2-way", 
    "exstart", "waiting", "negotiation", "lsdb", "bdr", "dr", "instance",
    
    "account", "user", "logged", "rebooted", "shutdown", "console", "ttys0",
    "api", "rest-api", "dhcp", "dhcp-client", "monitor", "event",
    
    "size", "simple", "got", "other", "monitor", "host", "rto",
    "153", "130", "132", "133", "168", "192", "255" # IP fragments umum

}

# ==========================================
# FUNGSI PEMBERSIH (CLEANING)
# ==========================================
def clean_text(text):
    if not isinstance(text, str):
        return []

    # 1. Ubah ke huruf kecil
    text = text.lower()

    # 2. Hapus karakter aneh (Regex)
    # Hanya sisakan huruf, angka, spasi, dan dash
    text = re.sub(r"[^a-z0-9\s\-]", " ", text)

    # 3. Filter Stopwords & Panjang Kata
    words = text.split()
    filtered_words = [w for w in words if w not in STOPWORDS and len(w) > 2]

    return filtered_words

# ==========================================
# EKSEKUSI CLEANING
# ==========================================
def main():
    # Cek apakah file ada
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] File tidak ditemukan di: {INPUT_FILE}")
        return

    print(f"📂 Membaca file: {INPUT_FILE}...")
    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"   Data Awal: {len(df)} baris")
    except Exception as e:
        print(f"[ERROR] Gagal membaca CSV: {e}")
        return

    print("Sedang membersihkan Stopwords...")

    # Gabungkan kolom jadi satu kalimat utuh (Router + Topik + Pesan)
    # Pastikan di-convert ke string dulu untuk menghindari error jika ada data kosong
    df["full_text"] = df["source_router"].astype(str) + " " + \
                      df["topics"].astype(str) + " " + \
                      df["message"].astype(str)

    # Terapkan cleaning
    df["items"] = df["full_text"].apply(clean_text)

    # Hapus baris yang kosong setelah dibersihkan
    # (Baris yang tadinya berisi 'link up' sekarang jadi kosong, dan akan terhapus di sini)
    initial_len = len(df)
    df = df[df["items"].map(len) > 0]
    final_len = len(df)
    dropped_count = initial_len - final_len

    # ==========================================
    # SIMPAN HASIL
    # ==========================================
    final_df = df[["Label", "items"]]
    
    # Pastikan folder output ada
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    final_df.to_csv(OUTPUT_FILE, index=False)

    print("=" * 50)
    print(f"✅ PREPROCESSING SELESAI!")
    print(f"   Data Bersih: {final_len} baris")
    print(f"   Dibuang: {dropped_count} baris (Log Normal/Recovery dibuang)")
    print(f"   File tersimpan: {OUTPUT_FILE}")
    print("\nContoh Data Bersih (5 Teratas):")
    print(final_df.head())
    print("=" * 50)

if __name__ == "__main__":
    main()