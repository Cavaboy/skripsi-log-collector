import pandas as pd
import os

# Konfigurasi Nama File dan Label Skenario
# Menggunakan format r'path' (raw string) agar backslash tidak dianggap karakter escape
files = {
    "../Data/dataset_normal.csv": "NORMAL",
    "../Data/dataset_upstreamfailure.csv": "UPSTREAM_FAILURE",
    "../Data/dataset_linkfailure.csv": "LINK_FAILURE",
    "../Data/bs_loop.csv": "BROADCAST_STORM",
    "../Data/bs_bandwith.csv": "BROADCAST_STORM",
    "../Data/ddos_icmp.csv": "DDOS_ATTACK",
    "../Data/ddos_bandwith_exhaustion.csv": "DDOS_ATTACK",
    "../Data/ddos_ppsflood.csv": "DDOS_ATTACK",
    "../Data/ddos_tcpflood.csv": "DDOS_ATTACK",
    "../Data/ddos_portscan.csv": "DDOS_ATTACK",
}

dfs = []

print("Mulai proses penggabungan data...")

# Mendapatkan absolute path dari script ini agar jalannya selalu benar dari folder mana pun
script_dir = os.path.dirname(os.path.abspath(__file__))
print(f"Direktori script ini: {script_dir}\n")

for filename, label in files.items():
    # Buat path absolut dari lokasi script ini ke ../Data/...
    clean_path = os.path.normpath(os.path.join(script_dir, filename))

    if os.path.exists(clean_path):
        print(f"Reading {clean_path}...")
        try:
            # Baca CSV
            df = pd.read_csv(clean_path)

            # Tambahkan kolom 'Label' agar kita tahu ini data skenario apa
            df["Label"] = label

            # --- CUSTOM LOGIC SAMPLING ---
            if label == "DDOS_ATTACK":
                # Ambil tepat 500 baris acak per file DDOS
                sample_size = min(500, len(df))
                df = df.sample(n=sample_size, random_state=42)
            elif "bs_loop.csv" in filename:
                # Ambil tepat 1.517 baris acak
                sample_size = min(1517, len(df))
                df = df.sample(n=sample_size, random_state=42)
            elif "bs_bandwith.csv" in filename:
                # Ambil semua untuk disubsidi silang (harus ~983)
                pass 
            # NORMAL, LINK_FAILURE, UPSTREAM_FAILURE dibiarkan utuh

            # Masukkan ke list
            dfs.append(df)
            print(f"  -> Berhasil! Jumlah baris diambil: {len(df)}")

        except Exception as e:
            print(f"  -> ERROR membaca file {clean_path}: {e}")
    else:
        # Menampilkan absolute path agar Anda bisa cek di mana Python mencari file tersebut
        abs_path = os.path.abspath(clean_path)
        print(f"  -> WARNING: File TIDAK DITEMUKAN.")
        print(f"     Dicari di: {abs_path}")

# Gabungkan semua data
if dfs:
    master_df = pd.concat(dfs, ignore_index=True)

    # Simpan ke CSV baru
    output_dir = os.path.normpath(os.path.join(script_dir, "../Data"))
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    import glob
    import re
    MAJOR_VERSION = 3
    existing_files = glob.glob(os.path.join(output_dir, f"Master_Dataset_Gabungan_v{MAJOR_VERSION}.*.csv"))
    
    minor_versions = []
    for f in existing_files:
        match = re.search(rf"v{MAJOR_VERSION}\.(\d+)\.csv$", f)
        if match:
            minor_versions.append(int(match.group(1)))
            
    next_minor = max(minor_versions) + 1 if minor_versions else 0
    output_filename = f"Master_Dataset_Gabungan_v{MAJOR_VERSION}.{next_minor}.csv"
    output_file = os.path.join(output_dir, output_filename)

    master_df.to_csv(output_file, index=False)

    print("\n" + "=" * 50)
    print(f"SUKSES! Data berhasil digabung ke '{output_file}'")
    print(f"Total Data: {len(master_df)} baris")
    print("Statistik Label:")
    print(master_df["Label"].value_counts())
    print("=" * 50)
else:
    print(
        "\nTidak ada data yang digabungkan. Pastikan folder '../Data' ada di satu tingkat di atas folder script ini."
    )
