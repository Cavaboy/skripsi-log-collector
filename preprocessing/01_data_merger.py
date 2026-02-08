import pandas as pd
import os

# Konfigurasi Nama File dan Label Skenario
# Menggunakan format r'path' (raw string) agar backslash tidak dianggap karakter escape
files = {
    "../Data/dataset_log_20260130_202136_dataset_normal.csv": "NORMAL",
    "../Data/fix_dataset_log_20260208_190350_upstream_failure.csv": "UPSTREAM_FAILURE",
    "../Data/fix_dataset_log_20260208_175633_linkfailure.csv": "LINK_FAILURE",
    "../Data/dataset_log_20260130_131104_broadcast_storm.csv": "BROADCAST_STORM",
    "../Data/dataset_log_20260130_190223_DDOS_Attack.csv": "DDOS_ATTACK",
}

dfs = []

print("Mulai proses penggabungan data...")

# Mendapatkan absolute path dari folder saat ini untuk debugging jika masih error
current_dir = os.getcwd()
print(f"Direktori kerja saat ini: {current_dir}\n")

for filename, label in files.items():
    # Menggunakan os.path.normpath agar format slash otomatis disesuaikan dengan Windows
    clean_path = os.path.normpath(filename)

    if os.path.exists(clean_path):
        print(f"Reading {clean_path}...")
        try:
            # Baca CSV
            df = pd.read_csv(clean_path)

            # Tambahkan kolom 'Label' agar kita tahu ini data skenario apa
            df["Label"] = label

            # Masukkan ke list
            dfs.append(df)
            print(f"  -> Berhasil! Jumlah baris: {len(df)}")

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
    output_dir = os.path.normpath("../Data")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_file = os.path.join(output_dir, "Master_Dataset_Gabungan_v2.2.csv")
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
