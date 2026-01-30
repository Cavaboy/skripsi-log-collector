import pandas as pd
import os

# Konfigurasi Nama File dan Label Skenario
# Pastikan nama file di sini SESUAI dengan nama file di laptop Anda
files = {
    '../Data/dataset_log_20260130_202136_dataset_normal.csv': 'NORMAL',
    '../Data/dataset_log_20260130_162450_upstream_failure.csv': 'UPSTREAM_FAILURE',
    '../Data/dataset_log_20260130_103204_link_failure.csv': 'LINK_FAILURE',
    '../Data/dataset_log_20260130_190223_DDOS_Attack.csv': 'DDOS_ATTACK',
    '../Data/dataset_log_20260130_131104_broadcast_storm.csv': 'BROADCAST_STORM' 
}

dfs = []

print("Mulai proses penggabungan data...")

for filename, label in files.items():
    if os.path.exists(filename):
        print(f"Reading {filename}...")
        try:
            # Baca CSV
            df = pd.read_csv(filename)
            
            # Tambahkan kolom 'Label' agar kita tahu ini data skenario apa
            df['Label'] = label
            
            # Masukkan ke list
            dfs.append(df)
            print(f"  -> Berhasil! Jumlah baris: {len(df)}")
            
        except Exception as e:
            print(f"  -> ERROR membaca file {filename}: {e}")
    else:
        print(f"  -> WARNING: File {filename} TIDAK DITEMUKAN di folder ini.")

# Gabungkan semua data
if dfs:
    master_df = pd.concat(dfs, ignore_index=True)
    
    # Simpan ke CSV baru
    output_file = '../Data/Master_Dataset_Gabungan.csv'
    master_df.to_csv(output_file, index=False)
    
    print("\n" + "="*50)
    print(f"SUKSES! Data berhasil digabung ke '{output_file}'")
    print(f"Total Data: {len(master_df)} baris")
    print("Statistik Label:")
    print(master_df['Label'].value_counts())
    print("="*50)
else:
    print("\nTidak ada data yang digabungkan. Cek nama file Anda.")