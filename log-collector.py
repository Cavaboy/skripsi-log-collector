import requests
import pandas as pd
import time
from requests.auth import HTTPBasicAuth
from datetime import datetime
import os

# ================= KONFIGURASI =================
# Masukkan IP Management (Ether1) router Anda di sini
ROUTERS = [
    {"name": "R1-Core",   "ip": "192.168.153.131"},  # <-- Ganti IP ini
    {"name": "R2-Dist",   "ip": "192.168.153.132"},  # <-- Ganti IP ini
    {"name": "R3-Access", "ip": "192.168.153.133"}   # <-- Ganti IP ini
]

USER = "admin"
PASS = "admin"
CSV_FILE = "dataset_log_skripsi.csv"
# ===============================================

def fetch_logs(router):
    """Mengambil log dari router tertentu"""
    url = f"http://{router['ip']}/rest/log"
    print(f"[*] Menghubungi {router['name']} ({router['ip']})...")
    
    try:
        # Timeout 2 detik agar tidak hang jika koneksi putus
        response = requests.get(url, auth=HTTPBasicAuth(USER, PASS), timeout=2)
        
        if response.status_code == 200:
            data = response.json()
            # Tambahkan identitas router dan waktu ambil
            for entry in data:
                entry['source_router'] = router['name']
                entry['fetched_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return data
        else:
            print(f"    [!] Gagal login ke {router['name']} (Status: {response.status_code})")
            return []
            
    except Exception as e:
        print(f"    [X] Error koneksi ke {router['name']}: {e}")
        return []

def main():
    print("=== SKRIPSI LOG COLLECTOR STARTED ===")
    print(f"Target: {len(ROUTERS)} Router")
    
    while True:
        all_new_logs = []
        
        # Loop ke semua router
        for r in ROUTERS:
            logs = fetch_logs(r)
            if logs:
                all_new_logs.extend(logs)
        
        # Simpan ke CSV jika ada data
        if all_new_logs:
            df = pd.DataFrame(all_new_logs)
            
            # Filter kolom penting untuk FP-Growth
            # Kita ambil topic & message karena itu inti gejalanya
            cols = ['fetched_at', 'source_router', 'time', 'topics', 'message']
            # Pastikan kolom ada (jaga-jaga kalau kosong)
            existing_cols = [c for c in cols if c in df.columns]
            df = df[existing_cols]

            # Mode 'a' (append) agar tidak menimpa data lama
            header_mode = not os.path.isfile(CSV_FILE)
            df.to_csv(CSV_FILE, mode='a', index=False, header=header_mode)
            print(f"--> [OK] Disimpan: {len(df)} baris log baru.")
        else:
            print("--> Tidak ada log atau koneksi gagal.")

        print("\nMenunggu 5 detik...\n")
        time.sleep(5)

if __name__ == "__main__":
    main()