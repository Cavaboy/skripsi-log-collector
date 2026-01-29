import requests
import pandas as pd
import time
from requests.auth import HTTPBasicAuth
from datetime import datetime
import os

# ================= KONFIGURASI =================
ROUTERS = [
    {"name": "R1-Core",   "ip": "192.168.153.131"},
    {"name": "R2-Dist",   "ip": "192.168.153.132"},
    {"name": "R3-Access", "ip": "192.168.153.133"}
]

USER = "admin"
PASS = "admin"
CSV_FILE = "dataset_log_skripsi.csv"

# State untuk menyimpan ID log terakhir (Hex) untuk setiap router
# Contoh: {'R1-Core': 20, 'R2-Dist': 5}
last_seen_ids = {r['name']: -1 for r in ROUTERS} 
# ===============================================

def parse_mikrotik_id(id_str):
    """Mengubah ID MikroTik (contoh: *14) menjadi integer."""
    try:
        # Hapus karakter '*' dan ubah hex ke int
        return int(id_str.replace('*', ''), 16)
    except:
        return -1

def fetch_logs(router):
    """Mengambil log dan memfilter hanya yang BARU"""
    url = f"http://{router['ip']}/rest/log"
    # Gunakan verify=False jika nanti ganti ke HTTPS
    
    try:
        response = requests.get(url, auth=HTTPBasicAuth(USER, PASS), timeout=2)
        
        if response.status_code == 200:
            raw_data = response.json()
            new_logs = []
            
            # Urutkan log berdasarkan ID (penting karena API kadang tidak urut)
            # Menghindari error jika '.id' tidak ada
            raw_data_sorted = sorted(raw_data, key=lambda x: parse_mikrotik_id(x.get('.id', '*0')))

            current_last_id = last_seen_ids[router['name']]
            max_id_in_batch = current_last_id

            for entry in raw_data_sorted:
                entry_id = parse_mikrotik_id(entry.get('.id', '*0'))
                
                # LOGIC UTAMA: Hanya ambil jika ID > ID terakhir yang disimpan
                if entry_id > current_last_id:
                    # Cleaning Topics: List ['ospf', 'error'] -> String "ospf,error"
                    # Ini agar mudah dibaca CSV
                    topics_str = ",".join(entry.get('topics', []))
                    
                    clean_entry = {
                        'fetched_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'source_router': router['name'],
                        'log_id': entry.get('.id'), # Simpan ID asli untuk referensi
                        'time': entry.get('time'),
                        'topics': topics_str, 
                        'message': entry.get('message')
                    }
                    new_logs.append(clean_entry)
                    
                    # Update max_id sementara
                    if entry_id > max_id_in_batch:
                        max_id_in_batch = entry_id
            
            # Update state global hanya jika ada log baru
            if max_id_in_batch > current_last_id:
                last_seen_ids[router['name']] = max_id_in_batch
                
            return new_logs
        else:
            print(f" [!] Gagal login ke {router['name']} (Status: {response.status_code})")
            return []
            
    except Exception as e:
        print(f" [X] Error koneksi ke {router['name']}: {e}")
        return []

def main():
    print("=== SKRIPSI LOG COLLECTOR (ANTI-DUPLICATE) STARTED ===")
    
    # Inisialisasi Header CSV jika file belum ada
    if not os.path.isfile(CSV_FILE):
        dummy_df = pd.DataFrame(columns=['fetched_at', 'source_router', 'log_id', 'time', 'topics', 'message'])
        dummy_df.to_csv(CSV_FILE, index=False)
        print(f"[INFO] File {CSV_FILE} dibuat baru.")

    while True:
        all_new_logs = []
        
        for r in ROUTERS:
            logs = fetch_logs(r)
            if logs:
                all_new_logs.extend(logs)
                print(f"    + {r['name']}: {len(logs)} log baru.")
        
        if all_new_logs:
            df = pd.DataFrame(all_new_logs)
            df.to_csv(CSV_FILE, mode='a', index=False, header=False)
            print(f"--> [OK] Total {len(df)} baris tersimpan ke CSV.")
        else:
            print("--> Tidak ada log baru (Duplikasi dicegah).")

        time.sleep(5)

if __name__ == "__main__":
    main()