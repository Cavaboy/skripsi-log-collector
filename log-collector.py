import requests
import pandas as pd
import time
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from datetime import datetime
import os
import csv
import sys
import errno

# ================= KONFIGURASI =================
ROUTERS = [
    {"name": "R1-Core",   "ip": "192.168.153.131"},
    {"name": "R2-Dist",   "ip": "192.168.153.132"},
    {"name": "R3-Access", "ip": "192.168.153.133"}
]

USER = "admin"
PASS = "admin"
# Directory ke Shared Folder yang dimount dari Host Windows (UNC path)
CSV_DIR = r"\\vmware-host\Shared Folders\shared_folder_data_log"

# State untuk menyimpan ID log terakhir (Hex) untuk setiap router
# Contoh: {'R1-Core': 20, 'R2-Dist': 5}
last_seen_ids = {r['name']: -1 for r in ROUTERS}
# State tambahan: last seen timestamp per router untuk dedup lebih robust
last_seen_times = {r['name']: None for r in ROUTERS}
# ===============================================

def parse_mikrotik_id(id_str):
    """Mengubah ID MikroTik (contoh: *14) menjadi integer."""
    try:
        # Hapus karakter '*' dan ubah hex ke int
        return int(id_str.replace('*', ''), 16)
    except:
        return -1

def write_csv_with_retry(df, csv_file_path, write_header=False, max_retries=3):
    """Menulis DataFrame ke CSV dengan retry logic untuk mengatasi file locking."""
    for attempt in range(max_retries):
        try:
            df.to_csv(csv_file_path, mode='a', index=False, header=write_header, encoding='utf-8')
            return True
        except (PermissionError, IOError, OSError) as e:
            if attempt < max_retries - 1:
                # Tunggu sebelum retry (exponential backoff: 1s, 2s, 3s)
                wait_time = (attempt + 1) * 1
                print(f"[WARN] Write failed (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            else:
                print(f"[ERROR] Failed to write CSV after {max_retries} attempts: {e}")
                return False
    return False

def fetch_logs(router):
    """Mengambil log dan memfilter hanya yang BARU (berbasis ID dan timestamp)"""
    url = f"http://{router['ip']}/rest/log"
    # Gunakan verify=False jika nanti ganti ke HTTPS
    
    try:
        # timeout=(connect_timeout, read_timeout) untuk kontrol lebih baik
        response = requests.get(url, auth=HTTPBasicAuth(USER, PASS), timeout=(5, 10))
        response.raise_for_status()  # Raise HTTPError jika status bukan 200
        
        raw_data = response.json()
        new_logs = []
        
        # Urutkan log berdasarkan ID (penting karena API kadang tidak urut)
        # Menghindari error jika '.id' tidak ada
        raw_data_sorted = sorted(raw_data, key=lambda x: parse_mikrotik_id(x.get('.id', '*0')))

        current_last_id = last_seen_ids[router['name']]
        last_time = last_seen_times[router['name']]
        max_id_in_batch = current_last_id
        latest_time = last_time

        for entry in raw_data_sorted:
            entry_id = parse_mikrotik_id(entry.get('.id', '*0'))
            entry_time_str = entry.get('time')
            entry_time = None
            
            # Parse entry time jika tersedia (untuk dedup berbasis timestamp)
            if entry_time_str:
                try:
                    entry_time = datetime.strptime(entry_time_str, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    entry_time = None
            
            # Accept entry jika ID lebih baru OR timestamp lebih baru dari last seen
            accept_by_id = (entry_id > current_last_id)
            accept_by_time = False
            if entry_time and last_time:
                accept_by_time = (entry_time > last_time)
            elif entry_time and last_time is None:
                accept_by_time = True
            
            if accept_by_id or accept_by_time:
                # Cleaning Topics: List ['ospf', 'error'] -> String "ospf,error"
                # Robust handling untuk None, non-string elements, dan empty strings
                topics = entry.get('topics')
                if not topics:
                    topics_str = ""
                elif isinstance(topics, list):
                    # Convert semua elemen ke string, trim whitespace, abaikan yang kosong
                    topics_str = ",".join(str(t).strip() for t in topics if t is not None and str(t).strip())
                else:
                    # Jika sudah string, bersihkan whitespace
                    topics_str = str(topics).strip()
                
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
                
                # Update latest timestamp
                if entry_time:
                    if latest_time is None or entry_time > latest_time:
                        latest_time = entry_time
        
        # Update state global hanya jika ada log baru
        if max_id_in_batch > current_last_id:
            last_seen_ids[router['name']] = max_id_in_batch
        if latest_time and (last_time is None or latest_time > last_time):
            last_seen_times[router['name']] = latest_time
            
        return new_logs
        
    except RequestException as e:
        # Catch requests-specific exceptions (timeout, connection error, http error, etc.)
        print(f" [X] Error koneksi ke {router['name']}: {e}")
        return []
    except Exception as e:
        # Catch unexpected errors (json decode, etc.) — jangan menelan KeyboardInterrupt
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        print(f" [X] Error tak terduga di {router['name']}: {e}")
        return []

def main():
    print("=== SKRIPSI LOG COLLECTOR (ANTI-DUPLICATE) STARTED ===")
    # Validasi: pastikan folder shared mount ada sebelum melanjutkan
    shared_dir = CSV_DIR
    if not shared_dir or not os.path.isdir(shared_dir):
        print("Error: Shared folder not mounted")
        sys.exit(1)

    # Buat nama file CSV ber-timestamp untuk run ini
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"dataset_log_{timestamp}.csv"
    csv_file_path = os.path.join(shared_dir, csv_filename)
    print(f"[INFO] Menggunakan file CSV: {csv_file_path}")

    # Inisialisasi Header CSV jika file belum ada
    if not os.path.isfile(csv_file_path):
        dummy_df = pd.DataFrame(columns=['fetched_at', 'source_router', 'log_id', 'time', 'topics', 'message'])
        success = write_csv_with_retry(dummy_df, csv_file_path, write_header=True)
        if success:
            print(f"[INFO] File {csv_file_path} dibuat baru.")
        else:
            print(f"[ERROR] Gagal membuat file CSV di {csv_file_path}")
            sys.exit(1)

    # Daftar pesan status yang akan dicetak bergantian setiap loop (5 detik)
    status_messages = [
        "Waiting for new logs...",
        "Polling routers...",
        "Heartbeat: collector alive",
        "Idle — no new entries",
        "Still running — checking devices"
    ]
    status_idx = 0

    try:
        while True:
            all_new_logs = []
            
            for r in ROUTERS:
                logs = fetch_logs(r)
                if logs:
                    all_new_logs.extend(logs)
                    print(f"    + {r['name']}: {len(logs)} log baru.")
            
            if all_new_logs:
                df = pd.DataFrame(all_new_logs)
                # Tulis header hanya jika file baru (adaptive)
                write_header = not os.path.isfile(csv_file_path)
                success = write_csv_with_retry(df, csv_file_path, write_header=write_header)
                if success:
                    print(f"--> [OK] Total {len(df)} baris tersimpan ke CSV.")
                else:
                    print(f"--> [WARN] Gagal menyimpan {len(df)} baris ke CSV (akan retry di iterasi berikutnya).")
            else:
                print("--> Tidak ada log baru (Duplikasi dicegah).")

            # Cetak satu pesan status berbeda setiap iterasi (untuk menunjukkan script berjalan)
            status = status_messages[status_idx % len(status_messages)]
            print(f"-- {status}  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
            status_idx += 1

            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[INFO] Stop requested by user (Ctrl+C). Exiting gracefully.")
    except Exception as e:
        # Catch unexpected errors dalam main loop
        print(f"[X] Unexpected error in main loop: {e}")
        import traceback
        traceback.print_exc()  # Debug: cetak traceback jika ada error yang tak terduga

if __name__ == "__main__":
    main()