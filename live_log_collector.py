import requests
import pandas as pd
import time
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException
from datetime import datetime
import os
import sys

# ================= KONFIGURASI =================
ROUTERS = [
    {"name": "R1-Core", "ip": "192.168.153.137"},
    {"name": "R2-Dist", "ip": "192.168.153.139"},
    {"name": "R3-Access", "ip": "192.168.153.133"},
]

USER = "admin"
PASS = "admin"
LIVE_LOG_FILE = "live_log.csv"  # Simpan di direktori saat ini
MAX_LIVE_LOG_ROWS = 2000  # Jumlah maksimal log yang disimpan (untuk efisiensi)
POLL_INTERVAL = 5  # Detik

# State untuk menyimpan ID log terakhir (Hex) untuk setiap router
last_seen_ids = {r["name"]: -1 for r in ROUTERS}
# State tambahan: last seen timestamp per router untuk dedup lebih robust
last_seen_times = {r["name"]: None for r in ROUTERS}
# ===============================================


def parse_mikrotik_id(id_str):
    """Mengubah ID MikroTik (contoh: *14) menjadi integer."""
    try:
        return int(id_str.replace("*", ""), 16)
    except:
        return -1


def write_live_csv(df, csv_file_path, max_rows=500):
    """
    Menulis DataFrame ke live CSV dengan limit rows.
    Menjaga hanya N baris terakhir untuk efisiensi live monitoring.
    Menggunakan retry mechanism untuk mengatasi file locking on Windows.
    Returns: (success, total_rows_in_file)
    """
    retries = 5
    for i in range(retries):
        try:
            # Jika file sudah ada, baca dan append
            if os.path.isfile(csv_file_path):
                try:
                    existing_df = pd.read_csv(csv_file_path)
                    combined_df = pd.concat([existing_df, df], ignore_index=True)
                except pd.errors.EmptyDataError:
                     # Handle case where file exists but is empty
                     combined_df = df
                except Exception:
                     # If read fails, raise to trigger retry
                     raise PermissionError("Read failed due to lock")
            else:
                combined_df = df

            # Keep hanya last N rows (untuk live mode, jangan terlalu besar)
            if len(combined_df) > max_rows:
                combined_df = combined_df.tail(max_rows).reset_index(drop=True)

            # Tulis ulang seluruh file (replace mode)
            combined_df.to_csv(csv_file_path, index=False, encoding="utf-8")
            return True, len(combined_df)
            
        except PermissionError:
            if i < retries - 1:
                time.sleep(0.2)  # Wait a bit before retry
                continue
            else:
                print(f"[WARN] Gagal menulis ke {csv_file_path} (Locked) setelah {retries} percobaan.")
                return False, 0
        except Exception as e:
            print(f"[ERROR] Gagal menulis ke {csv_file_path}: {e}")
            return False, 0
    return False, 0


def fetch_logs(router):
    """Mengambil log dan memfilter hanya yang BARU (berbasis ID dan timestamp)"""
    url = f"http://{router['ip']}/rest/log"

    try:
        response = requests.get(url, auth=HTTPBasicAuth(USER, PASS), timeout=(5, 10))
        response.raise_for_status()

        raw_data = response.json()
        new_logs = []

        # Urutkan log berdasarkan ID
        raw_data_sorted = sorted(
            raw_data, key=lambda x: parse_mikrotik_id(x.get(".id", "*0"))
        )

        current_last_id = last_seen_ids[router["name"]]
        last_time = last_seen_times[router["name"]]
        max_id_in_batch = current_last_id
        latest_time = last_time

        for entry in raw_data_sorted:
            entry_id = parse_mikrotik_id(entry.get(".id", "*0"))
            entry_time_str = entry.get("time")
            entry_time = None

            # Parse entry time
            if entry_time_str:
                try:
                    entry_time = datetime.strptime(entry_time_str, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    entry_time = None

            # Accept entry jika ID lebih baru OR timestamp lebih baru
            accept_by_id = entry_id > current_last_id
            accept_by_time = False
            if entry_time and last_time:
                accept_by_time = entry_time > last_time
            elif entry_time and last_time is None:
                accept_by_time = True

            if accept_by_id or accept_by_time:
                # Cleaning Topics
                topics = entry.get("topics")
                if not topics:
                    topics_str = ""
                elif isinstance(topics, list):
                    topics_str = ",".join(
                        str(t).strip()
                        for t in topics
                        if t is not None and str(t).strip()
                    )
                else:
                    topics_str = str(topics).strip()

                clean_entry = {
                    "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_router": router["name"],
                    "log_id": entry.get(".id"),
                    "time": entry.get("time"),
                    "topics": topics_str,
                    "message": entry.get("message"),
                }
                new_logs.append(clean_entry)

                # Update max_id
                if entry_id > max_id_in_batch:
                    max_id_in_batch = entry_id

                # Update latest timestamp
                if entry_time:
                    if latest_time is None or entry_time > latest_time:
                        latest_time = entry_time

        # Update state global hanya jika ada log baru
        if max_id_in_batch > current_last_id:
            last_seen_ids[router["name"]] = max_id_in_batch
        if latest_time and (last_time is None or latest_time > last_time):
            last_seen_times[router["name"]] = latest_time

        return new_logs

    except RequestException as e:
        print(f"[X] Error koneksi ke {router['name']}: {e}")
        return []
    except Exception as e:
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        print(f"[X] Error tak terduga di {router['name']}: {e}")
        return []


def main():
    print("=== LIVE LOG COLLECTOR STARTED ===")
    print(f"[INFO] Menulis ke file lokal: {LIVE_LOG_FILE}")
    print(f"[INFO] Max live log rows: {MAX_LIVE_LOG_ROWS}")
    print(f"[INFO] Poll interval: {POLL_INTERVAL} detik")

    # === [FEATURE] WIPE ON STARTUP ===
    # Always create fresh file with header on startup
    dummy_df = pd.DataFrame(
        columns=[
            "fetched_at",
            "source_router",
            "log_id",
            "time",
            "topics",
            "message",
        ]
    )
    try:
        dummy_df.to_csv(LIVE_LOG_FILE, index=False, encoding="utf-8")
        print(f"[INFO] File {LIVE_LOG_FILE} has been wiped and initialized with header.")
    except PermissionError:
        print(f"[WARN] Could not wipe {LIVE_LOG_FILE} (Locked). Will append instead.")
    except Exception as e:
         print(f"[ERROR] initializing file: {e}")


    status_messages = [
        "Listening for new logs...",
        "Polling routers (live)...",
        "Heartbeat: live collector active",
        "Idle — no new entries (live)",
        "Still running — checking devices",
    ]
    status_idx = 0

    try:
        while True:
            all_new_logs = []

            # Polling setiap router
            for r in ROUTERS:
                logs = fetch_logs(r)
                if logs:
                    all_new_logs.extend(logs)
                    print(f"    + {r['name']}: {len(logs)} log baru.")

            # Tulis ke live CSV jika ada log baru
            if all_new_logs:
                df = pd.DataFrame(all_new_logs)
                success, total_curr_rows = write_live_csv(df, LIVE_LOG_FILE, max_rows=MAX_LIVE_LOG_ROWS)
                if success:
                    print(
                        f"--> [OK] Total {len(df)} baris baru ditambahkan. Total dalam live_log.csv: {total_curr_rows}"
                    )
                else:
                    print(f"--> [WARN] Gagal menulis ke live_log.csv")
            else:
                print("--> Tidak ada log baru (Dedup active).")

            # Status message
            status = status_messages[status_idx % len(status_messages)]
            print(f"-- {status}  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]")
            status_idx += 1

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[INFO] Stop requested by user (Ctrl+C). Exiting gracefully.")
        # === [FEATURE] WIPE ON EXIT ===
        try:
             # Re-create empty dataframe to overwrite file
             dummy_df = pd.DataFrame(
                columns=[
                    "fetched_at",
                    "source_router",
                    "log_id",
                    "time",
                    "topics",
                    "message",
                ]
            )
             dummy_df.to_csv(LIVE_LOG_FILE, index=False, encoding="utf-8")
             print(f"[INFO] File {LIVE_LOG_FILE} has been wiped on exit.")
        except Exception as e:
             print(f"[ERROR] Failed to wipe on exit: {e}")
    except Exception as e:
        print(f"[X] Unexpected error in main loop: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
