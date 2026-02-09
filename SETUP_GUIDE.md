# Network RCA System - Setup & Run Guide

## Konfigurasi Akses untuk VM Windows → Host

Sistem ini dirancang untuk berjalan di VM Windows yang terhubung ke jaringan router, dengan dashboard bisa diakses dari Host.

### Prerequisites
- Python 3.8+ (di VM Windows)
- Packages: `pandas`, `streamlit`, `requests`

Install packages:
```bash
pip install -r requirements.txt
```

---

## Cara Menjalankan

### 1. **Di VM Windows - Terminal 1: Live Log Collector**

Jalankan live log collector (real-time monitoring):
```bash
python live_log_collector.py
```

**Output:**
- File `live_log.csv` akan dibuat otomatis
- Setiap 5 detik akan polling 3 router (R1-Core, R2-Dist, R3-Access)
- Simpan max 500 baris terakhir (configurable di `MAX_LIVE_LOG_ROWS`)

Pastikan berjalan sampai muncul pesan:
```
=== LIVE LOG COLLECTOR STARTED ===
[INFO] Menulis ke file lokal: live_log.csv
[INFO] Poll interval: 5 detik
```

---

### 2. **Di VM Windows - Terminal 2: Streamlit Dashboard**

Jalankan dashboard:
```bash
streamlit run dashboard.py
```

**Expected Output:**
```
  You can now view your Streamlit app in your browser.

  Network address: http://<VM-IP>:8501
  Local URL: http://localhost:8501
```

---

## Akses dari Host

### Cara 1: Browser (Recommended)
1. Di Host, buka browser
2. Ketik: `http://<VM-IP>:8501`
   - Ganti `<VM-IP>` dengan IP address VM Windows (e.g., `192.168.1.100`)

### Cara 2: Command Line di Host
```bash
curl http://<VM-IP>:8501
```

---

## Troubleshooting

### 1. **Dashboard tidak bisa diakses dari Host**
- Cek firewall VM Windows:
  - Pastikan port 8501 tidak diblock
  - Buka Windows Defender Firewall → Allow streamlit.exe

- Cek IP VM Windows:
  ```bash
  ipconfig  # Di VM Windows
  ```
  Gunakan IP yang tertera (contoh: `192.168.x.x`)

### 2. **Live Log Collector error: Connection Timeout**
- Cek IP router dan credentials:
  - Buka `live_log_collector.py`
  - Verifikasi `ROUTERS` list dan `USER/PASS`
  - Pastikan VM bisa ping ke router: `ping 192.168.153.137`

### 3. **live_log.csv tidak terbuat atau kosong**
- Cek permission folder (pastikan bisa write)
- Cek log output dari `live_log_collector.py`
- Kalau ada connection error, tunggu sampai router koneksi

---

## Struktur Monitoring

```
VM Windows (terhubung ke Router)
│
├─ live_log_collector.py     (polling routers setiap 5s)
│  └─→ live_log.csv          (updated real-time)
│
├─ dashboard.py              (Streamlit app)
│  └─→ reads live_log.csv    (when "Live Log Checking" enabled)
│
└─ bisa diakses dari Host via http://<VM-IP>:8501
```

---

## Configuration

### Ubah Polling Interval
Edit `live_log_collector.py`:
```python
POLL_INTERVAL = 5  # Ubah ke nilai yang diinginkan (detik)
```

### Ubah Max Live Log Rows
Edit `live_log_collector.py`:
```python
MAX_LIVE_LOG_ROWS = 500  # Ubah ke nilai yang diinginkan
```

### Ubah Port Streamlit
Edit `.streamlit/config.toml`:
```toml
[server]
port = 8501  # Ubah ke port lain jika perlu
```

---

## Optional: Running as Background Process

### Windows - Using nssm (Non-Sucking Service Manager)
```bash
# Install nssm terlebih dahulu
# Download dari: https://nssm.cc/download

# Setup service untuk live_log_collector
nssm install LiveLogCollector "C:\path\to\Python\python.exe" "C:\path\to\live_log_collector.py"
nssm start LiveLogCollector

# Setup service untuk dashboard
nssm install StreamlitDashboard "C:\path\to\Python\python.exe" "-m streamlit run dashboard.py"
nssm start StreamlitDashboard
```

### Windows - Using Task Scheduler
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (at startup, on schedule, etc.)
4. Set action: Start Program (`python.exe` dengan arguments)
5. Enable "Run with highest privileges"

---

## Summary

✅ **VM Windows:**
- Menjalankan `live_log_collector.py` (collect logs)
- Menjalankan `dashboard.py` (Streamlit server di 0.0.0.0:8501)

✅ **Host/Client:**
- Buka browser ke `http://<VM-IP>:8501`
- View grafis, tables, live monitoring

✅ **Live Mode di Dashboard:**
- Enable "Live Log Checking" checkbox
- Refresh Interval bisa dipilih (5s, 10s, 15s, 30s)
- Auto-refresh sesuai interval

Selesai!
