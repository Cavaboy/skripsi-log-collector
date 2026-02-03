import streamlit as st
import pandas as pd
import re
import time
import os
import ast

# ==========================================
# 1. KONFIGURASI HALAMAN
# ==========================================
st.set_page_config(
    page_title="Real-Time Network Sentinel",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Anomaly Detection System (Live)")
st.markdown("Sistem deteksi dini berbasis **FP-Growth Algorithm** secara Real-Time.")
st.markdown("---")

# ==========================================
# 2. FUNGSI BACKEND (SAMA SEPERTI SEBELUMNYA)
# ==========================================
def clean_text(text):
    if not isinstance(text, str): return set()
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s\-]', ' ', text)
    stopwords = ['info', 'input', 'in', 'out', 'message', 'log', 'by', 'from', 'to', 'via', 'changed', 'set', 'connection-state', 'new', 'proto', 'type', 'code']
    words = text.split()
    return set([w for w in words if w not in stopwords and len(w) > 2])

@st.cache_data
def load_rules():
    try:
        rules = pd.read_csv("Hasil_Rules_Skripsi.csv") 
        rules['antecedents'] = rules['antecedents'].apply(lambda x: set(list(eval(x))))
        rules['consequents'] = rules['consequents'].apply(lambda x: list(eval(x))[0])
        return rules
    except FileNotFoundError:
        return None

def detect_anomaly(log_line, rules_df):
    cleaned_items = clean_text(log_line)
    matches = []
    for index, row in rules_df.iterrows():
        rule_items = row['antecedents']
        if rule_items.issubset(cleaned_items):
            matches.append({'Diagnosis': row['consequents'], 'Confidence': row['confidence']})
    
    if matches:
        return max(matches, key=lambda x: x['Confidence'])
    else:
        return {'Diagnosis': 'NORMAL / UNKNOWN', 'Confidence': 0.0}

# ==========================================
# 3. INTERFACE DASHBOARD LIVE
# ==========================================
rules_df = load_rules()

if rules_df is None:
    st.error("❌ File Rules tidak ditemukan! Jalankan Jupyter Notebook dulu.")
    st.stop()

# Sidebar
st.sidebar.header("🎛️ Control Panel")
live_mode = st.sidebar.toggle("🔴 AKTIFKAN LIVE MONITORING", value=False)
refresh_rate = st.sidebar.slider("Refresh Rate (detik)", 0.5, 5.0, 1.0)
log_source = st.sidebar.text_input("Path File Log Live", "live_log.csv")

# Placeholder untuk update konten secara dinamis
status_container = st.empty()
log_container = st.empty()

# LOGIKA LIVE MONITORING
if live_mode:
    # Cek apakah file log ada
    if not os.path.exists(log_source):
        status_container.error(f"❌ File '{log_source}' belum ada. Jalankan script logger dulu!")
    else:
        # Loop terus menerus (seperti CCTV)
        while True:
            try:
                # 1. Baca 10 baris terakhir dari file log (Real-time reading)
                # on_bad_lines='skip' biar gak crash kalau ada baris log yang lagi ditulis setengah
                df_live = pd.read_csv(log_source, on_bad_lines='skip').tail(10)
                
                # Ambil baris paling baru (terakhir)
                if not df_live.empty:
                    last_log = df_live.iloc[-1]
                    raw_message = f"{last_log['topics']} {last_log['message']}"
                    timestamp = last_log['time']
                    
                    # 2. Analisis dengan AI
                    result = detect_anomaly(raw_message, rules_df)
                    diagnosis = result['Diagnosis']
                    conf = result['Confidence'] * 100

                    # 3. Update Tampilan (Tanpa Refresh Halaman)
                    with status_container.container():
                        col1, col2, col3 = st.columns([1, 2, 1])
                        
                        with col1:
                            st.metric("Last Update", timestamp.split(" ")[-1])
                        
                        with col2:
                            if diagnosis == 'DDOS_ATTACK':
                                st.error(f"⚠️ **TERDETEKSI: {diagnosis}**")
                            elif diagnosis == 'BROADCAST_STORM':
                                st.warning(f"⚠️ **TERDETEKSI: {diagnosis}**")
                            elif 'FAILURE' in diagnosis:
                                st.warning(f"🔧 **GANGGUAN: {diagnosis}**")
                            else:
                                st.success(f"✅ **STATUS: AMAN ({diagnosis})**")
                        
                        with col3:
                            st.metric("AI Confidence", f"{conf:.1f}%")

                    # Tampilkan Tabel Log Terkini
                    with log_container.container():
                        st.subheader("📜 Live Log Stream")
                        # Kita bikin tabelnya ada highlight warna kalau bahaya
                        def highlight_row(row):
                            msg = str(row['message']) + str(row['topics'])
                            if 'DDoS' in msg: return ['background-color: #ffcccc'] * len(row)
                            if 'down' in msg: return ['background-color: #ffffcc'] * len(row)
                            return [''] * len(row)

                        st.dataframe(df_live[['time', 'source_router', 'message']].sort_index(ascending=False), use_container_width=True)

                # 4. Tidur sebentar sebelum cek lagi
                time.sleep(refresh_rate)
                
            except Exception as e:
                status_container.error(f"Error membaca log: {e}")
                time.sleep(1)

else:
    # Tampilan jika Live Mode Mati (Mode Manual)
    st.info("👋 Sistem Standby. Aktifkan 'LIVE MONITORING' di sidebar untuk memulai pemindaian otomatis.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Tes Manual")
        test_log = st.text_area("Paste log di sini untuk tes manual:")
        if st.button("Cek Log"):
            res = detect_anomaly(test_log, rules_df)
            st.write(f"Hasil: **{res['Diagnosis']}** (Conf: {res['Confidence']:.2f})")