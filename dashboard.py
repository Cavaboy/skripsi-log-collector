import streamlit as st
import pandas as pd
import re
import ast

# ==========================================
# 1. KONFIGURASI HALAMAN
# ==========================================
st.set_page_config(
    page_title="Dashboard Deteksi Anomali Jaringan",
    page_icon="🛡️",
    layout="wide"
)

# Judul dan Deskripsi
st.title("🛡️ Network Anomaly Detection System")
st.markdown("Sistem deteksi dini berbasis **FP-Growth Algorithm** untuk Router Mikrotik.")
st.markdown("---")

# ==========================================
# 2. FUNGSI-FUNGSI PENTING (BACKEND)
# ==========================================

# Fungsi Cleaning (Harus SAMA PERSIS dengan saat Training)
def clean_text(text):
    if not isinstance(text, str): return set()
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s\-]', ' ', text)
    stopwords = ['info', 'input', 'in', 'out', 'message', 'log', 'by', 'from', 'to', 'via', 'changed', 'set', 'connection-state', 'new', 'proto', 'type', 'code']
    words = text.split()
    return set([w for w in words if w not in stopwords and len(w) > 2])

# Load Rules dari File CSV (Hasil Jupyter Notebook)
@st.cache_data
def load_rules():
    try:
        # Ganti nama file ini sesuai output Jupyter Notebook Anda
        rules = pd.read_csv("Hasil_Rules_Skripsi.csv") 
        # Ubah string "frozenset({'a', 'b'})" kembali menjadi set Python
        rules['antecedents'] = rules['antecedents'].apply(lambda x: set(list(eval(x))))
        rules['consequents'] = rules['consequents'].apply(lambda x: list(eval(x))[0]) # Ambil labelnya saja
        return rules
    except FileNotFoundError:
        return None

# Fungsi Deteksi (Otak AI)
def detect_anomaly(log_line, rules_df):
    cleaned_items = clean_text(log_line)
    matches = []
    
    # Cek setiap rule, apakah item rule ada di dalam log barusan?
    for index, row in rules_df.iterrows():
        rule_items = row['antecedents']
        if rule_items.issubset(cleaned_items):
            matches.append({
                'Diagnosis': row['consequents'],
                'Confidence': row['confidence'],
                'Rule': str(rule_items)
            })
    
    if matches:
        # Ambil match dengan confidence tertinggi
        best_match = max(matches, key=lambda x: x['Confidence'])
        return best_match
    else:
        return {'Diagnosis': 'NORMAL / UNKNOWN', 'Confidence': 0.0, 'Rule': '-'}

# ==========================================
# 3. TAMPILAN UTAMA (FRONTEND)
# ==========================================

# Load Database Rules
rules_df = load_rules()

if rules_df is None:
    st.error("❌ File 'Hasil_Rules_Skripsi.csv' tidak ditemukan! Jalankan Jupyter Notebook dulu.")
else:
    # Sidebar: Statistik Rules
    st.sidebar.header("🧠 Knowledge Base")
    st.sidebar.metric("Total Rules", len(rules_df))
    st.sidebar.markdown("### Top Rules:")
    st.sidebar.dataframe(rules_df[['antecedents', 'consequents', 'confidence']].head(5))

    # Area Input Log
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 Log Analyzer Simulator")
        input_log = st.text_area("Masukkan Baris Log Mikrotik di sini:", height=100, 
                                 placeholder="Contoh: firewall,info DDoS_DETECTED input: in:ether1 proto ICMP...")
        
        if st.button("Analisis Log"):
            if input_log:
                result = detect_anomaly(input_log, rules_df)
                
                # Tampilkan Hasil
                diagnosis = result['Diagnosis']
                conf = result['Confidence']
                
                if diagnosis == 'DDOS_ATTACK':
                    st.error(f"⚠️ DETEKSI BAHAYA: {diagnosis}")
                elif diagnosis == 'BROADCAST_STORM':
                    st.warning(f"⚠️ PERINGATAN: {diagnosis}")
                elif 'FAILURE' in diagnosis:
                    st.warning(f"🔧 GANGGUAN FISIK: {diagnosis}")
                else:
                    st.success(f"✅ STATUS: {diagnosis}")
                
                st.info(f"**Confidence Level:** {conf*100:.1f}%")
                st.caption(f"Terdeteksi berdasarkan Rule: {result['Rule']}")
                
            else:
                st.warning("Masukkan teks log terlebih dahulu.")

    with col2:
        st.subheader("📊 Live Status")
        # Ini simulasi visual dashboard
        st.metric(label="Status Jaringan", value="Monitoring", delta="Active")
        st.progress(100)

# Footer
st.markdown("---")
st.caption("Skripsi 2026 - Rancang Bangun Deteksi Anomali Jaringan")