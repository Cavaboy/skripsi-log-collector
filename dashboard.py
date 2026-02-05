import streamlit as st
import pandas as pd
import ast
import re
import time
import os

# ==========================================
# 1. KONFIGURASI HALAMAN
# ==========================================
st.set_page_config(
    page_title="Network RCA System",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS (Dark Mode Friendly & Professional)
st.markdown("""
<style>
    /* Card Styles - Menggunakan RGBA agar adaptif dengan Dark/Light Mode */
    .card {
        padding: 15px 20px;
        border-radius: 6px;
        margin-bottom: 15px;
        border: 1px solid rgba(128, 128, 128, 0.2);
    }
    
    .status-critical {
        background-color: rgba(255, 75, 75, 0.1); /* Merah transparan */
        border-left: 5px solid #ff4b4b;
    }
    
    .status-high {
        background-color: rgba(255, 165, 0, 0.1); /* Orange transparan */
        border-left: 5px solid #ffa500;
    }

    /* Typography */
    .card-header {
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .card-meta {
        font-size: 0.85rem;
        opacity: 0.8; /* Agar tidak terlalu kontras di dark mode */
        margin-bottom: 10px;
        font-family: monospace;
    }
    
    /* Evidence Tag Style */
    .evidence-tag { 
        background-color: rgba(128, 128, 128, 0.2); 
        padding: 2px 8px; 
        border-radius: 4px; 
        font-family: monospace; 
        font-size: 0.85em; 
        margin-right: 5px;
        display: inline-block;
    }

    /* Remove top padding standard Streamlit */
    .block-container { padding-top: 2rem; }
    
    /* Hide Table Index if needed (Optional) */
    thead tr th:first-child { display:none }
    tbody tr td:first-child { display:none }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. STATE MANAGEMENT
# ==========================================
if 'issues' not in st.session_state:
    st.session_state['issues'] = {}

def reset_state():
    st.session_state['issues'] = {}

# ==========================================
# 3. KAMUS & LOGIC (Sama seperti sebelumnya)
# ==========================================
RECOMMENDATION_MAP = {
    'LINK_FAILURE': {
        'title': 'Physical Link Failure',
        'desc': 'Putusnya koneksi fisik kabel atau port interface terdeteksi.',
        'actions': ['Periksa fisik kabel LAN (Ethernet).', 'Cek status Interface Bit Error Rate.', 'Pastikan perangkat lawan (peer) menyala.']
    },
    'UPSTREAM_FAILURE': {
        'title': 'Upstream/WAN Connection Failure',
        'desc': 'Terputusnya jalur utama menuju Gateway atau ISP.',
        'actions': ['Validasi status kabel Uplink/WAN.', 'Lakukan Ping ke Gateway Public (e.g., 8.8.8.8).', 'Koordinasi dengan penyedia ISP.']
    },
    'DDoS': {
        'title': 'DDoS Attack Pattern',
        'desc': 'Lonjakan trafik tidak wajar yang mengindikasikan serangan flood.',
        'actions': ['Analisis menu Firewall > Connections.', 'Terapkan Filter Rule untuk drop IP Source mencurigakan.', 'Batasi (Rate Limit) trafik ICMP/UDP.']
    },
    'BROADCAST_STORM': {
        'title': 'L2 Loop / Broadcast Storm',
        'desc': 'Indikasi looping pada jaringan Layer-2 (Switching loop).',
        'actions': ['Identifikasi kabel yang menghubungkan antar-switch (loop).', 'Pastikan RSTP/STP aktif pada Bridge.', 'Monitor CPU Load router.']
    }
}

STOPWORDS = {
    'message', 'info', 'via', 'from', 'to', 'route', 
    'script', 'system', 'debug', 'state', 'changed', 'defconf', 
    'input', 'forward', 'topics', 'log', 'time', 'date', 'identity',
    'ether1', 'ether2', 'ether3', 'ether4', 'ether5', 'wlan1', 'bridge',
    'up', 'running', 'full', 'exchange', 'loading', 'done', 'established'
}

def clean_text(text):
    if not isinstance(text, str): return set()
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    tokens = set(text.split())
    return tokens - STOPWORDS

# ==========================================
# 4. BACKEND PROCESSING
# ==========================================
@st.cache_data
def load_knowledge_base():
    # Ganti path sesuai struktur folder Anda
    possible_paths = ['Data/rules/Rules_fix.csv', 'Rules_fix.csv'] 
    df = pd.DataFrame()
    for f in possible_paths:
        if os.path.exists(f):
            try:
                df = pd.read_csv(f)
                break
            except: continue
            
    if df.empty: return pd.DataFrame()

    col_map = {'Root Cause (Gejala)': 'antecedents', 'Impact (Akibat)': 'consequents', 'Lift Ratio': 'lift', 'Confidence (%)': 'confidence'}
    df = df.rename(columns=col_map)

    def parse_and_clean(val):
        try: raw = set(ast.literal_eval(val))
        except: raw = set()
        return raw - STOPWORDS
    
    if 'antecedents' in df.columns and isinstance(df['antecedents'].iloc[0], str):
        df['antecedents'] = df['antecedents'].apply(parse_and_clean)

    def map_diagnosis(val):
        s = str(val).upper()
        if 'LINK_FAILURE' in s: return 'LINK_FAILURE'
        if 'UPSTREAM_FAILURE' in s: return 'UPSTREAM_FAILURE'
        if 'STORM' in s or 'LOOP' in s or 'BROADCAST' in s: return 'BROADCAST_STORM'
        if 'DDOS' in s: return 'DDoS'
        return None

    df['final_diagnosis'] = df['consequents'].apply(map_diagnosis)
    df = df[df['antecedents'].map(len) > 0] 
    return df.dropna(subset=['final_diagnosis'])

def process_chunk_aggregation(chunk_df, rules_df):
    for idx, row in chunk_df.iterrows():
        # Preprocessing on the fly
        msg = str(row.get('clean_message', row.get('message', '')))
        tokens = clean_text(msg) if 'clean_message' not in row else set(msg.split())
        
        if not tokens: continue

        for _, rule in rules_df.iterrows():
            if rule['antecedents'].issubset(tokens):
                if rule['lift'] < 2.0: continue 
                
                diag = rule['final_diagnosis']
                prio = "CRITICAL" if rule['lift'] > 5.0 else ("HIGH" if rule['confidence'] > 0.8 else "NORMAL")
                
                if prio == "NORMAL": continue
                
                router_id = row.get('source_router', row.get('identity', 'Unknown'))
                timestamp = row.get('time', '-')
                
                if diag not in st.session_state['issues']:
                    st.session_state['issues'][diag] = {
                        'count': 0, 'priority': prio, 'routers': set(),
                        'first_seen': timestamp, 'last_seen': timestamp,
                        'evidence': set(), 'logs': []
                    }
                
                issue = st.session_state['issues'][diag]
                issue['count'] += 1
                issue['routers'].add(router_id)
                issue['last_seen'] = timestamp
                issue['evidence'].update(rule['antecedents'])
                
                if len(issue['logs']) < 50:
                    display_msg = row.get('message', msg)
                    issue['logs'].append({'Timestamp': timestamp, 'Router': router_id, 'Log Message': display_msg})
                
                if prio == 'CRITICAL': issue['priority'] = 'CRITICAL'
                break 
    return True

# ==========================================
# 5. UI DISPLAY
# ==========================================
st.title("Network Root Cause Analysis")
st.caption("Automated Log Analysis & Diagnosis System")

# Layout Input & Button
col_input, col_action = st.columns([3, 1])
with col_input:
    uploaded_file = st.file_uploader("Upload Log File (CSV)", type=['csv'], label_visibility="collapsed")
with col_action:
    st.write("") # Spacer layout
    btn_process = st.button("Start Analysis", type="primary", use_container_width=True)

kb_df = load_knowledge_base()

if uploaded_file and btn_process:
    if kb_df.empty:
        st.error("Rules configuration file not found.")
    else:
        # 1. SIAPKAN WADAH KOSONG (PLACEHOLDER) SEBELUM LOOP
        # Ini kuncinya: wadah ini akan ditimpa isinya setiap kali loop berjalan
        metrics_placeholder = st.empty()
        main_dashboard_placeholder = st.empty()
        
        # Reset State
        reset_state()
        
        # Inisialisasi Progress Bar
        chunk_size = 1000
        total_rows = 0
        chunks = pd.read_csv(uploaded_file, chunksize=chunk_size)
        progress_bar = st.progress(0)
        
        # 2. MULAI LOOP (READING LOG STREAM)
        for i, chunk in enumerate(chunks):
            # Proses Log (Backend Logic)
            process_chunk_aggregation(chunk, kb_df)
            total_rows += len(chunk)
            
            # Hitung Metrics Realtime
            unique_routers = set()
            total_issues = 0
            for v in st.session_state['issues'].values():
                unique_routers.update(v['routers'])
                total_issues += 1
            
            # Hitung Compression Rate (Sesuai Skripsi Bab 3 & 4)
            # Rumus: 1 - (Jumlah Isu / Total Baris Log)
            compression_rate = 0
            if total_rows > 0:
                compression_rate = (1 - (total_issues / total_rows)) * 100
            
            # 3. RENDER ULANG METRICS (MENIMPA TAMPILAN LAMA)
            with metrics_placeholder.container():
                m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                m_col1.metric("Processed Logs", f"{total_rows:,}")
                m_col2.metric("Issues Detected", f"{total_issues}")
                m_col3.metric("Affected Routers", f"{len(unique_routers)}")
                m_col4.metric("Noise Reduction", f"{compression_rate:.1f}%")

            # 4. RENDER ULANG KARTU DASHBOARD (MENIMPA TAMPILAN LAMA)
            with main_dashboard_placeholder.container():
                if not st.session_state['issues']:
                    st.info("Scanning logs pattern...")
                else:
                    # Sort issues: Prioritaskan CRITICAL (Lift Ratio tinggi) di atas
                    sorted_issues = sorted(
                        st.session_state['issues'].items(),
                        key=lambda x: (x[1]['priority'] == 'CRITICAL', x[1]['count']),
                        reverse=True
                    )

                    for diag, data in sorted_issues:
                        info = RECOMMENDATION_MAP.get(diag, {})
                        
                        # Style Selection (Dark Mode Friendly)
                        if data['priority'] == 'CRITICAL':
                            style_cls = "status-critical"
                            badge_bg = "rgba(220, 53, 69, 0.9)" # Merah solid transparan
                        else:
                            style_cls = "status-high"
                            badge_bg = "rgba(255, 193, 7, 0.9)" # Kuning/Orange solid transparan
                        
                        # Data Prep
                        evidence_list = list(data['evidence'])
                        routers_list = list(data['routers'])
                        
                        evidence_html = "".join([f"<span class='evidence-tag'>{e}</span>" for e in evidence_list[:6]])
                        
                        # Render Card HTML (Tanpa Emoticon, Clean Design)
                        st.markdown(f"""
                        <div class="card {style_cls}">
                            <div class="card-header">
                                <span>{info.get('title', diag)}</span>
                                <span style="font-size:0.75em; background:{badge_bg}; color:black; padding:2px 8px; border-radius:4px; font-weight:bold;">{data['priority']}</span>
                            </div>
                            <div class="card-meta">
                                Total Events: <b>{data['count']}</b> | Last Seen: {data['last_seen']}
                            </div>
                            <p style="margin-bottom:10px; opacity:0.9;">{info.get('desc', '-')}</p>
                            <div style="font-size:0.9em; margin-bottom:5px;">
                                <b>Detected Symptoms:</b><br>{evidence_html}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Action Expanders (Interaktif)
                        c1, c2 = st.columns([1, 1])
                        with c1:
                            with st.expander(f"View Affected Routers ({len(routers_list)})"):
                                st.code(", ".join(routers_list), language="text")
                        with c2:
                            with st.expander("Action Recommendations"):
                                for act in info.get('actions', []):
                                    st.markdown(f"- {act}")

            # Update Progress Bar (Tanpa membuat baris baru)
            progress_bar.progress(min((i + 1) * 5, 100) if total_rows < 50000 else 100)
            time.sleep(0.01) # Simulasi delay agar terlihat live
            
        progress_bar.empty() # Hilangkan progress bar saat selesai
        st.toast("Analysis Complete", icon="✅")
        
        # 5. TAMPILKAN TABEL BUKTI (DI LUAR LOOP UTAMA)
        # Tabel ini statis, ditampilkan setelah semua selesai
        st.divider()
        st.subheader("Log Evidence Data")
        if st.session_state['issues']:
            tabs = st.tabs(list(st.session_state['issues'].keys()))
            for i, (k, v) in enumerate(st.session_state['issues'].items()):
                with tabs[i]:
                    st.dataframe(
                        pd.DataFrame(v['logs']), 
                        use_container_width=True, 
                        hide_index=True
                    )
elif not uploaded_file:
    st.info("Please upload a CSV log file to begin analysis.")