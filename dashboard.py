import streamlit as st
import pandas as pd
import ast
import re
import time
import os
from functools import lru_cache
from collections import defaultdict
from typing import Dict, List, DefaultDict, Any

# KONFIGURASI HALAMAN & CSS
st.set_page_config(
    page_title="Network RCA System (Tiered)", page_icon="shield", layout="wide"
)

# KONFIGURASI THRESHOLD
DDOS_THRESHOLD_COUNT = (
    20  # Jumlah minimum kejadian DDoS untuk dianggap sebagai serangan (bukan noise)
)

st.markdown(
    """
<style>
    .card { padding: 15px 20px; border-radius: 6px; margin-bottom: 15px; border: 1px solid rgba(128, 128, 128, 0.2); }
    .status-fatal { background-color: #ffebee; border-left: 5px solid #b71c1c; }
    .status-critical { background-color: #ffcdd2; border-left: 5px solid #e53935; }
    .status-warning { background-color: #fff9c4; border-left: 5px solid #fbc02d; }
    .status-normal { background-color: #e1f5fe; border-left: 5px solid #039be5; }
    .evidence-tag { 
        background-color: rgba(0,0,0,0.05); padding: 2px 8px; border-radius: 4px; 
        font-family: monospace; font-size: 0.85em; margin-right: 5px; display: inline-block; margin-bottom: 4px;
    }
</style>
""",
    unsafe_allow_html=True,
)

# LOGIC & MAPPING
RECOMMENDATION_MAP = {
    "LINK_FAILURE": {
        "title": "Physical Link Failure",
        "desc": "Putusnya koneksi fisik kabel atau port interface terdeteksi.",
        "actions": [
            "Periksa fisik kabel LAN (Ethernet).",
            "Cek status Interface Bit Error Rate.",
            "Pastikan perangkat lawan (peer) menyala.",
        ],
    },
    "UPSTREAM_FAILURE": {
        "title": "Upstream/WAN Connection Failure",
        "desc": "Terputusnya jalur utama menuju Gateway atau ISP.",
        "actions": [
            "Validasi status kabel Uplink/WAN (ether1).",
            "Lakukan Ping ke Gateway Public (e.g., 8.8.8.8).",
            "Koordinasi dengan penyedia ISP.",
        ],
    },
    "DDoS": {
        "title": "DDoS Attack Pattern",
        "desc": "Lonjakan trafik tidak wajar yang mengindikasikan serangan flood.",
        "actions": [
            "Analisis menu Firewall > Connections.",
            "Terapkan Filter Rule untuk drop IP Source mencurigakan.",
        ],
    },
    "BROADCAST_STORM": {
        "title": "L2 Loop / Broadcast Storm",
        "desc": "Indikasi looping pada jaringan Layer-2 (Switching loop).",
        "actions": [
            "Identifikasi kabel yang menghubungkan antar-switch (loop).",
            "Pastikan RSTP/STP aktif pada Bridge.",
        ],
    },
}

# STOPWORDS: keep generic noise but ensure critical network keywords remain
# (removed: 'ospf','neighbor','state','change','down','up','link')
STOPWORDS = {
    "message",
    "info",
    "via",
    "from",
    "to",
    "route",
    "system",
    "topics",
    "log",
    "time",
    "date",
    # network-state keywords removed from stopwords on purpose
    # 'state', 'changed', 'ospf', 'neighbor', 'link', 'down', 'up' are kept for detection
    "ospf-1",
    "router-id",
    "area",
    "area-0",
    "election",
    "version",
    "instance",
    "created",
    "created",
    "broadcast",
    "loopback",
    "loopback",
    "dr",
    "bdr",
    "me",
    "other",
    "loading",
    "full",
    "exchange",
    "done",
    "established",
    "init",
    "twoway",
    "address",
    "ip",
    "admin",
    "user",
    "logged",
}


# ==== OPTIMIZATION: Cached CSV reading for live mode ====
# @st.cache_data(ttl=5)  # Cache removed for instant live updates
def read_live_log(file_path):
    """Cache live log reads to reduce file I/O"""
    return pd.read_csv(file_path)


# ==== OPTIMIZATION: RuleEngine Class for O(1) matching ====
class RuleEngine:
    def __init__(self, rules_df):
        self.rules: List[Dict[str, Any]] = []
        # Mapping token -> list of rule indices
        self.token_map: DefaultDict[str, List[int]] = defaultdict(list)
        
        # Pre-process rules into list of dicts and build index
        for idx, rule in rules_df.iterrows():
            antecedents = rule["antecedents"]
            
            # [FILTER WEAK RULES] Removed completely for AI-Only rules strategy
            # Rely strictly on the FP-Growth support & confidence metrics

                
            rule_obj = {
                "antecedents": antecedents,
                "confidence": float(rule.get("confidence", 0) or 0),
                "lift": float(rule.get("lift", 0) or 0),
                "final_diagnosis": rule["final_diagnosis"],
                "idx": len(self.rules)
            }
            self.rules.append(rule_obj)
            
            for token in antecedents:
                self.token_map[token].append(int(rule_obj["idx"])) # type: ignore

    def match(self, tokens):
        """Find best matching rule for a set of tokens using inverted index"""
        candidate_counts: DefaultDict[int, int] = defaultdict(int) # type: ignore
        relevant_rules_indices = set()
        
        # 1. Gather candidates
        for token in tokens:
            if token in self.token_map:
                for rule_idx in self.token_map[str(token)]: # type: ignore
                    candidate_counts[rule_idx] += 1 # type: ignore
                    relevant_rules_indices.add(rule_idx)
        
        # 2. Check candidates
        best_rule = None
        best_conf = -1.0
        
        for rule_idx in relevant_rules_indices:
            rule = self.rules[rule_idx]
            # Optimization: Only check if ALL antecedents are present
            if candidate_counts[rule_idx] == len(rule["antecedents"]): # type: ignore
                 # Strict subset check passed (assuming unique tokens in antecedents)
                 conf_val = rule["confidence"]
                 
                 # Prefer rule with higher confidence, tie-breaker: higher lift
                 if conf_val > best_conf or (conf_val == best_conf and rule["lift"] > (best_rule["lift"] if best_rule else 0)): # type: ignore
                     best_rule = rule
                     best_conf = conf_val
                     
        return best_rule

# ==== OPTIMIZATION: Cached rules loading for better performance ====
@st.cache_resource(ttl=300)  # Changed to cache_resource for non-data objects
def load_and_process_rules():
    """Load and preprocess rules once, cache for performance"""
    rules_path_auto = "Data/rules/ACTIVE_DASHBOARD_RULES_AUTO.csv"

    df_auto = pd.read_csv(rules_path_auto, low_memory=False)

    # Normalize antecedents parsing
    def parse_antecedents(x):
        if pd.isna(x):
            return set()
        if isinstance(x, (list, set)):
            return set(x)
        s = str(x).strip()
        try:
            if s.startswith("["):
                return set(ast.literal_eval(s))
        except Exception:
            pass
        parts = [p.strip() for p in s.split(",") if p.strip()]
        return set(parts)

    rules_df = df_auto.copy()
    rules_df["antecedents"] = rules_df["antecedents"].apply(parse_antecedents)

    # Pre-parse rules
    rules_df["final_diagnosis"] = rules_df["consequents"].apply(map_diagnosis)
    rules_df["antecedents"] = rules_df["antecedents"].apply(
        lambda x: set(x) - STOPWORDS
    )
    
    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(
        subset=["final_diagnosis"]
    )

    # Initialize Engine
    return RuleEngine(rules_df) # type: ignore


def clean_text(text):
    if not isinstance(text, str):
        return set()
    text = text.lower()
    text = re.sub(r"([^\w\s])", r" \1 ", text)
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    tokens = set(text.split())
    # Hapus stopwords dan kata pendek (Jangan hapus isdigit karena port spt 5678 penting)
    return {t for t in tokens if t not in STOPWORDS and len(t) > 2}


def map_diagnosis(val):
    s = str(val).upper()
    if "NORMAL" in s:
        return None
    if "UPSTREAM_FAILURE" in s:
        return "UPSTREAM_FAILURE"
    if "LINK_FAILURE" in s:
        return "LINK_FAILURE"
    # Perketat: BROADCAST saja tidak cukup, harus ada STORM atau LOOPED
    if "STORM" in s or "LOOPED" in s:
        return "BROADCAST_STORM"
    if "DDOS" in s:
        return "DDoS"
    return None


# CORE PROCESSING - Optimization: Move GENERIC_KEYWORDS outside function
GENERIC_KEYWORDS = {
    "interface",
    "link",
    "ethernet",
    "port",
    "0x0800",
    "udp",
    "admin",
    "bridge",
    "proto",
    "icmp",
    "type",
    "code",
    "mac",
    "src",
    "dst",
    "ospf",
    "state",
    "neighbor",
    "change",
    "exstart",
    "logged",
    "user",
}


def process_chunk_aggregation(chunk_df, rule_engine):
    matched_count = 0

    for idx, row in chunk_df.iterrows():
        msg = str(row.get("message", ""))
        tokens = clean_text(msg)

        diag = None
        prio = "NORMAL"
        evidence = set()
        confidence = None

        # SUPER FAST ENGINE MATCHING
        best_rule = rule_engine.match(tokens)

        if best_rule is not None:
            diag = best_rule["final_diagnosis"]
            evidence = best_rule["antecedents"]
            lift_val = best_rule.get("lift", 0)
            confidence = best_rule.get("confidence", None)
            prio = (
                "FATAL"
                if lift_val >= 6.0
                else "CRITICAL" if lift_val >= 3.0 else "WARNING"
            )

        # FALLBACK & EXPLICIT OVERRIDE
        # Menangani prefix eksplisit dari MikroTik Firewall (Sangat Akurat)
        if "broadcast_storm" in msg.lower():
            diag, prio, evidence, confidence = "BROADCAST_STORM", "FATAL", {"broadcast", "udp_storm"}, 1.0
        elif "ddos_detected" in msg.lower() or "flood" in msg.lower():
            diag, prio, evidence, confidence = "DDoS", "CRITICAL", {"ddos", "flood"}, 1.0
        elif not diag:
            if (
                "internet connection lost" in msg.lower()
                or "8.8.8.8 rto" in msg.lower()
            ):
                diag, prio, evidence, confidence = (
                    "UPSTREAM_FAILURE",
                    "FATAL",
                    {"internet", "lost", "ping"},
                    1.0,
                )
            elif "looped packet" in msg.lower():
                diag, prio, evidence, confidence = "BROADCAST_STORM", "FATAL", {"looped", "packet"}, 1.0
            elif "link down" in msg.lower():
                # We simplified the hardcode rule so any 'link down' message will trigger
                # a LINK_FAILURE warning, regardless of the word 'ether'
                diag, prio, evidence, confidence = "LINK_FAILURE", "CRITICAL", {"link", "down"}, 1.0
            elif (
                "ospf" in msg.lower()
                and "broadcast" in msg.lower()
                and "neighbor" in msg.lower()
                and (
                    "state change to init" in msg.lower()
                    or "neighbor election" in msg.lower()
                )
            ):
                # OSPF neighbor flapping on broadcast segment = gejala kuat Broadcast Storm
                diag, prio, evidence = "BROADCAST_STORM", "FATAL", {"ospf_flapping", "broadcast"}


        # AGGREGATION
        if diag:
            matched_count += 1
            if diag not in st.session_state["issues"]:
                st.session_state["issues"][diag] = {
                    "count": 0,
                    "priority": prio,
                    "routers": set(),
                    "last_seen": row.get("time", "-"),
                    "evidence": set(),
                    "logs": [],
                    "lift": 0,
                }

            issue = st.session_state["issues"][diag]
            issue["count"] += 1
            issue["routers"].add(row.get("source_router", "Unknown"))
            issue["last_seen"] = row.get("time", "-")
            issue["evidence"].update(evidence)
            # Hardcode overrides have confidence=1.0; ML-matched logs have actual confidence
            conf_display = f"{confidence * 100:.1f}%" if confidence is not None else "100.0% (Deterministic)"
            if len(issue["logs"]) < 200:
                issue["logs"].append({
                    "Time": row.get("time", "-"),
                    "Device": row.get("source_router", "Unknown"),
                    "Diagnosis": diag,
                    "Priority": prio,
                    "Symptoms (Antecedents)": ", ".join(sorted(str(e) for e in evidence)),
                    "Confidence": conf_display,
                    "Trigger Message": msg[:120] + "..." if len(msg) > 120 else msg,
                })

    return matched_count


# STREAMLIT UI (Dashboard)
st.title("Network Root Cause Analysis")

# Initialize Session State
if "analysis_active" not in st.session_state:
    st.session_state["analysis_active"] = False
if "issues" not in st.session_state:
    st.session_state["issues"] = {}
if "alerts" not in st.session_state:
    st.session_state["alerts"] = []

# Live Log Checking Toggle
col1, col2 = st.columns([3, 1])
with col1:
    st.subheader("Log Source")
with col2:
    enable_live_log = st.checkbox("Live Log Checking", value=False)

if enable_live_log:
    st.info("Live Log Checking enabled - monitoring live_log.csv for real-time updates")

uploaded_file = (
    st.file_uploader("Upload Log File (CSV)", type=["csv"])
    if not enable_live_log
    else None
)

# Helper for Safe File Operations
def safe_read_csv(path, retries=5):
    """Attempt to read CSV with retries for Windows file locking"""
    for i in range(retries):
        try:
            return pd.read_csv(path, on_bad_lines='skip') # Skip bad lines if partial write
        except (PermissionError, pd.errors.ParserError):
            time.sleep(0.1)
        except pd.errors.EmptyDataError:
             return None
        except Exception:
            return None
    return None # Return None to indicate read failure

if uploaded_file or enable_live_log:
    # Determine the data source
    if enable_live_log:
        live_log_path = "live_log.csv"
        
        # --- CLEAR DATA BUTTON ---
        if st.button("🗑️ Clear Live Data"):
            try:
                # Create empty dataframe with headers
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
                # Write with retry
                success = False
                for _ in range(5):
                    try:
                        dummy_df.to_csv(live_log_path, index=False)
                        success = True
                        break
                    except PermissionError:
                        time.sleep(0.1)
                
                if success:
                    st.session_state["issues"] = {}
                    st.toast("Live data cleared!", icon="🗑️")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Could not clear file - it might be locked by the collector.")
            except Exception as e:
                st.error(f"Error clearing data: {e}")

        if not os.path.exists(live_log_path):
            st.error("live_log.csv not found. Please ensure log collector is running.")
            data_source = None
            is_live_mode = False
        else:
            # Initialize session state for live log tracking
            import time as time_module
            if "live_log_state" not in st.session_state:
                st.session_state["live_log_state"] = {
                    "last_check": time_module.time(),
                }

            # Refresh controls
            col_refresh, col_interval = st.columns([1, 3])
            with col_refresh:
                if st.button("Refresh Now"):
                    st.rerun()
            with col_interval:
                auto_refresh_interval = st.select_slider(
                    "Auto-refresh interval (seconds)",
                    options=[2, 5, 10, 15, 30],
                    value=5,
                    label_visibility="collapsed",
                    key="refresh_interval_slider" # Key for state persistence
                )

            if st.session_state.get("analysis_active", False):
                st.info(f"Live monitoring active - script will re-check every {auto_refresh_interval}s")

            data_source = live_log_path
            is_live_mode = True
    else:
        # File upload mode
        data_source = uploaded_file
        is_live_mode = False

    # OPTIMIZATION: Use cached rules loading instead of reloading every time
    rules_df = load_and_process_rules()

    # --- START/STOP ANALYSIS TOGGLE ---
    col_start, col_status = st.columns([1, 4])
    with col_start:
        if not st.session_state["analysis_active"]:
            if st.button("▶ Start Analysis", type="primary"):
                st.session_state["analysis_active"] = True
                st.rerun()
        else:
             if st.button("⏹ Stop Analysis", type="secondary"):
                st.session_state["analysis_active"] = False
                st.rerun()
    with col_status:
        if st.session_state["analysis_active"]:
            st.success("Analysis Running")
    
    if st.session_state["analysis_active"] and data_source:
        # Create containers for live streaming results
        progress_container = st.container()
        results_container = st.container()

        st.session_state["issues"] = {}
        st.session_state["alerts"] = []

        # OPTIMIZATION: Larger chunks for faster initial results + streaming
        CHUNK_SIZE = 2000
        
        # Read Data
        if is_live_mode:
            try:
                # Use safe read for live file
                full_df = safe_read_csv(data_source)
                
                if full_df is None:
                    # Read failed, try to use last known good state or just skip this run
                    st.warning("⚠️ Live log file is locked. Retrying next refresh...")
                    chunks = []
                    total_chunks = 0
                else:
                    # FORCE VIEW LIMIT: User wants to see more context
                    full_df = full_df.tail(2000).reset_index(drop=True)
                    
                    chunks = [full_df]
                    total_chunks = 1
            except Exception as e:
                st.error(f"Error reading live log: {e}")
                chunks = []
                total_chunks = 0
        else:
             # Standard CSV read for uploaded file
             try:
                chunks = list(pd.read_csv(data_source, chunksize=CHUNK_SIZE))
                total_chunks = len(chunks)
             except Exception:
                 chunks = []
                 total_chunks = 0


        # Process chunks
        with progress_container:
             if total_chunks > 0:
                pass # Silent processing for live mode to avoid flickering progress bars
             else:
                st.warning("No data to process")

        for current_chunk, chunk in enumerate(chunks, 1):
            if chunk.empty:
                continue
                
            # Process this chunk
            count = process_chunk_aggregation(chunk, rules_df)

        # LIVE UPDATE: Show results
        with results_container:
            # Filter issues
            filtered_issues = {}
            for diag, data in st.session_state.get("issues", {}).items():
                if diag == "DDoS" and data["count"] < DDOS_THRESHOLD_COUNT:
                    continue
                filtered_issues[diag] = data

            # METRICS HEADER
            m1, m2, m3 = st.columns(3)
            m1.metric("Jenis Anomali Ditemukan", len(filtered_issues))
            m2.metric(
                "Peringatan Kritis",
                sum(
                    1
                    for d in filtered_issues.values()
                    if d["priority"] in ["FATAL", "CRITICAL"]
                ),
            )

            if is_live_mode:
                current_log_count = len(chunks[0]) if chunks else 0
                last_count = st.session_state["live_log_state"].get("last_count", 0)
                new_logs_count = current_log_count - last_count
                if new_logs_count < 0:
                    new_logs_count = current_log_count
                st.session_state["live_log_state"]["last_count"] = current_log_count
                m3.metric(
                    "Total Log Diterima",
                    current_log_count,
                    delta=f"{new_logs_count} baru" if new_logs_count > 0 else None
                )
            else:
                m3.metric("Log Diproses", "Selesai")

            st.divider()

            # ======================================================
            # SECTION 1: DATA ALIRAN LOG AKTIF (Live Log Stream)
            # ======================================================
            st.subheader("Data Aliran Log Aktif (Live Log Stream)")
            st.caption("Log mentah yang diterima secara real-time dari seluruh perangkat router yang dipantau.")

            if chunks and not chunks[0].empty:
                live_df = chunks[0].copy()
                cols_available = [c for c in ["time", "source_router", "topics", "message"] if c in live_df.columns]
                live_display = live_df[cols_available].copy()
                live_display.columns = [
                    {"time": "Waktu Diterima", "source_router": "Perangkat (Host)",
                     "topics": "Topik Modul", "message": "Pesan Log Mentah"}.get(c, c)
                    for c in cols_available
                ]
                live_display = live_display.iloc[::-1].reset_index(drop=True)
                st.dataframe(
                    live_display,
                    hide_index=True,
                    use_container_width=True,
                    height=300,
                )
            else:
                st.info("Belum ada log yang diterima.")

            st.divider()

            # ======================================================
            # SECTION 2: ANALISIS & REKOMENDASI + TABEL PERINGATAN
            # ======================================================
            st.subheader("Analisis Akar Masalah & Rekomendasi Tindakan")

            if filtered_issues:
                for diag, data in sorted(filtered_issues.items(), key=lambda x: x[1]["priority"]):
                    info = RECOMMENDATION_MAP.get(diag, {"title": diag, "desc": "", "actions": []})
                    style = f"status-{data['priority'].lower()}"

                    st.markdown(
                        f"""
                    <div class="card {style}">
                        <div style="display:flex; justify-content:space-between;">
                            <span style="font-weight:bold; font-size:1.1em;">{info['title']}</span>
                            <span class="evidence-tag" style="background:black; color:white;">{data['priority']}</span>
                        </div>
                        <div style="font-size:0.9em; margin: 10px 0;">{info['desc']}</div>
                        <div style="font-size:0.8em; margin-top:5px;"><b>Key Symptoms:</b> {" ".join([f"<span class='evidence-tag'>{e}</span>" for e in data['evidence']])}</div>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                    with st.expander(f"Lihat Detail & Data Peringatan: {info['title']}"):
                        st.write("**Tindakan yang Direkomendasikan:**")
                        for a in info["actions"]:
                            st.write(f"- {a}")

                        if data["logs"]:
                            st.write(f"**Root Cause Alert Data ({len(data['logs'])} entries):**")
                            logs_df = pd.DataFrame(data["logs"])
                            st.dataframe(
                                logs_df,
                                hide_index=True,
                                use_container_width=True,
                                height=max(200, min(600, len(data["logs"]) * 38 + 40)),
                                column_config={
                                    "Time": st.column_config.TextColumn("Time", width="medium"),
                                    "Device": st.column_config.TextColumn("Device", width="small"),
                                    "Diagnosis": st.column_config.TextColumn("Diagnosis", width="medium"),
                                    "Priority": st.column_config.TextColumn("Priority", width="small"),
                                    "Symptoms (Antecedents)": st.column_config.TextColumn("Symptoms", width="medium"),
                                    "Confidence": st.column_config.TextColumn("Confidence", width="small"),
                                    "Trigger Message": st.column_config.TextColumn("Trigger Message", width="large"),
                                }
                            )
                    st.divider()
            else:
                st.info("Tidak ada anomali yang terdeteksi.")

if 'is_live_mode' in locals() and is_live_mode and st.session_state.get("analysis_active", False): # type: ignore
    import time
    time.sleep(auto_refresh_interval) # type: ignore
    st.rerun()
