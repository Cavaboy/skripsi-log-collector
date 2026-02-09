import streamlit as st
import pandas as pd
import ast
import re
import time
import os
from functools import lru_cache

# KONFIGURASI HALAMAN & CSS
st.set_page_config(
    page_title="Network RCA System (Tiered)", page_icon="shield", layout="wide"
)

# KONFIGURASI THRESHOLD
DDOS_THRESHOLD_COUNT = (
    100  # Jumlah minimum kejadian DDoS untuk dianggap sebagai serangan (bukan noise)
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
    "broadcast",
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
}


# ==== OPTIMIZATION: Cached CSV reading for live mode ====
@st.cache_data(ttl=5)  # Cache for 5 seconds in live mode
def read_live_log(file_path):
    """Cache live log reads to reduce file I/O"""
    return pd.read_csv(file_path)


# ==== OPTIMIZATION: Cached rules loading for better performance ====
@st.cache_data(ttl=300)  # Cache for 5 minutes
def load_and_process_rules():
    """Load and preprocess rules once, cache for performance"""
    rules_path_auto = "Data/rules/Rules_Best_S0.02_C0.3.csv"
    rules_path_cur = "Data/rules/dashboard_data.csv"

    df_auto = pd.read_csv(rules_path_auto, low_memory=False)
    df_cur = pd.read_csv(rules_path_cur, low_memory=False)

    df_cur = df_cur.rename(
        columns={
            "Root Cause (Gejala)": "antecedents",
            "Impact (Akibat)": "consequents",
            "Confidence (%)": "confidence",
            "Lift Ratio": "lift",
        }
    )

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

    df_auto = df_auto.copy()
    df_auto["antecedents"] = df_auto["antecedents"].apply(parse_antecedents)

    df_cur = df_cur.copy()
    df_cur["antecedents"] = df_cur["antecedents"].apply(parse_antecedents)

    rules_df = pd.concat([df_auto, df_cur], ignore_index=True, sort=False)

    # Pre-parse rules
    rules_df["final_diagnosis"] = rules_df["consequents"].apply(map_diagnosis)
    rules_df["antecedents"] = rules_df["antecedents"].apply(
        lambda x: set(x) - STOPWORDS
    )
    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(
        subset=["final_diagnosis"]
    )

    return rules_df


def clean_text(text):
    if not isinstance(text, str):
        return set()
    text = text.lower()
    text = re.sub(r"([^\w\s])", r" \1 ", text)
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    tokens = set(text.split())
    # Hapus stopwords, angka, dan kata pendek
    return {t for t in tokens if t not in STOPWORDS and not t.isdigit() and len(t) > 2}


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
}


def process_chunk_aggregation(chunk_df, rules_df):
    matched_count = 0

    for idx, row in chunk_df.iterrows():
        msg = str(row.get("message", ""))
        tokens = clean_text(msg)

        diag = None
        prio = "NORMAL"
        evidence = set()

        # ASSOCIATION RULES FIRST (prioritize highest confidence)
        best_rule = None
        best_conf = -1.0
        for _, rule in rules_df.iterrows():
            # [FILTER WEAK RULES] Abaikan jika rule cuma 1 kata dan kata itu generic
            if (
                len(rule["antecedents"]) == 1
                and list(rule["antecedents"])[0] in GENERIC_KEYWORDS
            ):
                continue

            # Match if antecedents subset of cleaned tokens
            if rule["antecedents"].issubset(tokens):
                try:
                    conf_val = float(rule.get("confidence", 0) or 0)
                except Exception:
                    conf_val = 0.0

                # Prefer rule with higher confidence, tie-breaker: higher lift
                if (
                    best_rule is None
                    or conf_val > best_conf
                    or (
                        conf_val == best_conf
                        and rule.get("lift", 0) > best_rule.get("lift", 0)
                    )
                ):
                    best_rule = rule
                    best_conf = conf_val

        if best_rule is not None:
            diag = best_rule["final_diagnosis"]
            evidence = best_rule["antecedents"]
            lift_val = best_rule.get("lift", 0)
            prio = (
                "FATAL"
                if lift_val >= 6.0
                else "CRITICAL" if lift_val >= 3.0 else "WARNING"
            )

        # FALLBACK: hardcoded keyword checks only if no rule matched
        if not diag:
            if (
                "internet connection lost" in msg.lower()
                or "8.8.8.8 rto" in msg.lower()
            ):
                diag, prio, evidence = (
                    "UPSTREAM_FAILURE",
                    "FATAL",
                    {"internet", "lost", "ping"},
                )
            elif "looped packet" in msg.lower():
                diag, prio, evidence = "BROADCAST_STORM", "FATAL", {"looped", "packet"}
            elif "link down" in msg.lower() and "ether" in msg.lower():
                diag, prio, evidence = "LINK_FAILURE", "CRITICAL", {"link", "down"}
            elif "ddos_detected" in msg.lower() or "flood" in msg.lower():
                diag, prio, evidence = "DDoS", "CRITICAL", {"ddos", "flood"}

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
            if len(issue["logs"]) < 50:
                issue["logs"].append(
                    {
                        "Timestamp": row.get("time", "-"),
                        "Router": row.get("source_router", "Unknown"),
                        "Message": msg,
                    }
                )

    return matched_count


# STREAMLIT UI (Dashboard)
st.title("Network Root Cause Analysis")

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

if uploaded_file or enable_live_log:
    # Determine the data source
    if enable_live_log:
        # Live log mode: read from live_log.csv
        live_log_path = "live_log.csv"
        if not os.path.exists(live_log_path):
            st.error("live_log.csv not found. Please ensure log collector is running.")
        else:
            # OPTIMIZATION: Better auto-refresh for live monitoring
            import time as time_module

            # Initialize session state for live log tracking
            if "live_log_state" not in st.session_state:
                st.session_state["live_log_state"] = {
                    "last_check": time_module.time(),
                    "last_row_count": 0,
                }

            # Refresh controls
            col_refresh, col_interval = st.columns([1, 3])
            with col_refresh:
                if st.button("🔄 Refresh Now"):
                    st.session_state["live_log_state"][
                        "last_check"
                    ] = 0  # Force refresh
                    st.rerun()
            with col_interval:
                auto_refresh_interval = st.select_slider(
                    "Auto-refresh interval (seconds)",
                    options=[5, 10, 15, 30, 60],
                    value=10,
                    label_visibility="collapsed",
                )
                st.session_state["auto_refresh_interval"] = auto_refresh_interval

            # Auto-refresh logic using st.session_state
            current_time = time_module.time()
            last_check = st.session_state["live_log_state"].get("last_check", 0)

            if current_time - last_check >= auto_refresh_interval:
                st.session_state["live_log_state"]["last_check"] = current_time
                st.rerun()

            st.info(
                f"✓ Live monitoring active - auto-refreshes every {auto_refresh_interval}s"
            )

            data_source = live_log_path
            is_live_mode = True
    else:
        # File upload mode
        data_source = uploaded_file
        is_live_mode = False

    # OPTIMIZATION: Use cached rules loading instead of reloading every time
    rules_df = load_and_process_rules()

    if st.button("Start Analysis"):
        # Placeholder untuk loading indicator
        loading_container = st.container()
        with loading_container:
            with st.spinner("Analyzing logs... Please wait"):
                progress_bar = st.progress(0)
                status_text = st.empty()

                st.session_state["issues"] = {}

                # OPTIMIZATION: Read CSV once instead of twice
                csv_source = data_source if is_live_mode else data_source

                # Read all chunks and count at the same time
                chunks = list(pd.read_csv(csv_source, chunksize=500))
                total_chunks = len(chunks)

                for current_chunk, chunk in enumerate(chunks, 1):
                    progress = min(current_chunk / total_chunks, 1.0)
                    progress_bar.progress(progress)
                    status_text.text(f"Processing chunk {current_chunk}/{total_chunks}")
                    process_chunk_aggregation(chunk, rules_df)

                progress_bar.progress(1.0)
                status_text.text("Analysis complete!")

        # Hapus loading container
        loading_container.empty()

        # Display Metrics
        m1, m2, m3 = st.columns(3)

        # Filter DDoS berdasarkan threshold (rule-based, tidak ditampilkan)
        filtered_issues = {}
        for diag, data in st.session_state["issues"].items():
            if diag == "DDoS" and data["count"] < DDOS_THRESHOLD_COUNT:
                # DDoS dihitung tapi tidak ditampilkan (rule-based filtering)
                continue
            filtered_issues[diag] = data

        m1.metric("Anomalies Found", len(filtered_issues))
        m2.metric(
            "Critical Issues",
            sum(
                1
                for d in filtered_issues.values()
                if d["priority"] in ["FATAL", "CRITICAL"]
            ),
        )

        # Live mode: display last check time and total log count
        if is_live_mode:
            try:
                # OPTIMIZATION: Read CSV only once instead of 3 times
                live_df = pd.read_csv(data_source)
                total_logs = len(live_df)
                last_update = (
                    live_df["fetched_at"].max()
                    if "fetched_at" in live_df.columns
                    else "N/A"
                )
                m3.metric("Total Logs (Live)", total_logs)
                st.caption(f"Last Update: {last_update}")
            except Exception as e:
                m3.metric("Total Logs (Live)", "Error", help=str(e))

        # TABEL EVENT SUMMARY
        st.divider()
        st.subheader("Event Summary Table")

        # Buat data untuk tabel
        event_data = []
        for diag, data in filtered_issues.items():
            event_data.append(
                {
                    "Anomaly Type": diag,
                    "Count": data["count"],
                    "Priority": data["priority"],
                    "Last Seen": data["last_seen"],
                    "Routers": ", ".join(data["routers"]),
                }
            )

        if event_data:
            event_df = pd.DataFrame(event_data)
            st.dataframe(event_df, width="stretch", hide_index=True)
        else:
            st.info("No anomalies detected in the uploaded logs.")

        st.divider()

        # Display Cards (DDoS tidak ditampilkan - rule-based filtering hanya)
        for diag, data in sorted(
            filtered_issues.items(), key=lambda x: x[1]["priority"]
        ):
            if diag == "DDoS":
                continue
            info = RECOMMENDATION_MAP.get(
                diag, {"title": diag, "desc": "", "actions": []}
            )
            style = f"status-{data['priority'].lower()}"

            st.markdown(
                f"""
            <div class="card {style}">
                <div style="display:flex; justify-content:space-between;">
                    <span style="font-weight:bold; font-size:1.1em;">{info['title']}</span>
                    <span class="evidence-tag" style="background:black; color:white;">{data['priority']}</span>
                </div>
                <div style="font-size:0.9em; margin: 10px 0;">{info['desc']}</div>
                <div style="font-size:0.8em;"><b>Events:</b> {data['count']} | <b>Last Seen:</b> {data['last_seen']}</div>
                <div style="font-size:0.8em; margin-top:5px;"><b>Key Symptoms:</b> {" ".join([f"<span class='evidence-tag'>{e}</span>" for e in data['evidence']])}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

            with st.expander("View Details"):
                st.write("**Recommended Actions:**")
                for a in info["actions"]:
                    st.write(f"- {a}")
                st.dataframe(pd.DataFrame(data["logs"]))

        # TABEL DETAIL EVENT LOGS - Grouped by diagnosis type (moved below cards)
        st.divider()
        st.subheader("All Event Logs")

        # Organize logs by diagnosis type
        if filtered_issues:
            for diag in sorted(filtered_issues.keys()):
                data = filtered_issues[diag]
                if data["logs"]:
                    info = RECOMMENDATION_MAP.get(
                        diag, {"title": diag, "desc": "", "actions": []}
                    )
                    st.subheader(f"{info['title']}")
                    logs = [
                        {
                            "Timestamp": log["Timestamp"],
                            "Router": log["Router"],
                            "Message": log["Message"],
                        }
                        for log in data["logs"]
                    ]
                    logs_df = pd.DataFrame(logs)
                    st.dataframe(logs_df, width="stretch", hide_index=True)
        else:
            st.info("No event logs available.")

# Auto-refresh timer for live log mode
if enable_live_log and "issues" in st.session_state:
    # Add auto-refresh button with countdown
    st.divider()
    col_timer, col_interval = st.columns([2, 1])
    with col_timer:
        st.caption("Live monitoring active - refreshing data...")
    with col_interval:
        refresh_interval = st.selectbox(
            "Refresh Interval (seconds)",
            [5, 10, 15, 30],
            index=1,
            label_visibility="collapsed",
        )

    # Implement auto-refresh using time
    import time as time_mod

    if "auto_refresh" not in st.session_state:
        st.session_state["auto_refresh"] = time_mod.time()

    current_time = time_mod.time()
    if current_time - st.session_state["auto_refresh"] > refresh_interval:
        st.session_state["auto_refresh"] = current_time
        st.rerun()
