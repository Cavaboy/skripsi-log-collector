import streamlit as st
import pandas as pd
import ast
import re
import time
import os

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

# STOPWORDS diperketat untuk mengeliminasi noise OSPF
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
    "state",
    "changed",
    "ospf",
    "ospf-1",
    "router-id",
    "area",
    "area-0",
    "neighbor",
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


# CORE PROCESSING
def process_chunk_aggregation(chunk_df, rules_df):
    matched_count = 0
    # Kata kunci yang tidak boleh berdiri sendiri sebagai aturan
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

    for idx, row in chunk_df.iterrows():
        msg = str(row.get("message", ""))
        tokens = clean_text(msg)

        diag = None
        prio = "NORMAL"
        evidence = set()

        # PRIORITAS: DETEKSI POLA KHUSUS
        if "internet connection lost" in msg.lower() or "8.8.8.8 rto" in msg.lower():
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

        # ASSOCIATION RULES (Hanya jika belum terdeteksi pola di atas)
        if not diag:
            best_rule = None
            for _, rule in rules_df.iterrows():
                # [FILTER WEAK RULES] Abaikan jika rule cuma 1 kata dan kata itu generic
                if (
                    len(rule["antecedents"]) == 1
                    and list(rule["antecedents"])[0] in GENERIC_KEYWORDS
                ):
                    continue

                if rule["antecedents"].issubset(tokens):
                    # Cari rule dengan kriteria terpanjang (paling spesifik)
                    if best_rule is None or len(rule["antecedents"]) > len(
                        best_rule["antecedents"]
                    ):
                        best_rule = rule

            if best_rule is not None:
                diag = best_rule["final_diagnosis"]
                evidence = best_rule["antecedents"]
                lift_val = best_rule["lift"]
                prio = (
                    "FATAL"
                    if lift_val >= 6.0
                    else "CRITICAL" if lift_val >= 3.0 else "WARNING"
                )

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
uploaded_file = st.file_uploader("Upload Log File (CSV)", type=["csv"])

if uploaded_file:
    # Load Rules
    rules_df = pd.read_csv("Data/rules/Rules_Best_S0.02_C0.3.csv")
    rules_df = rules_df.rename(
        columns={
            "Root Cause (Gejala)": "antecedents",
            "Impact (Akibat)": "consequents",
            "Lift Ratio": "lift",
        }
    )

    # Pre-parse rules
    rules_df["final_diagnosis"] = rules_df["consequents"].apply(map_diagnosis)
    rules_df["antecedents"] = rules_df["antecedents"].apply(
        lambda x: set(ast.literal_eval(x)) - STOPWORDS
    )
    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(
        subset=["final_diagnosis"]
    )

    if st.button("Start Analysis"):
        # Placeholder untuk loading indicator
        loading_container = st.container()
        with loading_container:
            with st.spinner("Analyzing logs... Please wait"):
                progress_bar = st.progress(0)
                status_text = st.empty()

                st.session_state["issues"] = {}
                chunks = pd.read_csv(uploaded_file, chunksize=1000)

                # Hitung total chunks untuk progress bar
                uploaded_file.seek(0)
                total_chunks = sum(
                    1 for _ in pd.read_csv(uploaded_file, chunksize=1000)
                )
                uploaded_file.seek(0)

                current_chunk = 0
                for chunk in pd.read_csv(uploaded_file, chunksize=1000):
                    current_chunk += 1
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

        # Filter DDoS berdasarkan threshold - hanya include jika count >= DDOS_THRESHOLD_COUNT
        filtered_issues = {}
        filtered_out_ddos = 0
        for diag, data in st.session_state["issues"].items():
            if diag == "DDoS" and data["count"] < DDOS_THRESHOLD_COUNT:
                # Skip DDoS jika jumlah kejadian kurang dari threshold
                filtered_out_ddos = data["count"]
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
        if filtered_out_ddos > 0:
            m3.metric(
                "DDoS Minor Events (Filtered)",
                filtered_out_ddos,
                delta=f"Below {DDOS_THRESHOLD_COUNT} threshold",
            )

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
            st.dataframe(event_df, use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies detected in the uploaded logs.")

        # TABEL DETAIL EVENT LOGS
        st.subheader("All Event Logs")
        all_logs = []
        for diag, data in filtered_issues.items():
            for log in data["logs"]:
                all_logs.append(
                    {
                        "Timestamp": log["Timestamp"],
                        "Router": log["Router"],
                        "Anomaly": diag,
                        "Message": log["Message"],
                    }
                )

        if all_logs:
            logs_df = pd.DataFrame(all_logs)
            st.dataframe(logs_df, use_container_width=True, hide_index=True)
        else:
            st.info("No event logs available.")

        st.divider()

        # Display Cards
        for diag, data in sorted(
            filtered_issues.items(), key=lambda x: x[1]["priority"]
        ):
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
