import re
import pandas as pd

# ==========================================
# 1. FINAL STOPWORDS (USER REQUEST + DATA ANALYSIS)
# ==========================================
STOPWORDS = {
    # --- DARI LIST ANDA (Wajib) ---
    "ether1", "ether2", "ether3", "ether4", "ether5", "ether6", "ether7", 
    "loading", "info", "input", "in", "out", "message", "log", "by", "from", 
    "to", "via", "changed", "set", "connection-state", "new", "time", "date", 
    "identity", "forward", "zone", "firewall", "router", "system", "script", 
    "debug", "topics", "active", "inactive", "assigned", "deassigned", "address", 
    "status", "state", "detected", "using", "packet", "rule", "up", "running", 
    "full", "established", "connected", "reachable", "designated", "backup", 
    "installed", "added", "exchange",

    # --- TAMBAHAN DARI ANALISIS DATA 'Data_Siap_Mining_revisi.csv' ---
    # Kata-kata ini muncul ribuan kali di log NORMAL dan menyebabkan False Positive
    
    # 1. Istilah Routing & OSPF Normal
    "route", "version", "change", "created", "init", "twoway", "2-way", 
    "exstart", "waiting", "negotiation", "lsdb", "bdr", "dr", "instance",
    
    # 2. Aktivitas User & System Normal
    "account", "user", "logged", "rebooted", "shutdown", "console", "ttys0",
    "api", "rest-api", "dhcp", "dhcp-client", "monitor", "event",
    
    # 3. Kata Penghubung & Simbol Noise yang tersisa
    "size", "simple", "got", "other", "monitor", "host", "rto",
    "153", "130", "132", "133", "168", "192", "255" # IP fragments umum
}

# ==========================================
# 2. PREPROCESSING & MATCHING ENGINE
# ==========================================

def clean_text(text):
    """
    Membersihkan log menggunakan Strict Stopwords.
    Hanya menyisakan kata kunci kritikal (misal: 'down', 'fail', 'ddos', 'storm').
    """
    if not isinstance(text, str): 
        return set()
    
    # 1. Lowercase
    text = text.lower()
    
    # 2. Hapus simbol (Hanya sisakan huruf & angka)
    text = re.sub(r'[^a-z0-9\s]', '', text)
    
    # 3. Tokenisasi
    tokens = set(text.split())
    
    # 4. Stopwords Removal (Filter Ketat)
    cleaned_tokens = tokens - STOPWORDS
    
    return cleaned_tokens

def analyze_chunk(chunk_df, rules_df):
    """
    Analisis dengan Logic Filter: Lift > 5.0 (Critical Only)
    """
    results = []
    
    for idx, row in chunk_df.iterrows():
        msg = str(row.get('message', ''))
        
        # Bersihkan log
        log_tokens = clean_text(msg)
        
        best_diag = "NORMAL"
        best_prio = "NORMAL"
        evidence = ""

        # Jika log kosong setelah dibersihkan (artinya isinya cuma info normal), skip.
        # Contoh: "ether1 link up" -> tokens jadi kosong -> SKIP
        if not log_tokens:
            pass 
        else:
            # Matching Engine
            for _, rule in rules_df.iterrows():
                
                # SYARAT 1: STRICT SUBSET
                # Alarm hanya bunyi jika SEMUA kata di rule muncul di log.
                if rule['antecedents'].issubset(log_tokens):
                    
                    # SYARAT 2: FILTER LIFT RATIO (Kekuatan Rule)
                    # Hanya rule yang sangat kuat (Lift > 5) yang dianggap CRITICAL
                    # Data menunjukkan rule umum (misal 'neighbor' saja) Lift-nya rendah (< 4.5)
                    
                    if rule['lift'] > 5.0:
                        best_diag = rule['final_diagnosis']
                        best_prio = "CRITICAL"
                        evidence = ", ".join(rule['antecedents'])
                        break # Prioritas tertinggi ditemukan, stop cari rule lain
                    
                    # Opsional: Jika Confidence tinggi (> 80%) tapi Lift sedang (> 2.0)
                    elif rule['confidence'] > 0.8 and rule['lift'] > 2.0:
                         if best_prio != "CRITICAL":
                            best_diag = rule['final_diagnosis']
                            best_prio = "HIGH"
                            evidence = ", ".join(rule['antecedents'])

        results.append({
            'time': row.get('time', row.get('fetched_at', '-')),
            'identity': row.get('source_router', row.get('identity', '-')),
            'message': msg,
            'Diagnosis': best_diag,
            'Priority': best_prio,
            'Evidence': evidence
        })
        
    return pd.DataFrame(results)