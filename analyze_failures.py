
import pandas as pd
import ast
import re
from collections import defaultdict
from typing import Dict, List, DefaultDict, Any

# STOPWORDS matching current dashboard.py
STOPWORDS = {
    "message", "info", "via", "from", "to", "route", "system", "topics", "log", "time", "date",
    "ospf-1", "router-id", "area", "area-0", "election", "version", "instance", "created",
    "broadcast", 
    "loopback", "dr", "bdr", "me", "other", "loading", "full", "exchange",
    "done", "established", "init", "twoway", "address", "ip",
}

# GENERIC_KEYWORDS matching current dashboard.py
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
    "mac", "src", "dst",
    "ospf",
    "state",
    "neighbor",
    "change",
    "exstart",
    "logged",
    "user",
}

class RuleEngine:
    def __init__(self, rules_df):
        self.rules: List[Dict[str, Any]] = []
        self.token_map: DefaultDict[str, List[int]] = defaultdict(list)
        
        for idx, rule in rules_df.iterrows():
            antecedents = rule["antecedents"]
            
            # [FILTER WEAK RULES]
            # 1. Abaikan jika rule cuma 1 kata dan kata itu generic ATAU nama interface
            if len(antecedents) == 1:
                token = list(antecedents)[0]
                if token in GENERIC_KEYWORDS or re.match(r"^ether\d+$", token):
                    continue

            # 2. Abaikan jika rule terdiri dari beberapa kata TAPI semuanya generic words
            # Contoh: {'interface', 'change'}, {'neighbor', 'interface'}, {'interface', 'ether2'}
            is_all_generic = True
            for token in antecedents:
                # Token dianggap generic jika ada di GENERIC_KEYWORDS ATAU formatnya etherX
                if token not in GENERIC_KEYWORDS and not re.match(r"^ether\d+$", token):
                    is_all_generic = False
                    break
            
            if is_all_generic:
                continue
                
            rule_obj = {
                "antecedents": antecedents,
                "confidence": float(rule.get("confidence", 0) or 0),
                "lift": float(rule.get("lift", 0) or 0),
                "final_diagnosis": rule["final_diagnosis"],
                "consequents": rule["consequents"],
                "idx": len(self.rules)
            }
            self.rules.append(rule_obj)
            
            for token in antecedents:
                self.token_map[token].append(int(rule_obj["idx"]))

    def match(self, tokens):
        candidate_counts: DefaultDict[int, int] = defaultdict(int)
        relevant_rules_indices = set()
        
        for token in tokens:
            if token in self.token_map:
                for rule_idx in self.token_map[str(token)]:
                    candidate_counts[rule_idx] += 1
                    relevant_rules_indices.add(rule_idx)
        
        best_rule = None
        best_conf = -1.0
        
        for rule_idx in relevant_rules_indices:
            rule = self.rules[rule_idx]
            if candidate_counts[rule_idx] == len(rule["antecedents"]):
                 conf_val = rule["confidence"]
                 if conf_val > best_conf or (conf_val == best_conf and rule["lift"] > (best_rule["lift"] if best_rule else 0)):
                     best_rule = rule
                     best_conf = conf_val
                     
        return best_rule

def clean_text(text):
    if not isinstance(text, str):
        return set()
    text = text.lower()
    text = re.sub(r"([^\w\s])", r" \1 ", text)
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    tokens = set(text.split())
    return {t for t in tokens if t not in STOPWORDS and not t.isdigit() and len(t) > 2}

def map_diagnosis(val):
    s = str(val).upper()
    if "NORMAL" in s: return None
    if "UPSTREAM_FAILURE" in s: return "UPSTREAM_FAILURE"
    if "LINK_FAILURE" in s: return "LINK_FAILURE"
    if "STORM" in s or "LOOPED" in s: return "BROADCAST_STORM"
    if "DDOS" in s: return "DDoS"
    return None

def load_rules():
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

    def parse_antecedents(x):
        if pd.isna(x): return set()
        if isinstance(x, (list, set)): return set(x)
        s = str(x).strip()
        try:
            if s.startswith("["): return set(ast.literal_eval(s))
        except Exception: pass
        parts = [p.strip() for p in s.split(",") if p.strip()]
        return set(parts)

    df_auto = df_auto.copy()
    df_auto["antecedents"] = df_auto["antecedents"].apply(parse_antecedents)

    df_cur = df_cur.copy()
    df_cur["antecedents"] = df_cur["antecedents"].apply(parse_antecedents)

    rules_df = pd.concat([df_auto, df_cur], ignore_index=True, sort=False)

    rules_df["final_diagnosis"] = rules_df["consequents"].apply(map_diagnosis)
    rules_df["antecedents"] = rules_df["antecedents"].apply(lambda x: set(x) - STOPWORDS)
    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(subset=["final_diagnosis"])

    return RuleEngine(rules_df)

if __name__ == "__main__":
    engine = load_rules()
    
    # Manual test
    test_msg = "ether5 link down"
    test_tokens = clean_text(test_msg)
    print(f"Manual Test: '{test_msg}' -> Tokens: {test_tokens}")
    m = engine.match(test_tokens)
    if m:
        print(f"Manual Match: {m['final_diagnosis']} via {m['antecedents']}")
    else:
        print("Manual Test: NO MATCH")

    log_file = "Data/dataset_log_20260130_131104_broadcast_storm.csv"
    try:
        df_logs = pd.read_csv(log_file)
        print(f"CSV Columns: {df_logs.columns.tolist()}")
        
        matches = []
        for idx, row in df_logs.iterrows():
            # Check if Message column exists, if not try 'message' or index
            if "Message" in df_logs.columns:
                msg = str(row["Message"])
            elif "message" in df_logs.columns:
                msg = str(row["message"])
            else:
                 # Fallback to last column if no header
                 msg = str(row.iloc[-1])
            
            tokens = clean_text(msg)
            match = engine.match(tokens)
            
            if match and match["final_diagnosis"] == "LINK_FAILURE":
                 matches.append({
                     "msg": msg,
                     "tokens": tokens,
                     "antecedents": match["antecedents"]
                 })
                 if len(matches) > 10: break # Show top 10 only
        
        print(f"Found {len(matches)} LINK_FAILURE matches:")
        for m in matches:
            print(f"Log: {m['msg']}")
            print(f"Clean Tokens: {m['tokens']}")
            print(f"Matched Rule: {m['antecedents']}")
            print("-" * 20)
            
    except Exception as e:
        print(f"Error reading log file: {e}")
