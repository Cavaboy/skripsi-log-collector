
import pandas as pd
import ast
import re
from collections import defaultdict
from typing import Dict, List, DefaultDict, Any

# UPDATED STOPWORDS from dashboard.py
STOPWORDS = {
    "message", "info", "via", "from", "to", "route", "system", "topics", "log", "time", "date",
    "ospf-1", "router-id", "area", "area-0", "election", "version", "instance", "created",
    # "broadcast",  <-- REMOVED
    "loopback", "dr", "bdr", "me", "other", "loading", "full", "exchange",
    "done", "established", "init", "twoway", "address", "ip",
}

# UPDATED GENERIC_KEYWORDS from dashboard.py
GENERIC_KEYWORDS = {
    "interface", "link", "ethernet", "port", "0x0800", "udp", "admin", "bridge", 
    "proto", "icmp", "type", "code",
    "packet", "detected", "received", "sent", # <-- ADDED
}

class RuleEngine:
    def __init__(self, rules_df):
        self.rules: List[Dict[str, Any]] = []
        self.token_map: DefaultDict[str, List[int]] = defaultdict(list)
        
        for idx, rule in rules_df.iterrows():
            antecedents = rule["antecedents"]
            
            # Skip rules that only have 1 antecedent if it's a generic keyword
            if len(antecedents) == 1 and list(antecedents)[0] in GENERIC_KEYWORDS:
                continue
                
            rule_obj = {
                "antecedents": antecedents,
                "confidence": float(rule.get("confidence", 0) or 0),
                "lift": float(rule.get("lift", 0) or 0),
                "final_diagnosis": rule["final_diagnosis"],
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
    print(f"DEBUG: df_auto length: {len(df_auto)}")
    print(f"DEBUG: df_cur length: {len(df_cur)}")

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

    # [NEW] Filter and Correction Logic
    def filter_and_correct(row):
        ants = row["antecedents"]
        
        # 1. REMOVE rules where ALL antecedents are generic or interface names
        # This catches {'packet', 'udp'}, {'ether1'}, etc.
        is_all_generic = True
        for token in ants:
            if not (token in GENERIC_KEYWORDS or re.match(r"^ether\d+$", token)):
                is_all_generic = False
                break
        
        if is_all_generic:
            return False
        
        # 2. FORCE "looped" -> BROADCAST_STORM
        # Because the CSV has incorrect mappings (looped -> LINK_FAILURE)
        if "looped" in ants:
            row["final_diagnosis"] = "BROADCAST_STORM"
            
        return True

    # Apply the filter/correction
    # We use a mask to filter, and apply the side-effect (correction) within the function
    # Note: apply with axis=1 is slow but fine for 3k rules.
    mask = rules_df.apply(filter_and_correct, axis=1)
    rules_df = rules_df[mask]

    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(subset=["final_diagnosis"])

    return RuleEngine(rules_df)

if __name__ == "__main__":
    engine = load_rules()
    
    test_logs = [
        "interface ether1 looped packet detected",
        "excessive broadcasts on interface ether1",
        "broadcast storm detected",
        "loop detected on port 1",
        "link down on interface ether1",
        "neighbor down",
        "UDP packet loop detected",
		"bridge port received packet with own address as source address",
    ]
    
    print(f"{'LOG MESSAGE':<60} | {'TOKENS':<40} | {'DIAGNOSIS':<20} | {'CONFIDENCE'}")
    print("-" * 140)
    
    for log in test_logs:
        tokens = clean_text(log)
        match = engine.match(tokens)
        diag = match['final_diagnosis'] if match else "NO MATCH"
        conf = match['confidence'] if match else 0
        ants = match['antecedents'] if match else {}
        print(f"{log:<60} | {str(tokens):<40} | {diag:<20} | {conf}")
        if match:
            print(f"   Matched Rule: {match}")
            print(f"   Matched Rule Antecedents: {ants}")
