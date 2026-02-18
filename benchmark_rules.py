import pandas as pd
import ast
import time
import re
from collections import defaultdict
from typing import Dict, List, Set, DefaultDict, Any

# --- Mock Data and Functions ---
STOPWORDS = {
    "message", "info", "via", "from", "to", "route", "system", "topics", "log", "time", "date",
    "ospf-1", "router-id", "area", "area-0", "election", "version", "instance", "created",
    "broadcast", "loopback", "dr", "bdr", "me", "other", "loading", "full", "exchange",
    "done", "established", "init", "twoway", "address", "ip",
}

GENERIC_KEYWORDS = {
    "interface", "link", "ethernet", "port", "0x0800", "udp", "admin", "bridge",
    "proto", "icmp", "type", "code",
}

def clean_text(text):
    if not isinstance(text, str):
        return set()
    text = text.lower()
    text = re.sub(r"([^\w\s])", r" \1 ", text)
    text = re.sub(r"[^a-z0-9\s_]", " ", text)
    tokens = set(text.split())
    return {t for t in tokens if t not in STOPWORDS and not t.isdigit() and len(t) > 2}

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

def load_rules():
    print("Loading rules...")
    t0 = time.time()
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

    df_auto = df_auto.copy()
    df_auto["antecedents"] = df_auto["antecedents"].apply(parse_antecedents)

    df_cur = df_cur.copy()
    df_cur["antecedents"] = df_cur["antecedents"].apply(parse_antecedents)

    rules_df = pd.concat([df_auto, df_cur], ignore_index=True, sort=False)
    
    # Pre-filter logic from dashboard.py
    def map_diagnosis(val):
        s = str(val).upper()
        if "NORMAL" in s: return None
        if "UPSTREAM_FAILURE" in s: return "UPSTREAM_FAILURE"
        if "LINK_FAILURE" in s: return "LINK_FAILURE"
        if "STORM" in s or "LOOPED" in s: return "BROADCAST_STORM"
        if "DDOS" in s: return "DDoS"
        return None

    rules_df["final_diagnosis"] = rules_df["consequents"].apply(map_diagnosis)
    rules_df["antecedents"] = rules_df["antecedents"].apply(lambda x: set(x) - STOPWORDS)
    rules_df = rules_df[rules_df["antecedents"].map(len) > 0].dropna(subset=["final_diagnosis"])
    
    print(f"Loaded {len(rules_df)} rules in {time.time()-t0:.2f}s")
    return rules_df

# --- Benchmark Implementations ---

def matched_iter_rows(chunk_df, rules_df):
    matched_count = 0
    start_time = time.time()
    
    # Simulation of dashboard logic
    for idx, row in chunk_df.iterrows():
        msg = str(row.get("message", ""))
        tokens = clean_text(msg)
        best_rule = None
        best_conf = -1.0

        for _, rule in rules_df.iterrows():
             if len(rule["antecedents"]) == 1 and list(rule["antecedents"])[0] in GENERIC_KEYWORDS:
                 continue
             
             if rule["antecedents"].issubset(tokens):
                 try: conf_val = float(rule.get("confidence", 0) or 0)
                 except: conf_val = 0.0
                 
                 if best_rule is None or conf_val > best_conf or (conf_val == best_conf and rule.get("lift", 0) > best_rule.get("lift", 0)):
                     best_rule = rule
                     best_conf = conf_val
        
        if best_rule is not None:
            matched_count += 1
            
    return time.time() - start_time, matched_count

def matched_to_dict(chunk_df, rules_list):
    matched_count = 0
    start_time = time.time()
    
    for idx, row in chunk_df.iterrows():
        msg = str(row.get("message", ""))
        tokens = clean_text(msg)
        best_rule = None
        best_conf = -1.0

        for rule in rules_list:
             # Manual filter check
             if len(rule["antecedents"]) == 1 and list(rule["antecedents"])[0] in GENERIC_KEYWORDS:
                 continue

             if rule["antecedents"].issubset(tokens):
                 conf_val = float(rule.get("confidence", 0) or 0)
                 if best_rule is None or conf_val > best_conf or (conf_val == best_conf and rule.get("lift", 0) > best_rule.get("lift", 0)):
                     best_rule = rule
                     best_conf = conf_val
        
        if best_rule is not None:
            matched_count += 1
            
    return time.time() - start_time, matched_count

class RuleEngine:
    def __init__(self, rules_df):
        self.rules: List[Dict[str, Any]] = []
        self.token_map: DefaultDict[str, List[int]] = defaultdict(list)
        
        # Pre-process rules into list of dicts and build index
        for idx, rule in rules_df.iterrows():
            antecedents = rule["antecedents"]
            # Filter generic single-word rules ONCE during load
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
                self.token_map[token].append(int(rule_obj["idx"])) # type: ignore
                
    def process(self, chunk_df):
        matched_count = 0
        start_time = time.time()
        
        for idx, row in chunk_df.iterrows():
            msg = str(row.get("message", ""))
            tokens = clean_text(msg)
            
            candidate_counts: DefaultDict[int, int] = defaultdict(int) # type: ignore
            relevant_rules_indices = set()
            
            # 1. Gather candidates
            for token in tokens:
                if token in self.token_map:
                    for rule_idx in self.token_map[str(token)]: # Force cast to str to satisfy Pyre
                        candidate_counts[rule_idx] += 1
                        relevant_rules_indices.add(rule_idx)
            
            # 2. Check candidates
            best_rule = None
            best_conf = -1.0
            
            for rule_idx in relevant_rules_indices:
                rule = self.rules[rule_idx]
                # Optimization: Count match
                if candidate_counts[rule_idx] == len(rule["antecedents"]): # type: ignore
                     # Strict subset check (double verification not strictly needed if count matches distinct tokens, but safe)
                     # Actually count is enough if tokens are unique sets.
                     
                     if rule["confidence"] > best_conf or (rule["confidence"] == best_conf and rule["lift"] > (best_rule["lift"] if best_rule else 0)): # type: ignore
                         best_rule = rule
                         best_conf = rule["confidence"]
                         
            if best_rule:
                matched_count += 1
                
        return time.time() - start_time, matched_count

# --- Main ---
if __name__ == "__main__":
    rules_df = load_rules()
    
    # Create dummy logs
    print("Creating dummy logs...")
    # Mix of random text and text that should match rules
    dummy_logs = []
    for i in range(50):
        dummy_logs.append({"message": "system info route change ether1 down unexpected"})
        dummy_logs.append({"message": "random noise log entry with no meaning"})
    
    chunk_df = pd.DataFrame(dummy_logs)
    print(f"Benchmarking with {len(chunk_df)} logs...")
    
    # 1. Iterrows
    print("\n--- Strategy 1: iterrows (Current) ---")
    t_iter, c_iter = matched_iter_rows(chunk_df, rules_df)
    print(f"Time: {t_iter:.4f}s | Matches: {c_iter}")
    
    # 2. List of Dicts
    print("\n--- Strategy 2: List of Dicts (Simple) ---")
    rules_list = rules_df.to_dict('records')
    t_dict, c_dict = matched_to_dict(chunk_df, rules_list)
    print(f"Time: {t_dict:.4f}s | Matches: {c_dict}")
    
    # 3. Indexed Engine
    print("\n--- Strategy 3: Inverted Index (Complex) ---")
    engine = RuleEngine(rules_df)
    t_idx, c_idx = engine.process(chunk_df)
    print(f"Time: {t_idx:.4f}s | Matches: {c_idx}")
    
    print(f"\nSpeedup (Dict vs Iterrows): {t_iter/t_dict:.2f}x")
    print(f"Speedup (Index vs Iterrows): {t_iter/t_idx:.2f}x")
