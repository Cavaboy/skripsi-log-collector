import pandas as pd
import ast
import time

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
    rules_path_auto = "Data/rules/Rules_Best_S0.02_C0.3.csv"
    rules_path_cur = "Data/rules/dashboard_data.csv"

    df_auto = pd.read_csv(rules_path_auto, low_memory=False)
    df_cur = pd.read_csv(rules_path_cur, low_memory=False)
    
    # Rename columns to match
    df_cur = df_cur.rename(
        columns={
            "Root Cause (Gejala)": "antecedents",
            "Impact (Akibat)": "consequents",
            "Confidence (%)": "confidence",
            "Lift Ratio": "lift",
        }
    )

    df_auto["antecedents"] = df_auto["antecedents"].apply(parse_antecedents)
    df_cur["antecedents"] = df_cur["antecedents"].apply(parse_antecedents)

    rules_df = pd.concat([df_auto, df_cur], ignore_index=True, sort=False)
    print(f"Total rules loaded: {len(rules_df)}")
    return rules_df

if __name__ == "__main__":
    load_rules()
