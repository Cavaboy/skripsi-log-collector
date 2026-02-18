
import pandas as pd
import ast

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
    return rules_df

if __name__ == "__main__":
    df = load_rules()
    found = False
    print("Searching for rules with 'down'...")
    for idx, row in df.iterrows():
        ants = row["antecedents"]
        if "down" in ants:
            print(f"Rule found: {ants} -> {row['consequents']}")
            found = True
    
    if not found:
        print("No rule containing 'down' found.")
