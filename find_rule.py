
import pandas as pd

def check_file(path):
    print(f"Checking {path}...")
    try:
        df = pd.read_csv(path, low_memory=False)
        # Check antecedents column for 'ether1'
        # The column name might vary
        col = "antecedents" if "antecedents" in df.columns else "Root Cause (Gejala)"
        con_col = "consequents" if "consequents" in df.columns else "Impact (Akibat)"
        
        matches = df[df[col].astype(str).str.contains("ether1", case=False, na=False)]
        print(f"Found {len(matches)} matches in {col}")
        if len(matches) > 0:
            print(matches[[col, con_col]].to_string())
            
    except Exception as e:
        print(f"Error reading {path}: {e}")

check_file("Data/rules/Rules_Best_S0.02_C0.3.csv")
check_file("Data/rules/dashboard_data.csv")
