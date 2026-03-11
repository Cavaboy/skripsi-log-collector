import pandas as pd
df = pd.read_csv("Data/rules/ACTIVE_DASHBOARD_RULES_AUTO.csv", low_memory=False)
print(len(df))
