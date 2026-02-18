import pandas as pd
df = pd.read_csv("Data/rules/Rules_Best_S0.02_C0.3.csv", low_memory=False)
print(len(df))
