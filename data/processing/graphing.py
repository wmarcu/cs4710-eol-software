import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("counts_eol.csv")
df.columns = ["date", "value"]
df = df.sort_values("date")
plt.figure(figsize=(12, 6))
plt.bar(df["date"], df["value"])
plt.title("Values Over Time")
plt.xlabel("Date")
plt.ylabel("Value")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()