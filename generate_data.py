
import pandas as pd
import numpy as np
import os

# Create dataset directory
os.makedirs("dataset", exist_ok=True)

np.random.seed(42)

records = []

users = ["admin", "employee1", "employee2", "employee3", "analyst"]

# Generate normal activities
for i in range(900):
    records.append({
        "user": np.random.choice(users),
        "login_hour": np.random.randint(8, 19),
        "failed_attempts": np.random.randint(0, 2),
        "files_accessed": np.random.randint(1, 10),
        "privilege_level": np.random.choice([0, 1], p=[0.9, 0.1]),
        "network_connections": np.random.randint(1, 8),
        "activity_type": "Normal"
    })

# Generate suspicious activities
for i in range(100):
    records.append({
        "user": np.random.choice(users),
        "login_hour": np.random.choice([0, 1, 2, 3, 4, 23]),
        "failed_attempts": np.random.randint(4, 12),
        "files_accessed": np.random.randint(20, 60),
        "privilege_level": 2,
        "network_connections": np.random.randint(15, 40),
        "activity_type": "Suspicious"
    })

# Shuffle records
df = pd.DataFrame(records)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save dataset
df.to_csv("dataset/security_logs.csv", index=False)

print("Security dataset generated successfully!")
print("Total records:", len(df))
print("\nDataset preview:")
print(df.head())
print("\nActivity distribution:")
print(df["activity_type"].value_counts())