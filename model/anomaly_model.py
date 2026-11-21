
import pandas as pd
import numpy as np

# Load security dataset
df = pd.read_csv("dataset/security_logs.csv")

# Initialize anomaly score
df["anomaly_score"] = 0

# Detect unusual login hours
df.loc[
    (df["login_hour"] < 7) | (df["login_hour"] > 20),
    "anomaly_score"
] += 20

# Detect repeated failed login attempts
df.loc[
    df["failed_attempts"] >= 4,
    "anomaly_score"
] += 25

# Detect unusual file access
df.loc[
    df["files_accessed"] >= 15,
    "anomaly_score"
] += 20

# Detect privilege escalation
df.loc[
    df["privilege_level"] == 2,
    "anomaly_score"
] += 20

# Detect unusual network connections
df.loc[
    df["network_connections"] >= 12,
    "anomaly_score"
] += 15

def get_detection_reasons(row):
    reasons = []

    if row["login_hour"] < 7 or row["login_hour"] > 20:
        reasons.append("Unusual login time")

    if row["failed_attempts"] >= 4:
        reasons.append("Multiple failed login attempts")

    if row["files_accessed"] >= 15:
        reasons.append("Excessive file access")

    if row["privilege_level"] == 2:
        reasons.append("Unusual privilege escalation")

    if row["network_connections"] >= 12:
        reasons.append("Unusual network connections")

    return ", ".join(reasons) if reasons else "No suspicious behaviour detected"


df["detection_reasons"] = df.apply(get_detection_reasons, axis=1)
# Classify activities
df["detected_status"] = np.where(
    df["anomaly_score"] >= 40,
    "Suspicious",
    "Normal"
)
df["risk_level"] = np.where(
    df["anomaly_score"] >= 70, "High",
    np.where(df["anomaly_score"] >= 40, "Medium", "Low")
)

# Save analysis results
df.to_csv("dataset/security_analysis.csv", index=False)

# Display results
print("====================================")
print(" BEHAVIOURAL ANOMALY DETECTION ENGINE")
print("====================================")

print("\nTotal records:", len(df))

print("\nDetection Results:")
print(df["detected_status"].value_counts())

print("\nSuspicious Activity Samples:")
print(
    df[df["detected_status"] == "Suspicious"][
        ["user", "login_hour", "failed_attempts",
         "files_accessed", "privilege_level",
         "network_connections", "anomaly_score"]
    ].head(10)
)

print("\nAnalysis saved successfully!")
print("File: dataset/security_analysis.csv")
