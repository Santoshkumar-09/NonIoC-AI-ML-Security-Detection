from flask import Flask, render_template, jsonify, send_file, request, redirect, url_for
import webbrowser
import threading
import io
import pandas as pd
import os

app = Flask(__name__)

DATA_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dataset",
    "security_analysis.csv"
)
REQUIRED_COLUMNS = {
    "user",
    "login_hour",
    "failed_attempts",
    "files_accessed",
    "privilege_level",
    "network_connections",
    "detection_reasons",
    "detected_status",
    "anomaly_score",
    "risk_level"
}
NUMERIC_COLUMNS = (
    "login_hour",
    "failed_attempts",
    "files_accessed",
    "privilege_level",
    "network_connections",
    "anomaly_score"
)
INCIDENT_STATUSES = {"New", "Investigating", "Resolved"}


class SecurityDataError(Exception):
    def __init__(self, message, status_code=500):
        super().__init__(message)
        self.status_code = status_code


def get_security_data():
    if not os.path.isfile(DATA_FILE):
        raise SecurityDataError(
            "Security dataset not found. Run model\\anomaly_model.py first.",
            404
        )

    try:
        df = pd.read_csv(DATA_FILE)
    except (OSError, UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        raise SecurityDataError(
            "Unable to read the security analysis dataset. Check that the CSV is valid and accessible."
        ) from error

    if df.empty:
        raise SecurityDataError("The security analysis dataset contains no records.")

    missing_columns = REQUIRED_COLUMNS.difference(df.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise SecurityDataError(f"The security analysis dataset is missing required columns: {missing}.")

    for column in NUMERIC_COLUMNS:
        values = pd.to_numeric(df[column], errors="coerce")
        if values.isna().any():
            raise SecurityDataError(f"The security analysis dataset contains invalid values in '{column}'.")
        df[column] = values

    if df["user"].isna().any() or df["user"].astype(str).str.strip().eq("").any():
        raise SecurityDataError("The security analysis dataset contains a record with no username.")
    if df["detection_reasons"].isna().any():
        raise SecurityDataError("The security analysis dataset contains missing detection reasons.")

    for column, allowed_values in (
        ("detected_status", {"Normal", "Suspicious"}),
        ("risk_level", {"Low", "Medium", "High"})
    ):
        df[column] = df[column].astype(str).str.strip()
        if not df[column].isin(allowed_values).all():
            raise SecurityDataError(f"The security analysis dataset contains an invalid '{column}' value.")

    if "record_id" not in df.columns:
        df.insert(0, "record_id", range(1, len(df) + 1))
    else:
        record_ids = pd.to_numeric(df["record_id"], errors="coerce")
        if (
            record_ids.isna().any()
            or (record_ids <= 0).any()
            or (record_ids % 1 != 0).any()
            or record_ids.duplicated().any()
        ):
            raise SecurityDataError("The security analysis dataset contains invalid record IDs.")
        df["record_id"] = record_ids.astype("int64")

    if "incident_status" not in df.columns:
        df["incident_status"] = "New"
    else:
        df["incident_status"] = df["incident_status"].fillna("New").astype(str).str.strip()
        df.loc[df["incident_status"] == "", "incident_status"] = "New"
        if not df["incident_status"].isin(INCIDENT_STATUSES).all():
            raise SecurityDataError("The security analysis dataset contains an invalid incident status.")

    return df


@app.route("/")
def dashboard():
    try:
        df = get_security_data()
    except SecurityDataError as error:
        return str(error), error.status_code

    total = len(df)

    suspicious = int(
        (df["detected_status"] == "Suspicious").sum()
    )

    normal = int(
        (df["detected_status"] == "Normal").sum()
    )

    alerts = df[df["detected_status"] == "Suspicious"].sort_values(by="anomaly_score", ascending=False)
    incident_stats = df[df["detected_status"] == "Suspicious"]["incident_status"].value_counts().to_dict()
    
    normal_records = (
    df[df["detected_status"] == "Normal"]
    .head(10)
    .to_dict(orient="records")
    )
    
    user_stats = (
        df[df["detected_status"] == "Suspicious"]
        .groupby("user")
        .agg(
            suspicious_count=("user", "count"),
            average_score=("anomaly_score", "mean")
        )
        .reset_index()
        .sort_values(by="suspicious_count", ascending=False)
        .to_dict(orient="records")
    )
    
    high_risk = int((df["risk_level"] == "High").sum())
    medium_risk = int((df["risk_level"] == "Medium").sum())
    low_risk = int((df["risk_level"] == "Low").sum())

    records = alerts.to_dict(orient="records")

    return render_template(
    "index.html",
    total=total,
    suspicious=suspicious,
    normal=normal,
    user_stats=user_stats,
    incident_stats=incident_stats,
    records=records,
    normal_records=normal_records,
    high_risk=high_risk,
    medium_risk=medium_risk,
    low_risk=low_risk
)



@app.route("/api/summary")
def summary():
    try:
        df = get_security_data()
    except SecurityDataError as error:
        return jsonify({"error": str(error)}), error.status_code

    return jsonify({
        "total": len(df),
        "suspicious": int((df["detected_status"] == "Suspicious").sum()),
        "normal": int((df["detected_status"] == "Normal").sum()),
        "high_risk": int((df["risk_level"] == "High").sum()),
        "medium_risk": int((df["risk_level"] == "Medium").sum()),
        "low_risk": int((df["risk_level"] == "Low").sum())
    })

@app.route("/update-incident/<int:record_id>", methods=["POST"])
def update_incident(record_id):
    try:
        df = get_security_data()
    except SecurityDataError as error:
        return str(error), error.status_code

    status = request.form.get("incident_status")
    if status not in INCIDENT_STATUSES:
        return "Invalid incident status.", 400
    if record_id not in df["record_id"].values:
        return "Security alert not found.", 404

    df.loc[df["record_id"] == record_id, "incident_status"] = status
    try:
        df.to_csv(DATA_FILE, index=False)
    except OSError:
        app.logger.exception("Unable to save the updated security analysis dataset.")
        return "Unable to save the incident status. Check that the dataset file is writable.", 500

    return redirect(url_for("dashboard"))

@app.route("/download-report")
def download_report():
    try:
        df = get_security_data()
    except SecurityDataError as error:
        return str(error), error.status_code

    report = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
    return send_file(
        report,
        as_attachment=True,
        download_name="security_analysis_report.csv",
        mimetype="text/csv"
    )
    
if __name__ == "__main__":
    threading.Timer(
        1.5,
        lambda: webbrowser.open("http://127.0.0.1:5000")
    ).start()

    app.run(debug=True, use_reloader=False)
