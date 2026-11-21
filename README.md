# Non-IoC AI/ML Security Detection

A Flask-based behavioural security dashboard that detects potentially suspicious activity without relying on indicators of compromise (IoCs). The application uses rule-based machine-learning-style feature analysis, visualizes security data, tracks incident status, and exports analysis reports.

## Features

- Generates a synthetic dataset of normal and suspicious user activity.
- Calculates anomaly scores from login time, failed attempts, file access, privilege level, and network connections.
- Classifies records as `Normal` or `Suspicious`.
- Assigns `Low`, `Medium`, or `High` risk levels.
- Displays security totals, risk summaries, suspicious users, and recent activity in a web dashboard.
- Updates incident status as `New`, `Investigating`, or `Resolved`.
- Provides a JSON summary API and downloadable CSV report.
- Opens the dashboard automatically in a local browser.

## Technology Stack

- Python
- Flask
- Pandas
- NumPy
- Chart.js
- HTML and CSS

## Project Structure

```text
NonIoC_AI_ML_Detection/
|-- app.py                  # Flask application and dashboard routes
|-- generate_data.py        # Synthetic security log generator
|-- model/
|   `-- anomaly_model.py    # Behavioural anomaly scoring engine
|-- dataset/
|   |-- security_logs.csv   # Generated raw activity data
|   `-- security_analysis.csv # Scored and classified results
|-- templates/
|   `-- index.html          # Dashboard interface
|-- static/
|   `-- style.css           # Dashboard styling
`-- README.md
```

## Setup

### 1. Clone or download the project

```powershell
cd C:\path\to\NonIoC_AI_ML_Detection
```

### 2. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, allow it for the current process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 3. Install dependencies

```powershell
python -m pip install flask pandas numpy
```

## Usage

Generate the synthetic activity dataset:

```powershell
python generate_data.py
```

Run the anomaly detection engine:

```powershell
python model\anomaly_model.py
```

Start the Flask dashboard:

```powershell
python app.py
```

The application opens `http://127.0.0.1:5000` automatically. You can also open that address manually.

## Anomaly Scoring

The detector adds points when an activity matches any of these behavioural rules:

| Condition | Score |
|---|---:|
| Login outside 07:00-20:00 | 20 |
| 4 or more failed login attempts | 25 |
| 15 or more files accessed | 20 |
| Privilege level equal to 2 | 20 |
| 12 or more network connections | 15 |

A record is classified as:

- **Suspicious** when the anomaly score is at least 40.
- **Normal** when the anomaly score is below 40.

Risk levels are assigned as:

- **High:** 70 or more points
- **Medium:** 40-69 points
- **Low:** below 40 points

## Dashboard

The dashboard includes:

- Total, normal, suspicious, and risk-level counts.
- New, investigating, and resolved incident totals.
- Suspicious activity records sorted by anomaly score.
- User-level suspicious activity summaries.
- Activity distribution charts.
- Incident status controls.
- CSV report download.

## API and Routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Renders the security dashboard. |
| `GET` | `/api/summary` | Returns security totals and risk counts as JSON. |
| `POST` | `/update-incident/<record_id>` | Updates an incident status using `incident_status` form data. |
| `GET` | `/download-report` | Downloads `security_analysis_report.csv`. |

Example summary request:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/summary"
```

## Data

- `dataset/security_logs.csv` contains the generated raw records.
- `dataset/security_analysis.csv` contains anomaly scores, detection reasons, classifications, risk levels, and incident status.
- Incident status is initialized to `New` and is updated by the dashboard.

## Reproducibility

The data generator uses a fixed NumPy random seed (`42`) and shuffles records reproducibly. Analysis and report files are created in the `dataset` directory.

## Limitations

This project is a demonstration of behavioural anomaly detection using a deterministic rules engine. It is not a production intrusion-detection system and should not be used as the sole basis for security decisions. Replace the synthetic dataset and scoring logic with validated telemetry and an appropriate ML or SIEM workflow before production use.
