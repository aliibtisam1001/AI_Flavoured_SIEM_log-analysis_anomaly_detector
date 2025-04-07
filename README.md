Login Anomaly Detector
Detects unusual login attempt spikes in log files using Isolation Forest and visualizes results.

Features
Parses CSV logs (timestamp, level, message, user).
Identifies anomalies in login attempts per minute.
Plots data with anomalies marked.
Lists top suspicious users.
Requirements
Python 3.6+
Install dependencies: pip install pandas numpy scikit-learn matplotlib
Log Format
CSV with 4 columns: timestamp,level,message,user (e.g., 2025-04-05 12:00:00,INFO,Login attempt,user:johndoe).

Usage
bash

Collapse

Wrap

Copy
python script.py [log_file_path]
Prompts for file path if not provided.
Outputs anomaly details and a plot.
Customization
Adjust contamination=0.05 in IsolationForest for sensitivity.
Change freq='1min' in pd.Grouper for time intervals.
Troubleshooting
Ensure correct file path and log format.
Check timestamps (e.g., YYYY-MM-DD HH:MM:SS).