import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import sys

def parse_log_file(file_path):
    parsed_logs = []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for i, line in enumerate(lines):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:  # Ensure the line has all required parts
                    # Check if first line looks like a header
                    if i == 0 and "timestamp" in parts[0].lower():
                        continue  # Skip header row
                    timestamp = parts[0]
                    level = parts[1]
                    message = parts[2]
                    user = parts[3].split(":")[1].strip() if "user:" in parts[3] else None
                    parsed_logs.append({"timestamp": timestamp, "level": level, "message": message, "user": user})
                else:
                    print(f"Warning: Skipping malformed line {i+1}: {line.strip()}")
        if not parsed_logs:
            print("No valid log entries found after parsing.")
            sys.exit(1)
        return parsed_logs
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing file: {e}")
        sys.exit(1)

def analyze_logs(file_path):
    # Parse logs from file
    parsed_logs = parse_log_file(file_path)
    df_logs = pd.DataFrame(parsed_logs)

    # Debug: Print the DataFrame to verify contents
    print("------------------Parsed DataFrame head-----------------")
    print(df_logs.head())

    # Convert timestamp column to datetime
    try:
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
    except Exception as e:
        print(f"Error converting timestamps: {e}")
        print("First few timestamp values:", df_logs['timestamp'].head().tolist())
        sys.exit(1)

    # Count login attempts per minute
    login_counts = df_logs.groupby(pd.Grouper(key='timestamp', freq='1min')).size().fillna(0)
    login_attempts = login_counts.values

    # Prepare data for the model
    X = login_attempts.reshape(-1, 1)

    # Initialize and train the Isolation Forest model
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # Predict anomalies
    labels = model.predict(X)
    anomaly_indices = np.where(labels == -1)[0]
    anomaly_values = login_attempts[anomaly_indices]

    # Plot results
    plt.plot(login_counts.index, login_attempts, label="Login attempts per minute")
    plt.scatter(login_counts.index[anomaly_indices], anomaly_values, color='red', label="Anomalies")
    plt.xlabel("Time")
    plt.ylabel("Login Attempts")
    plt.title("Login Attempt Anomaly Detection")
    plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Print results
    if len(anomaly_indices) > 0:
        print(f"Alert! Detected {len(anomaly_indices)} anomalous events.")
        print("Anomaly indices (minute offsets):", anomaly_indices.tolist())
        print("Anomaly values (login attempts):", anomaly_values.tolist())
        anomaly_times = login_counts.index[anomaly_indices]
        suspicious_users = df_logs[df_logs['timestamp'].isin(anomaly_times)]['user'].value_counts()
        print("Top suspicious users:")
        print(suspicious_users.head())
    else:
        print("No anomalies detected.")

    # Show plot and exit
    plt.show()

def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        file_path = input("Please enter the path to the log file (e.g., log.csv): ").strip()

    analyze_logs(file_path)

if __name__ == "__main__":
    main()