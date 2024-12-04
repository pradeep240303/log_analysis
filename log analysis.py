import re
import csv
from collections import defaultdict


LOG_FILE = "sample.log"  


def parse_log_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error: Unable to read file '{file_path}': {e}")
        return []


def count_requests_per_ip(log_lines):
    ip_counts = defaultdict(int)
    ip_pattern = re.compile(r'^([\d\.]+) ')
    for line in log_lines:
        match = ip_pattern.match(line)
        if match:
            ip_counts[match.group(1)] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)


def find_most_accessed_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    endpoint_pattern = re.compile(r'"[A-Z]+ (\/[^\s]*) HTTP')
    for line in log_lines:
        match = endpoint_pattern.search(line)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))
    return most_accessed


def detect_suspicious_activity(log_lines, threshold=10):
    failed_logins = defaultdict(int)
    failure_pattern = re.compile(r'^([\d\.]+).*"POST /login HTTP.*" 401')
    for line in log_lines:
        match = failure_pattern.match(line)
        if match:
            failed_logins[match.group(1)] += 1
    return {ip: count for ip, count in failed_logins.items() if count > threshold}


def save_to_csv(ip_counts, most_accessed, suspicious_activity, output_file="log_analysis_results.csv"):
    with open(output_file, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)
        writer.writerow([])
        
        
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        writer.writerow([])
        
        
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    
    log_lines = parse_log_file(LOG_FILE)

    if not log_lines:
        print("No log data found. Exiting.")
        return

    
    ip_counts = count_requests_per_ip(log_lines)
    print("IP Address           Request Count")
    for ip, count in ip_counts:
        print(f"{ip:20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = find_most_accessed_endpoint(log_lines)
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    suspicious_activity = detect_suspicious_activity(log_lines)
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

    
    save_to_csv(ip_counts, most_accessed, suspicious_activity)
    print(f"\nResults saved to 'log_analysis_results.csv'")

if __name__ == "__main__":
    main()
