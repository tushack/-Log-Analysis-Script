import csv
from collections import Counter

# Function to read and parse the log file
def parse_log_file(file_path):
    log_entries = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                components = line.split()
                if len(components) > 8:  # Check for valid log line format
                    ip_address = components[0]
                    endpoint = components[6]
                    status_code = components[8]
                    log_entries.append({"ip": ip_address, "endpoint": endpoint, "status": status_code})
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    return log_entries

# Function to count requests by IP address
def count_requests_by_ip(log_entries):
    ip_request_count = Counter(entry["ip"] for entry in log_entries)
    return sorted(ip_request_count.items(), key=lambda item: item[1], reverse=True)

# Function to determine the most accessed endpoint
def get_most_accessed_endpoint(log_entries):
    endpoint_count = Counter(entry["endpoint"] for entry in log_entries)
    if endpoint_count:
        return endpoint_count.most_common(1)[0]
    return ("N/A", 0)

# Function to identify potential suspicious activity
def find_suspicious_ips(log_entries, threshold=10):
    failed_attempts = Counter(entry["ip"] for entry in log_entries if entry["status"] == "401")
    return [(ip, attempts) for ip, attempts in failed_attempts.items() if attempts > threshold]

# Function to export analysis results to a CSV file
def save_results_to_csv(ip_counts, popular_endpoint, suspicious_ips, output_file):
    try:
        with open(output_file, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)

            # Write IP request counts
            writer.writerow(["IP Address", "Request Count"])
            writer.writerows(ip_counts)
            writer.writerow([])  # Blank row for separation

            # Write the most accessed endpoint
            writer.writerow(["Most Accessed Endpoint", "Access Count"])
            writer.writerow([popular_endpoint[0], popular_endpoint[1]])
            writer.writerow([])

            # Write suspicious IPs
            writer.writerow(["Suspicious IP", "Failed Login Attempts"])
            writer.writerows(suspicious_ips)
    except Exception as e:
        print(f"Error writing to CSV: {e}")

# Main execution function
def main():
    log_file_path = "sample.log"  # Replace with the path to your log file
    output_file_path = "log_analysis_results.csv"

    # Parse the log file
    log_entries = parse_log_file(log_file_path)

    if not log_entries:
        print("No log data found. Exiting.")
        return

    # Analyze the log data
    ip_request_counts = count_requests_by_ip(log_entries)
    most_accessed_endpoint = get_most_accessed_endpoint(log_entries)
    suspicious_ips = find_suspicious_ips(log_entries)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_request_counts:
        print(f"{ip:20} {count}")

    print(f"\nMost Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, attempts in suspicious_ips:
            print(f"{ip:20} {attempts}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_ips, output_file_path)
    print(f"\nResults have been saved to '{output_file_path}'.")

if __name__ == "__main__":
    main()
