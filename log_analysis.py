import csv
from collections import Counter, defaultdict

def parse_log_file(log_file):
    requests_per_ip = defaultdict(int)
    endpoint_counts = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue  # Skip malformed lines

            ip_address = parts[0]
            request = parts[5] + " " + parts[6] if len(parts) > 6 else ''
            status_code = parts[8]

            # Count requests per IP
            requests_per_ip[ip_address] += 1

            # Count endpoint accesses
            if request.startswith('"GET') or request.startswith('"POST'):
                endpoint = parts[6]
                endpoint_counts[endpoint] += 1

            # Detect failed logins (e.g., HTTP 401 status)
            if status_code == '401':
                failed_logins[ip_address] += 1

    return requests_per_ip, endpoint_counts, failed_logins

def save_to_csv(data, file_path):
    if not data:
        return

    # Define the complete set of fieldnames for all sections
    headers = ['Category', 'IP Address', 'Request Count', 'Endpoint', 'Access Count', 'Failed Login Count']

    with open(file_path, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)

def main():
    log_file = 'sample.log'  # Input log file
    output_file = 'log_analysis_results.csv'  
    failed_login_threshold = 10  

    # Parse log file
    requests_per_ip, endpoint_counts, failed_logins = parse_log_file(log_file)

    # Count requests per IP
    requests_per_ip_sorted = sorted(requests_per_ip.items(), key=lambda x: x[1], reverse=True)

    print("IP Address           Request Count")
    for ip, count in requests_per_ip_sorted:
        print(f"{ip:<20} {count}")

    # Identify most frequently accessed endpoint
    most_accessed_endpoint, access_count = endpoint_counts.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {access_count} times)")

    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > failed_login_threshold}
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    csv_data = []

    # Requests per IP section
    csv_data.extend([{'Category': 'Requests per IP', 'IP Address': ip, 'Request Count': count, 
                      'Endpoint': '', 'Access Count': '', 'Failed Login Count': ''} 
                     for ip, count in requests_per_ip_sorted])

    # Most accessed endpoint section
    csv_data.append({'Category': 'Most Accessed Endpoint', 'IP Address': '', 'Request Count': '', 
                     'Endpoint': most_accessed_endpoint, 'Access Count': access_count, 'Failed Login Count': ''})

    # Suspicious activity section
    csv_data.extend([{'Category': 'Suspicious Activity', 'IP Address': ip, 'Request Count': '', 
                      'Endpoint': '', 'Access Count': '', 'Failed Login Count': count} 
                     for ip, count in suspicious_ips.items()])

    # Save results to CSV
    save_to_csv(csv_data, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
