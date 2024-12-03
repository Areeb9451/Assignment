Log Analysis Script
Overview
The Log Analysis Script is a Python-based tool designed to parse and analyze web server log files. It extracts valuable insights, including:

The number of requests made by each IP address.
The most frequently accessed endpoint.
Suspicious activities such as potential brute force login attempts.
The results are displayed in the terminal and saved to a structured CSV file for further review.

Features
Requests per IP Address:
Counts the total number of requests from each IP and sorts them in descending order.
Most Frequently Accessed Endpoint:
Identifies the endpoint accessed the most and its access count.
Suspicious Activity Detection:
Detects IPs with failed login attempts exceeding a configurable threshold.
CSV Output:
Saves analysis results to a well-formatted log_analysis_results.csv file.
