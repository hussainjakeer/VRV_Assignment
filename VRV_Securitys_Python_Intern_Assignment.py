# Importing required libraries
import os
import re
import csv


def count_requests_per_ip(ip_requests):
    """
    Sorts and returns a list.
    
    Args:
        ip_requests (dict): A dictionary where the keys are IP Addresses and the 
        values are count of respective IP Address.
    
    Returns:
        list: A sorted list of tuples (IP Adress, count) in descending order of count.
    """
    sorted_ip_requests = sorted(ip_requests.items(), key = lambda x : x[1], reverse = True)
    return sorted_ip_requests


def most_accessed_endpoint(endpoint_requests):
    """
    Determines the most frequently accessed endpoint(s) and the number of times they were accessed.
    
    Args:
        endpoint_requests (dict): A dictionary where the keys are URLs endpoint and the values are the access count.
    
    Returns:
        tuple: A tuple containing:
            - A list of the most accessed endpoint(s).
            - The maximum count.
    """
    accessed_endpoints = []
    max_access_count = 0
    
    for endpoint, access_count in endpoint_requests.items():
        if access_count > max_access_count:
            accessed_endpoints = [endpoint]
            max_access_count = access_count
        elif access_count == max_access_count:
            accessed_endpoints.append(endpoint)
            
    return accessed_endpoints, max_access_count


def suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD):
    """
    Identifies IP addresses with a number of failed login attempts greater than the given threshold.
    
    Args:
        failed_logins (dict): A dictionary where the keys are IP addresses and the values are the failed login attempt count.
        FAILED_LOGIN_THRESHOLD (int): The threshold for identifying suspicious activity based on failed login attempts.
    
    Returns:
        list: A sorted list of tuples (IP address, failed login count) for suspicious activity.
    """
    suspicious_activities = {ip : count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    suspicious_activities = sorted(suspicious_activities.items(), key = lambda x : x[1], reverse = True)
    return suspicious_activities


def file_preprocess(log_file_path):
    """
    Reads and processes the log file to extract IP addresses, endpoints, and failed login attempts.
    
    Args:
        log_file_path (str): The path to the log file to process.
    
    Returns:
        tuple: A tuple containing:
            - ip_requests (dict): A dictionary of IP addresses and their respective request counts.
            - endpoint_requests (dict): A dictionary of accessed endpoints and their respective counts.
            - failed_logins (dict): A dictionary of IP addresses and their respective failed login attempt counts.
    """
    
    ip_requests = {}
    endpoint_requests = {}
    failed_logins = {}

    try :
        # Regex patterns to match IP address, URLs endpoints and failed logins. 
        ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
        endpoint_pattern = re.compile(r'(?:GET|POST) (\S+)')
        login_failed_pattern = re.compile(r'(HTTP\S+ 401|Invalid credentials)')

        # Opening the log file in read mode and find patterns.
        with open(log_file_path, "r") as file:
            
            for each_line in file:
        
                ip_match = ip_pattern.search(each_line)
                if ip_match:
                    ip_address = ip_match.groups()[0]
                    ip_requests[ip_address] = ip_requests.get(ip_address, 0) + 1
        
                endpoint_match = endpoint_pattern.search(each_line)
                if endpoint_match:
                    end_point = endpoint_match.groups()[0]
                    endpoint_requests[end_point] = endpoint_requests.get(end_point, 0) + 1
                    
                if login_failed_pattern.search(each_line):
                    failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1
        
    except Exception as e:
        print(f" Error in text preprocessing : {e}")
        return None
        
    return ip_requests, endpoint_requests, failed_logins

def display_report_on_terminal(ip_requests, endpoint_requests, failed_logins, FAILED_LOGIN_THRESHOLD):
    """
    Displays a report of the IP requests, most accessed endpoints, and suspicious activities on the terminal.
    
    Args:
        ip_requests (dict): A dictionary of IP addresses and their respective request counts.
        endpoint_requests (dict): A dictionary of accessed endpoints and their respective counts.
        failed_logins (dict): A dictionary of IP addresses and their respective failed login attempt counts.
        FAILED_LOGIN_THRESHOLD (int): The threshold for identifying suspicious activity based on failed login attempts.
    """

    # Displays Requests per IP Address.
    sorted_ip_requests = count_requests_per_ip(ip_requests)
    print("Requests per IP Address:\n")
    print(f"{'IP Address':<20} {'Request Count'}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20}  {count}")

    # Displays Most Frequently Accessed Endpoint.
    accessed_endpoints, max_access_count = most_accessed_endpoint(endpoint_requests)
    print("\n\nMost Frequently Accessed Endpoint:")
    print(f"{', '.join(accessed_endpoints)} (Accessed {max_access_count} times)")

    # Displays Suspicious Activity.
    suspicious_activities = suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)
    print("\n\nSuspicious Activity Detected:\n")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in suspicious_activities:
        print(f"{ip:<20}  {count}")


def save_to_csv(ip_requests, endpoint_requests, failed_logins, FAILED_LOGIN_THRESHOLD, filename):
    """
    Saves the log analysis results (IP requests, most accessed endpoints, and suspicious activities) to a CSV file.
    
    Args:
        ip_requests (dict): A dictionary of IP addresses and their respective request counts.
        endpoint_requests (dict): A dictionary of accessed endpoints and their respective counts.
        failed_logins (dict): A dictionary of IP addresses and their respective failed login attempt counts.
        FAILED_LOGIN_THRESHOLD (int): The threshold for identifying suspicious activity based on failed login attempts.
        filename (str): The name of the CSV file to save the results (default is "log_analysis_results.csv").
    """
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Writes Requests per IP Address section.
        sorted_ip_requests = count_requests_per_ip(ip_requests)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted_ip_requests:
            writer.writerow([ip, count])

        # Writes Most Frequently Accessed Endpoint section.
        accessed_endpoints, max_access_count = most_accessed_endpoint(endpoint_requests)
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([', '.join(accessed_endpoints), max_access_count])

        # Writes Suspicious Activity section.
        suspicious_activities = suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities:
          writer.writerow([ip, count])


def main():

    # Log file path.
    log_file_path = "./sample.log"
    output_file_name = "log_analysis_results.csv"

    # Threshold limit for failed logins.
    FAILED_LOGIN_THRESHOLD = 10

    # Checking weather the log file path is present or not.
    if not os.path.exists(log_file_path):
        print(f"Log file {log_file_path} not found.")
        return None

    if not isinstance(FAILED_LOGIN_THRESHOLD, int) or FAILED_LOGIN_THRESHOLD < 0:
        print("Invalid FAILED_LOGIN_THRESHOLD. It must be a non-negative integer.")
        return None
    try:
        # Getting preprocessed data from log file.
        ip_requests, endpoint_requests, failed_logins = file_preprocess(log_file_path)

        # Displaying the Report in Terminal.
        display_report_on_terminal(ip_requests, endpoint_requests, failed_logins, FAILED_LOGIN_THRESHOLD)

        # saving the results as csv file.
        save_to_csv(ip_requests, endpoint_requests, failed_logins, FAILED_LOGIN_THRESHOLD, filename = output_file_name)
    
    except Exception as e:
        print(f"Error : {e}")
        return None


if __name__ == "__main__":
    main()