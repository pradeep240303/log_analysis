# Log Analysis Script

## **Overview**
This Python script analyzes server log files to extract key insights related to web traffic, endpoint usage, and suspicious activity. The script processes logs, provides a summary in the terminal, and saves the results in a structured CSV file. It demonstrates key programming skills such as file handling, string manipulation, and cybersecurity-focused data analysis.

---

## **Features**
1. **Count Requests Per IP Address**:
   - Extracts all IP addresses from the log file.
   - Calculates and displays the number of requests per IP in descending order.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Identifies the URL endpoint with the highest number of accesses.
   - Displays the endpoint name and total access count.

3. **Detect Suspicious Activity**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).
   - Searches for failed attempts using HTTP status code `401` or failure messages like "Invalid credentials".

4. **Save Results to CSV**:
   - Outputs results to a CSV file (`log_analysis_results.csv`).
   - Includes:
     - Requests per IP address.
     - Most accessed endpoint.
     - IPs flagged for suspicious activity.

---

## **Getting Started**

### **Prerequisites**
- Python 3.7 or later installed.
- A log file (`sample.log`) in the same directory as the script.

### **Installation**
1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/log-analysis-script.git
    cd log-analysis-script
    ```
2. Install any required libraries:
    ```bash
    pip install -r requirements.txt
    ```
   > **Note**: The script relies on the `csv` and `re` modules, which are part of Python's standard library.

3. Place your log file in the same directory (e.g., `sample.log`).

### **Running the Script**
Run the script using the following command:
```bash
python log_analysis.py
