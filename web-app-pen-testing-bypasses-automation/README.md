Project Title: Web Application Penetration Testing: Bypasses & Automation
1. Project Overview / Summary
This project focused on advancing web application security testing skills by specifically understanding and bypassing common web application defenses, and introducing automation with Python. It involved setting up a controlled lab environment using Kali Linux and Metasploitable2 (hosting DVWA), leveraging Burp Suite for traffic analysis, and developing a simple Python script for web reconnaissance.

Key Skills Demonstrated:
Understanding and bypassing common web application defenses for SQL Injection (escaping) and Cross-Site Scripting (XSS - tag stripping).

Advanced use of Burp Suite for analyzing server responses to defense mechanisms.

Automating web content discovery using Python and the requests library.

Environment setup and troubleshooting (VirtualBox Guest Additions, Python package management).

Methodical approach to identifying and exploiting vulnerabilities beyond basic levels.

2. Tools Used
Virtualization Software: Oracle VirtualBox

Attacker Machine: Kali Linux VM

Target Machine: Metasploitable2 VM (hosting vulnerable web applications)

Core Cybersecurity Tools:

Kali Linux Web Browser: (e.g., Firefox/Chromium) for interacting with web applications.

Burp Suite Community Edition: An integrated platform for performing security testing of web applications. Used for proxying, intercepting, modifying, and analyzing web traffic.

Python 3: For scripting and automation.

requests Python library: For making HTTP requests in Python.

3. Project Steps & Methodology
This section details the methodical approach taken to bypass web application vulnerabilities on the Metasploitable2 target's "medium" security level and introducing automation.

3.1. Bypassing DVWA Medium Security Defenses (SQLi & XSS)
This section details successful attempts to bypass the security measures implemented at DVWA's "medium" level.

3.1.1. SQL Injection Bypass (Medium Security)
Lab Setup & Configuration: Ensured Kali Linux and Metasploitable2 VMs were running, Burp Suite was configured as a browser proxy, and DVWA's security level was set to "medium".

Initial Payload Attempt: Re-attempted the original SQL Injection payload (1' or '1'='1 -- #).

Observed Defense: The application returned a SQL error message indicating that single quotes were being escaped (e.g., \'1\'), preventing the original injection from working. This defense aims to neutralize the attacker's ability to manipulate SQL queries via string concatenation.

Bypass Attempt: Used an ORDER BY clause to bypass the quote escaping defense. This technique leverages the fact that ORDER BY can sometimes be injected into numeric fields without requiring the problematic single quotes, allowing an attacker to deduce the number of columns in the query. Payload used: 1 ORDER BY 2 -- #.

Successful Bypass: The application successfully processed the ORDER BY clause, returning the admin user's details without a syntax error, indicating that a valid SQL query was still formed and executed, despite the medium-level defenses.

Initial SQLi payload failing on Medium:


Successful SQLi bypass on Medium (using ORDER BY):


3.1.2. XSS Bypass (Reflected, Medium Security)
Lab Setup & Configuration: Confirmed DVWA security was at "medium" and Burp Suite was active.

Initial Payload Attempt: Re-attempted the original XSS payload (<script>alert('XSS!')</script>).

Observed Defense: The application stripped the <script> tags from the input, displaying only Hello alert('XSS!') on the page. This prevents direct execution of embedded JavaScript. Inspection of the server's HTML response in Burp Suite confirmed that the <script> tags were removed by the server-side filtering.

Initial XSS payload failing on Medium:


Burp Suite response showing script tags stripped:


Bypass Attempt: Employed an alternative HTML tag and event handler that could execute JavaScript without relying on the <script> tag. This exploits the fact that the filter was specifically targeting script tags, but not other HTML elements capable of triggering JavaScript. Payload used: <img src=x onerror=alert('XSS!')>.

Successful Bypass: A JavaScript alert box successfully popped up in the browser, confirming that the XSS payload was executed, demonstrating a successful bypass of the tag-stripping defense.

Successful XSS bypass on Medium:


3.2. Python Mini-Project: Simple Web Content Discoverer
This section outlines the development and execution of a basic Python script for web reconnaissance, automating the search for common files and directories on a target web server.

3.2.1. Environment Setup (Troubleshooting)
To enable proper copy/paste and enhance the integration of the Kali VM with the host machine, VirtualBox Guest Additions were successfully installed. This process involved troubleshooting initial pasting issues and resolving Python package management errors.

Install pip (if not already present):

sudo apt install python3-pip -y

Install VirtualBox Guest Additions components (addressing dkms error):

sudo apt install -y virtualbox-guest-x11 virtualbox-guest-utils

Reboot Kali VM:

sudo reboot

Confirmed successful copy/paste functionality and screen resizing after reboot.

3.2.2. Python Script Development and Execution
Created a dedicated project directory: mkdir python_projects

Navigated into the directory: cd python_projects

Created a Python script file: nano web_discoverer.py

Pasted the following Python code into web_discoverer.py using the fixed clipboard functionality:

# Import the requests library to make HTTP requests
import requests
import sys # Import sys for exiting if wordlist is not found

# --- Configuration ---
# Set your target URL here. Make sure it ends with a slash if it's a directory.
# This should be your Metasploitable2 IP
TARGET_URL = "http://192.168.56.101/"

# A simple in-memory wordlist for demonstration. For real-world, use larger files.
COMMON_PATHS = [
    "admin/",
    "robots.txt",
    "index.html",
    "login.php",
    "config/",
    "backup/",
    "test/",
    "upload/",
    ".git/",
    "docs/",
    "db/",
    "server-status",
    "phpinfo.php"
]

# HTTP status codes that indicate an interesting (found/redirect/forbidden) path
INTERESTING_STATUS_CODES = [200, 301, 302, 401, 403]

# --- Functions ---
def discover_content(target_url, paths_list):
    """
    Attempts to discover common web content on a target URL
    by checking a list of predefined paths.
    """
    print(f"[*] Starting content discovery for: {target_url}")
    print(f"[*] Checking {len(paths_list)} common paths...")
    print("-" * 40)

    found_count = 0
    for path in paths_list:
        full_url = f"{target_url}{path}"
        try:
            # Make a GET request to the full URL with a timeout
            response = requests.get(full_url, timeout=5)

            # Check if the status code is interesting
            if response.status_code in INTERESTING_STATUS_CODES:
                print(f"[+] Found: {full_url} (Status: {response.status_code})")
                found_count += 1

        except requests.exceptions.ConnectionError:
            print(f"[-] Connection Error: Could not connect to {full_url}. Is the target up and network configured?")
            break # Exit loop if connection fails, as target might be down
        except requests.exceptions.Timeout:
            print(f"[-] Timeout: Request to {full_url} timed out.")
        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred with {full_url}: {e}")

    print("-" * 40)
    print(f"[*] Content discovery finished. Found {found_count} interesting paths.")

# --- Main execution ---
if __name__ == "__main__":
    discover_content(TARGET_URL, COMMON_PATHS)

Saved and exited nano (Ctrl + O, Enter, Ctrl + X).

Installed the requests library (after resolving ModuleNotFoundError and externally-managed-environment by using --break-system-packages flag):

pip3 install requests --break-system-packages

Executed the script: python3 web_discoverer.py

Observed Outcome: The script successfully identified and reported several interesting paths on the Metasploitable2 web server, including /test/, /server-status, and /phpinfo.php, demonstrating effective automated content discovery.

Successful execution of Python web_discoverer.py script:


4. Key Learnings & Takeaways
This project significantly enhanced practical skills in web application penetration testing and introduced automation, moving beyond basic exploitation.

Advanced Web Vulnerability Understanding: Gained deeper insight into common web application defense mechanisms and developed practical techniques to bypass them for both SQL Injection and XSS on "medium" security levels. This demonstrates a more sophisticated understanding of offensive security.

Python for Automation: Acquired foundational experience in using Python (requests library) to automate web-based reconnaissance tasks. This is a critical skill for improving efficiency and developing custom tools in security assessments.

System & Environment Troubleshooting: Successfully navigated and resolved complex environment setup issues, including VirtualBox Guest Additions installation (addressing clipboard and display problems) and Python package management errors (ModuleNotFoundError, externally-managed-environment). This highlights strong problem-solving and technical debugging capabilities.

Bridging Manual & Automated Testing: Demonstrated the transition from manual vulnerability testing with Burp Suite to automating aspects of reconnaissance, a key step in professional penetration testing.

5. Supporting Evidence
(Please insert your actual screenshot image files here, using Markdown image syntax, after you have uploaded them to a screenshots/ folder within this project's directory in your GitHub repository. The captions are provided below.)

Screenshot 1: Initial SQLi Payload Failing on Medium Security

Caption: SQL error message showing escaped quotes, indicating defense against original SQLi payload on medium security.


Screenshot 2: Successful SQLi Bypass on Medium Security

Caption: Browser output showing successful SQL Injection bypass on medium security using '1 ORDER BY 2 -- #'.


Screenshot 3: Initial XSS Payload Failing on Medium Security

Caption: Browser displaying Hello alert('XSS!'), indicating <script> tags were stripped on medium security.


Screenshot 4: Burp Suite Response Showing Stripped XSS Tags (Medium Security)

Caption: Burp Suite's HTTP History response confirming <script> tags were removed by the server for XSS on medium security.


Screenshot 5: Successful XSS Bypass on Medium Security

*Caption: Browser displaying a JavaScript alert box ('XSS!') after successful XSS bypass on medium security using <img src=x onerror=alert('XSS!')>. *


Screenshot 6: Successful Execution of Python Web Content Discoverer

Caption: Terminal output showing the Python script identifying interesting paths on the Metasploitable2 web server.
