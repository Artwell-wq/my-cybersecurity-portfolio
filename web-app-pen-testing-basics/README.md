# Project Title: Web Application Penetration Testing Basics

## 1. Project Overview / Summary

This project focused on foundational web application security testing, building from basic exploitation to understanding and bypassing common defenses, and introducing automation with Python. It involved setting up a controlled lab environment using Kali Linux and Metasploitable2 (hosting DVWA), leveraging Burp Suite for traffic analysis, and developing a simple Python script for web reconnaissance.

### Key Skills Demonstrated:
* Web application reconnaissance and vulnerability identification.
* Configuring and utilizing Burp Suite for traffic interception, modification, and analysis.
* Identifying and exploiting **SQL Injection** vulnerabilities (low security).
* Identifying and exploiting **Cross-Site Scripting (XSS)** vulnerabilities (low security).
* **Understanding and bypassing common web application defenses** for SQL Injection and XSS (medium security).
* **Automating web content discovery** using Python and the `requests` library.
* Environment setup and troubleshooting (VirtualBox Guest Additions, Python package management).
* Adherence to ethical hacking principles within an isolated lab environment.

## 2. Tools Used

* **Virtualization Software:** Oracle VirtualBox
* **Attacker Machine:** Kali Linux VM
* **Target Machine:** Metasploitable2 VM (hosting vulnerable web applications)
* **Core Cybersecurity Tools:**
    * **Kali Linux Web Browser:** (e.g., Firefox/Chromium) for interacting with web applications.
    * **Burp Suite Community Edition:** An integrated platform for performing security testing of web applications. Used for proxying, intercepting, modifying, and analyzing web traffic.
    * **Python 3:** For scripting and automation.
    * **`requests` Python library:** For making HTTP requests in Python.

## 3. Project Steps & Methodology

This section details the methodical approach taken to identify and exploit web application vulnerabilities on the Metasploitable2 target, including defensive bypasses and automation.

### 3.1. Lab Setup & DVWA Configuration

1.  **VM Setup:** Ensured both Kali Linux VM (with internet access via NAT and Host-Only network for target communication) and Metasploitable2 VM (on Host-Only network) were powered on and communicating.
2.  **Access DVWA:** From the Kali Linux VM, navigated to Metasploitable2's web interface (`http://192.168.56.101/`) using Firefox.
3.  **DVWA Login:** Accessed the DVWA (Damn Vulnerable Web Application) link and logged in with default credentials (`admin`/`password`).
4.  **Security Level Configuration:** Navigated to "DVWA Security" and set the security level to **"low"** to facilitate learning and exploitation of basic vulnerabilities.

### 3.2. Introducing and Configuring Burp Suite

1.  **Launch Burp Suite:** Started Burp Suite Community Edition from Kali's "Web Application Analysis" menu, accepting default temporary project settings. Confirmed "Proxy" tab and "Intercept" sub-tab were active with "Intercept is on".
2.  **Browser Proxy Configuration:** Configured Firefox's network proxy settings to manually use Burp Suite as a proxy:
    * HTTP Proxy: `127.0.0.1`
    * Port: `8080`
    * Checked "Also use this proxy for HTTPS".
3.  **Proxy Test:** Refreshed the browser to confirm Burp Suite intercepted requests. Forwarded requests to allow browsing to proceed, verifying proper proxy functionality.

### 3.3. Exploiting SQL Injection (DVWA - Low Security)

1.  **Navigation:** In the proxied browser, navigated to DVWA's **"SQL Injection"** section.
2.  **Basic Valid Test:** Entered `1` into the "User ID" field and submitted to observe normal application behavior (displaying user ID 1).
3.  **SQL Injection Payload Execution:** Entered the SQL Injection payload `1' or '1'='1 -- #` into the "User ID" field and clicked "Submit".
4.  **Observed Outcome:** The web application returned results for *all* users in the database, specifically showing "admin" details, confirming that the injected SQL query was executed successfully, bypassing authentication/logic.
5.  **Burp Repeater Experimentation:** Sent the successful SQL Injection request from Burp's "HTTP history" to the **"Repeater"** tab. Used Repeater to modify the `id` parameter (e.g., changing it back to `id=1`) and re-send requests, observing the changing server responses without browser interaction, demonstrating manual request manipulation.

### 3.4. Exploiting Cross-Site Scripting (XSS - Reflected, DVWA - Low Security)

1.  **Navigation:** In the proxied browser, navigated to DVWA's **"XSS (Reflected)"** section.
2.  **Basic Valid Test:** Entered a simple name (`YourName`) into the "Name" field and submitted to observe normal reflection of the input.
3.  **XSS Payload Execution:** Entered the XSS payload `<script>alert('XSS!')</script>` into the "Name" field and clicked "Submit".
4.  **Observed Outcome:** A JavaScript alert box immediately popped up in the browser with the message "XSS!", confirming that the web application failed to sanitize the input, allowing arbitrary client-side script execution.

### 3.5. Bypassing DVWA Medium Security Defenses (SQLi & XSS)

This section details attempts to bypass the security measures implemented at DVWA's "medium" level.

#### 3.5.1. SQL Injection Bypass (Medium Security)

1.  **Security Level Update:** Set DVWA security to **"medium"**.
2.  **Initial Payload Attempt:** Re-attempted the original SQL Injection payload (`1' or '1'='1 -- #`).
3.  **Observed Defense:** The application returned a SQL error message indicating that single quotes were being escaped (e.g., `\'1\'`), preventing the original injection from working.
4.  **Bypass Attempt:** Used an `ORDER BY` clause to bypass the quote escaping, demonstrating information leakage without relying on quotes in the same way. Payload used: `1 ORDER BY 2 -- #`.
5.  **Successful Bypass:** The application successfully processed the `ORDER BY` clause, returning the `admin` user's details without a syntax error, indicating that a valid SQL query was still formed.

    * *Initial SQLi payload failing on Medium:*
    ![SQLi Medium Fail](screenshots/sqli_medium_fail.png)
    * *Successful SQLi bypass on Medium (using ORDER BY):*
    ![SQLi Medium Bypass](screenshots/sqli_medium_bypass.png)

#### 3.5.2. XSS Bypass (Reflected, Medium Security)

1.  **Security Level Update:** Confirmed DVWA security was at **"medium"**.
2.  **Initial Payload Attempt:** Re-attempted the original XSS payload (`<script>alert('XSS!')</script>`).
3.  **Observed Defense:** The application stripped the `<script>` tags, displaying only `Hello alert('XSS!')` on the page, preventing JavaScript execution. Confirmed this by inspecting the server's HTML response in Burp Suite, which showed the `<script>` tags were removed.

    * *Initial XSS payload failing on Medium:*
    ![XSS Medium Fail](screenshots/xss_medium_fail.png)
    * *Burp Suite response showing script tags stripped:*
    ![XSS Medium Stripped Burp](screenshots/xss_medium_stripped_burp.png)

4.  **Bypass Attempt:** Employed an alternative HTML tag and event handler that could execute JavaScript without using `<script>` tags. Payload used: `<img src=x onerror=alert('XSS!')>`.
5.  **Successful Bypass:** A JavaScript alert box popped up in the browser, confirming successful execution of the XSS payload, demonstrating a bypass of the tag-stripping defense.

    * *Successful XSS bypass on Medium:*
    ![XSS Medium Bypass](screenshots/xss_medium_bypass.png)

### 3.6. Python Mini-Project: Simple Web Content Discoverer

This section outlines the development and execution of a basic Python script for web reconnaissance, automating the search for common files and directories.

#### 3.6.1. Environment Setup (Troubleshooting)

To enable proper copy/paste and integrate the Kali VM with the host, VirtualBox Guest Additions were installed. This involved troubleshooting pasting issues and ultimately installing necessary packages via `apt`.

1.  **Install `pip` (if not already present):**
    ```bash
    sudo apt install python3-pip -y
    ```
2.  **Install VirtualBox Guest Additions components:**
    ```bash
    sudo apt install -y virtualbox-guest-x11 virtualbox-guest-utils
    # (virtualbox-guest-dkms was excluded due to 'no installation candidate' error)
    ```
3.  **Reboot Kali VM:**
    ```bash
    sudo reboot
    ```
4.  Confirmed copy/paste and screen resizing functionality.

#### 3.6.2. Python Script Development and Execution

1.  **Created a project directory:** `mkdir python_projects`
2.  **Navigated into the directory:** `cd python_projects`
3.  **Created a Python script file:** `nano web_discoverer.py`
4.  **Pasted the following code into `web_discoverer.py`:**
    ```python
    # Import the requests library to make HTTP requests
    import requests
    import sys # Import sys for exiting if wordlist is not found

    # --- Configuration ---
    # Set your target URL here. Make sure it ends with a slash if it's a directory.
    # This should be your Metasploitable2 IP
    TARGET_URL = "[http://192.168.56.101/](http://192.168.56.101/)"

    # Let's use a simple in-memory wordlist for this first run.
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
    ```
5.  **Saved and exited `nano`** (`Ctrl + O`, Enter, `Ctrl + X`).
6.  **Installed the `requests` library** (after encountering `ModuleNotFoundError` and `externally-managed-environment` errors):
    ```bash
    pip3 install requests --break-system-packages
    ```
7.  **Executed the script:** `python3 web_discoverer.py`
8.  **Observed Outcome:** The script successfully identified and reported several interesting paths on the Metasploitable2 web server, demonstrating automated content discovery.

    * *Successful execution of Python web_discoverer.py script:*
    ![Python Web Discoverer Output](screenshots/python_web_discoverer_output.png)

## 4. Key Learnings & Takeaways

This project significantly enhanced practical skills in web application penetration testing and introduced automation.

* **HTTP Protocol Mastery:** Reinforced understanding of HTTP requests and responses.
* **Web Proxy Proficiency:** Solidified use of Burp Suite for traffic manipulation and analysis.
* **Defense Bypass Techniques:** Learned common input validation and sanitization methods (escaping, stripping tags) and practical ways to bypass them for SQL Injection and XSS. This demonstrates a deeper understanding of vulnerability exploitation.
* **Python for Automation:** Gained foundational experience in using Python (`requests` library) to automate web-based reconnaissance tasks, a crucial skill for efficiency in security assessments.
* **Troubleshooting:** Successfully navigated and resolved complex environment setup issues (VirtualBox Guest Additions, Python package management errors), highlighting problem-solving abilities.
* **Foundational for Advanced Testing:** Built strong groundwork for more complex web vulnerabilities, custom tooling, and broader network assessments.

## 5. Supporting Evidence

*(Please insert your actual screenshot image files here, using Markdown image syntax, after you have uploaded them to a `screenshots/` folder within this project's directory in your GitHub repository. The captions are provided below.)*

* **Screenshot 1: DVWA Login & Security Setup**
    * *Caption: DVWA login page and confirmation of security level set to 'low'.*
    ![DVWA Login and Low Security](screenshots/dvwa_login_security.png)

* **Screenshot 2: Burp Suite Proxy Configuration**
    * *Caption: Browser proxy settings configured to send traffic through Burp Suite on 127.0.0.1:8080.*
    ![Burp Suite Proxy Config](screenshots/burp_proxy_config.png)

* **Screenshot 3: Burp Suite Intercepting Traffic**
    * *Caption: Burp Suite's Proxy tab showing intercepted HTTP requests, confirming the proxy is active.*
    ![Burp Intercepting Traffic](screenshots/burp_intercept.png)

* **Screenshot 4: Successful SQL Injection Result (Low Security)**
    * *Caption: Browser output showing all users after injecting '1' or '1'='1 -- #' on low security.*
    ![SQL Injection Success Low](screenshots/sqli_success_low.png)

* **Screenshot 5: SQLi Request in Burp Repeater**
    * *Caption: The SQL Injection request captured in Burp Repeater, used for modification and re-sending.*
    ![SQLi in Repeater](screenshots/sqli_repeater.png)

* **Screenshot 6: Successful XSS Alert (Low Security)**
    * *Caption: Browser displaying a JavaScript alert box ('XSS!') after injecting `<script>alert('XSS!')</script>` on low security.*
    ![XSS Alert Pop-up Low](screenshots/xss_alert_low.png)

* **Screenshot 7: Initial SQLi Payload Failing on Medium Security**
    * *Caption: SQL error message showing escaped quotes, indicating defense against original SQLi payload on medium security.*
    ![SQLi Medium Fail](screenshots/sqli_medium_fail.png)

* **Screenshot 8: Successful SQLi Bypass on Medium Security**
    * *Caption: Browser output showing successful SQL Injection bypass on medium security using '1 ORDER BY 2 -- #'.*
    ![SQLi Medium Bypass](screenshots/sqli_medium_bypass.png)

* **Screenshot 9: Initial XSS Payload Failing on Medium Security**
    * *Caption: Browser displaying `Hello alert('XSS!')`, indicating `<script>` tags were stripped on medium security.*
    ![XSS Medium Fail](screenshots/xss_medium_fail.png)

* **Screenshot 10: Burp Suite Response Showing Stripped XSS Tags (Medium Security)**
    * *Caption: Burp Suite's HTTP History response confirming `<script>` tags were removed by the server for XSS on medium security.*
    ![XSS Medium Stripped Burp](screenshots/xss_medium_stripped_burp.png)

* **Screenshot 11: Successful XSS Bypass on Medium Security**
    * *Caption: Browser displaying a JavaScript alert box ('XSS!') after successful XSS bypass on medium security using `<img src=x onerror=alert('XSS!')>`. *
    ![XSS Medium Bypass](screenshots/xss_medium_bypass.png)

* **Screenshot 12: Successful Execution of Python Web Content Discoverer**
    * *Caption: Terminal output showing the Python script identifying interesting paths on the Metasploitable2 web server.*
    ![Python Web Discoverer Output](screenshots/python_web_discoverer_output.png)
