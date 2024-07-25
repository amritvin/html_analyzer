HTML Static Analysis Tool
Overview
This tool performs static analysis on HTML files to identify potential security risks such as phishing, malvertising, obfuscation, and other malicious activities. It uses predefined rules to detect suspicious patterns in the HTML content.

Features
-Detect and deobfuscate JavaScript: Identifies obfuscated JavaScript and deobfuscates it for further analysis. // still working on deobfuscation.
-Phishing detection: Checks for phishing keywords and form actions that are commonly used in phishing attacks.
-Malvertising detection: Looks for keywords that are often used in scams and fraudulent schemes.
-Iframes analysis: Identifies hidden iframes that may be used for drive-by downloads or malvertising.
-Event handlers analysis: Detects elements with suspicious event handlers which can be used for malicious activities.

Usage
Install Dependencies
pip install beautifulsoup4 jsbeautifier

OUTPUT for <example.html>
Findings Summary:
Scripts: 1 found
Iframes: 1 found
Event_handlers: 1 found
Obfuscation: 1 found
Phishing_forms: 1 found
Malvertising: 3 found

Insights:
- The HTML contains obfuscated JavaScript which was deobfuscated for further analysis.
- The HTML contains hidden iframes which may be used for drive-by downloads or malvertising.
- The HTML contains elements with onclick event handlers which can be used for malicious activities.
- The HTML contains the keyword 'username' which is commonly used in phishing attacks.
- The HTML contains the keyword 'password' which is commonly used in phishing attacks.
- The form submits data to 'http://phishingsite.com/login' and contains input fields for sensitive information such as 'text'.
- The HTML contains the malvertising keyword 'free' which is often used in scams and fraudulent schemes.
- The HTML contains the malvertising keyword 'prize' which is often used in scams and fraudulent schemes.
- The HTML contains the malvertising keyword 'claim' which is often used in scams and fraudulent schemes.

Obfuscation Details:
Original Obfuscated Script:

// Obfuscated JavaScript example
eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,34,72,101,108,108,111,32,87,111,114,108,100,34,41));

Deobfuscated Script:
 // Obfuscated JavaScript example
eval(String.fromCharCode(100, 111, 99, 117, 109, 101, 110, 116, 46, 119, 114, 105, 116, 101, 40, 34, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 34, 41));

Phishing Score: 12/10
This HTML file is likely to be malicious or phishing.
