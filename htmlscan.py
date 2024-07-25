import re
import json
from bs4 import BeautifulSoup
from jsbeautifier import beautify

# Rule file (JSON) for updating rules
RULE_FILE = "rules.json"

# Load rules from the file
def load_rules():
    with open(RULE_FILE, 'r') as file:
        rules = json.load(file)
    return rules

# Update rules function
def update_rules(new_rules):
    with open(RULE_FILE, 'w') as file:
        json.dump(new_rules, file, indent=4)
    print("Rules updated successfully.")

# Detect and deobfuscate JavaScript
def detect_and_deobfuscate(script_content):
    obfuscation_patterns = [
        re.compile(r'eval\(.+\)'),
        re.compile(r'unescape\(.+\)'),
        re.compile(r'document\.write\(.+\)'),
        re.compile(r'atob\(.+\)'),
        re.compile(r'btoa\(.+\)'),
        re.compile(r'charCodeAt\(.+\)'),
        re.compile(r'fromCharCode\(.+\)')
    ]
    
    if any(pattern.search(script_content) for pattern in obfuscation_patterns):
        return beautify(script_content)
    return script_content

# Static analysis function
def static_analysis(html_content, rules):
    soup = BeautifulSoup(html_content, 'html.parser')
    findings = {
        "scripts": [],
        "iframes": [],
        "event_handlers": [],
        "obfuscation": [],
        "phishing_forms": [],
        "malvertising": []
    }
    insights = []
    phishing_score = 0

    # Find scripts and analyze
    scripts = soup.find_all('script')
    for script in scripts:
        script_content = script.string
        if script_content:
            # Check for obfuscation and deobfuscate
            deobfuscated_script = detect_and_deobfuscate(script_content)
            if deobfuscated_script != script_content:
                findings['obfuscation'].append({"obfuscated": script_content, "deobfuscated": deobfuscated_script})
                insights.append("The HTML contains obfuscated JavaScript which was deobfuscated for further analysis.")
                script_content = deobfuscated_script
            findings['scripts'].append(script_content)
    
    # Find iframes and analyze
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        findings['iframes'].append(str(iframe))
        iframe_style = iframe.get('style', '')
        if any(style in iframe_style for style in rules.get('suspicious_iframes', [])):
            phishing_score += 2
            insights.append("The HTML contains hidden iframes which may be used for drive-by downloads or malvertising.")
        if any(domain in iframe.get('src', '') for domain in rules.get('malicious_domains', [])):
            phishing_score += 2
    
    # Find elements with event handlers
    for handler in rules.get('suspicious_event_handlers', []):
        events = soup.find_all(attrs={handler: True})
        for event in events:
            findings['event_handlers'].append(str(event))
            phishing_score += 1
            insights.append(f"The HTML contains elements with {handler} event handlers which can be used for malicious activities.")
    
    # Check for phishing keywords
    for keyword in rules.get('phishing_keywords', []):
        if soup.find_all(string=re.compile(keyword, re.IGNORECASE)):
            phishing_score += 1
            insights.append(f"The HTML contains the keyword '{keyword}' which is commonly used in phishing attacks.")
    
    # Check for phishing forms
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        inputs = form.find_all('input')
        for pattern in rules.get('phishing_forms', [{'action_patterns': [], 'input_types': []}])[0]['action_patterns']:
            if re.search(pattern, action, re.IGNORECASE):
                for input_field in inputs:
                    if input_field.get('type') in rules['phishing_forms'][0]['input_types']:
                        findings['phishing_forms'].append(str(form))
                        phishing_score += 2
                        insights.append(f"The form submits data to '{action}' and contains input fields for sensitive information such as '{input_field.get('type')}'.")
                        break

    # Check for malvertising keywords
    for keyword in rules.get('malvertising_keywords', []):
        if soup.find_all(string=re.compile(keyword, re.IGNORECASE)):
            findings['malvertising'].append(keyword)
            phishing_score += 1
            insights.append(f"The HTML contains the malvertising keyword '{keyword}' which is often used in scams and fraudulent schemes.")

    return findings, insights, phishing_score

# Main function
def main(html_file):
    with open(html_file, 'r') as file:
        html_content = file.read()
    
    rules = load_rules()
    findings, insights, phishing_score = static_analysis(html_content, rules)
    
    print("Findings Summary:")
    for key, value in findings.items():
        print(f"{key.capitalize()}: {len(value)} found")

    print("\nInsights:")
    for insight in insights:
        print(f"- {insight}")

    if findings['obfuscation']:
        print("\nObfuscation Details:")
        for obfuscation in findings['obfuscation']:
            print("Original Obfuscated Script:\n", obfuscation['obfuscated'])
            print("Deobfuscated Script:\n", obfuscation['deobfuscated'])

    print(f"\nPhishing Score: {phishing_score}/10")
    if phishing_score > 5:
        print("This HTML file is likely to be malicious or phishing.")
    else:
        print("This HTML file appears to be safe.")

if __name__ == "__main__":
    # Example to update rules
    new_rules = {
        "obfuscation_patterns": ["eval(", "unescape(", "document.write(", "setTimeout("],
        "malicious_domains": ["badexample.com", "maliciousdomain.com"],
        "suspicious_event_handlers": ["onclick", "onmouseover"],
        "suspicious_iframes": ["display:none", "visibility:hidden"],
        "phishing_keywords": ["login", "username", "password", "secure", "verify"],
        "phishing_forms": [
            {
                "action_patterns": ["login", "signin", "authenticate"],
                "input_types": ["text", "password", "email"]
            }
        ],
        "malvertising_keywords": ["free", "prize", "winner", "congratulations", "claim"]
    }
    #update_rules(new_rules)

    # Analyze an HTML file
    html_file_path = "example.html"  # replace with your HTML file path
    main(html_file_path)
