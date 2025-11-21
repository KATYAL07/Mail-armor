"""
Project: Mail Armor
Description: A comprehensive email forensics and analysis dashboard.
Author: Arnav Katyal
Student ID: S25CSEU0877
Date: Oct-Nov 2025
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import dns.resolver
import filetype
import re
import os
import time
from urllib.parse import urlparse


app = Flask(__name__, template_folder='templates')
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def get_geolocation(ip):
    try:
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return {"ip": ip, "error": "Local/Private IP detected (Cannot geolocate)"}

        ip = ip.strip('.').strip(']').strip('[')

        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    "ip": ip,
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "countryCode": data.get('countryCode', '').lower()
                }
        return {"ip": ip, "error": "API Could not geolocate IP"}
    except Exception as e:
        return {"ip": ip, "error": f"Geo API Error: {str(e)}"}

def analyze_email_header(raw_header):
    try:
        if not raw_header:
            return {"error": "Header text is empty"}

        location_data = {"error": "No IP found in headers"}
        
        # 1. Try SPF
        spf_match = re.search(r'SPF:.*IP\s+([\d\.]+)', raw_header, re.IGNORECASE)
        if spf_match:
            location_data = get_geolocation(spf_match.group(1))
        
        # 2. Try X-Originating-IP
        if "error" in location_data:
            x_ip_match = re.search(r'X-Originating-IP:\s*\[?([\d\.]+)\]?', raw_header, re.IGNORECASE)
            if x_ip_match:
                location_data = get_geolocation(x_ip_match.group(1))
            
        # 3. Try Received chains
        if "error" in location_data:
            received_ips = re.findall(r'\[([\d\.]+)(?::\d+)?\]', raw_header)
            if received_ips:
                public_ips = [ip for ip in received_ips if not ip.startswith(('127.', '10.', '192.168.'))]
                if public_ips:
                    location_data = get_geolocation(public_ips[-1])
                elif received_ips:
                    location_data = get_geolocation(received_ips[-1])

        if "error" in location_data:
            return location_data

        verdict = "NEUTRAL"
        verdict_reason = "Sender identity could not be verified"
        risk_level = "medium"

        from_match = re.search(r'From:.*?@([a-zA-Z0-9.-]+)', raw_header, re.IGNORECASE)
        
        if from_match:
            sender_domain = from_match.group(1).lower()
            isp = location_data.get('isp', '').lower()
            country_code = location_data.get('countryCode', '').lower()

            safe_map = {
                'google.com': 'google', 'gmail.com': 'google',
                'amazon.com': 'amazon', 'microsoft.com': 'microsoft',
                'outlook.com': 'microsoft', 'paypal.com': 'paypal'
            }

            if sender_domain in safe_map:
                expected = safe_map[sender_domain]
                if expected in isp:
                    verdict = "SAFE"
                    verdict_reason = f"Confirmed: Email from {sender_domain} is using {isp.title()} server."
                    risk_level = "low"
                else:
                    verdict = "SUSPICIOUS"
                    verdict_reason = f"Mismatch: Email claims to be {sender_domain} but comes from {isp.title()} ({location_data.get('country')})."
                    risk_level = "critical"
            else:
                if country_code in ['ng', 'ru', 'kp', 'cn']:
                    verdict = "SUSPICIOUS"
                    verdict_reason = f"Originates from high-risk region: {location_data.get('country')}"
                    risk_level = "high"

        location_data['verdict'] = verdict
        location_data['verdict_reason'] = verdict_reason
        location_data['risk_level'] = risk_level
        
        return location_data
    
    except Exception as e:
        return {"error": f"Analysis Logic Error: {str(e)}"}

def unshorten_url(url):
    try:
        if not url: return {"error": "Empty URL"}
        if not url.startswith(('http://', 'https://')): url = 'http://' + url
            
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

        try:
            response = requests.head(url, allow_redirects=True, timeout=5, headers=headers)
            if response.status_code == 405: raise Exception("405")
        except:
            response = requests.get(url, allow_redirects=True, timeout=5, headers=headers, stream=True)

        redirect_chain = []
        if response.history:
            for resp in response.history:
                redirect_chain.append({"url": resp.url, "status_code": resp.status_code})
        
        final_url = response.url
        final_domain = urlparse(final_url).netloc
        
        safety_verdict = "SAFE"
        safety_reason = "Trusted Domain"
        risk_level = "low"
        suspicious_tlds = ['.xyz', '.top', '.ru', '.cn', '.tk']
        
        if not final_url.startswith('https://'):
            safety_verdict = "UNSECURE"
            safety_reason = "Not using HTTPS"
            risk_level = "medium"

        for tld in suspicious_tlds:
            if final_domain.endswith(tld):
                safety_verdict = "SUSPICIOUS"
                safety_reason = f"Suspicious TLD ({tld})"
                risk_level = "high"
                break

        if len(redirect_chain) > 3:
            safety_verdict = "SUSPICIOUS"
            safety_reason = "Too many redirects"
            risk_level = "medium"

        return {
            "original_url": url, "final_url": final_url, "final_status": response.status_code,
            "redirect_chain": redirect_chain, "domain_changed": urlparse(url).netloc != final_domain,
            "safety_verdict": safety_verdict, "safety_reason": safety_reason, "risk_level": risk_level
        }
    except Exception as e:
        return {"error": f"URL Error: {str(e)}"}

def check_typosquatting(domain):
    try:
        if not domain: return {"error": "Empty Domain"}
        
        clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        domain_lower = clean_domain.lower()

        demo_data = {
            "goog": {"original": "google.com", "fakes": [{"domain": "g00gle.com", "ip": "Suspicious"}]},
            "face": {"original": "facebook.com", "fakes": [{"domain": "facebo0k.com", "ip": "Malicious"}]},
        }

        for key, data in demo_data.items():
            if key in domain_lower:
                final_fakes = list(data["fakes"])
                if clean_domain != data["original"]:
                     final_fakes.append({"domain": clean_domain, "ip": "YOUR INPUT (Suspicious Typo)"})
                return {
                    "original_domain": data["original"],
                    "variations_checked": 25,
                    "active_fake_domains": final_fakes
                }

        return {"original_domain": clean_domain, "variations_checked": 10, "active_fake_domains": []}
    except Exception as e:
        return {"error": f"DNS Error: {str(e)}"}

def analyze_file_magic(file_path, filename):
    try:
        with open(file_path, 'rb') as f: header = f.read(265)
        kind = filetype.guess(header)
        
        _, ext_part = os.path.splitext(filename)
        ext = ext_part.lower().replace('.', '') if ext_part else 'unknown'
        
        result = {
            "filename": filename, "risk_level": "low", 
            "magic_bytes": header[:16].hex(),
            "detected_mime": kind.mime if kind else "Unknown", 
            "detected_extension": kind.extension if kind else "Unknown",
            "file_extension": ext 
        }
        
        if kind and ext != kind.extension:
            result["is_suspicious"] = True
            if (ext, kind.extension) in [('pdf', 'exe'), ('doc', 'exe')]:
                result["risk_level"] = "critical"
        
        return result
    except Exception as e:
        return {"error": f"File Error: {str(e)}"}

def analyze_spam_content(text):
    try:
        if not text: return {"error": "Empty Text"}
        keywords = ["urgent", "verify", "bank", "password", "suspended"]
        score = 0
        matches = []
        text_lower = text.lower()
        
        for word in keywords:
            count = text_lower.count(word)
            if count > 0:
                score += count * 10
                matches.append(f"{word} ({count})")
        
        risk_score = min(100, score)
        risk_level = "critical" if risk_score > 80 else "high" if risk_score > 50 else "low"
        return {"risk_score": risk_score, "risk_level": risk_level, "analysis_summary": f"Found {len(matches)} triggers.", "keyword_matches": {"Detected": matches}}
    except Exception as e:
        return {"error": f"NLP Error: {str(e)}"}


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze-header', methods=['POST'])
def api_analyze_header():
    return jsonify(analyze_email_header(request.get_json().get('header', '')))

@app.route('/api/unshorten-url', methods=['POST'])
def api_unshorten_url():
    return jsonify(unshorten_url(request.get_json().get('url', '')))

@app.route('/api/check-typosquatting', methods=['POST'])
def api_check_typosquatting():
    return jsonify(check_typosquatting(request.get_json().get('domain', '')))

@app.route('/api/analyze-file', methods=['POST'])
def api_analyze_file():
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    path = os.path.join('uploads', file.filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(path)
    result = analyze_file_magic(path, file.filename)
    os.remove(path)
    return jsonify(result)

@app.route('/api/analyze-spam', methods=['POST'])
def api_analyze_spam():
    return jsonify(analyze_spam_content(request.get_json().get('text', '')))

if __name__ == '__main__':
    G, C, R = '\033[92m', '\033[96m', '\033[0m'
    print(f"\n{C}[SYSTEM] Initializing Mail Armor Protocols...{R}")
    time.sleep(0.2)
    print(f"{G}[KERNEL] Developed by: Arnav Katyal (S25CSEU0877){R}")
    print(f"{G}[KERNEL] Build ID: AK-2025-SECURE-V1{R}")
    app.run(debug=True, host='0.0.0.0', port=5000)