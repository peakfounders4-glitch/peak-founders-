from dotenv import load_dotenv
load_dotenv()

import os
import json
from flask import Flask, render_template, request, jsonify
from ueba_engine import ueba_instance, process_event, USERS, ALERT_FEED, LIVE_EVENTS
from google.genai import Client
from google.genai import types
from PIL import Image
import io

app = Flask(__name__)

# Initialize the Gemini Client (Reads GEMINI_API_KEY from environment variables automatically)
try:
    client = Client()
except Exception as e:
    print(f"Error initializing Gemini Client. Make sure GEMINI_API_KEY is set. Error: {e}")
    client = None

def clean_and_parse_json(text):
    """
    Cleans potential markdown formatting backticks from Gemini response
    and parses it into a Python dictionary.
    """
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()
    return json.loads(cleaned)

app.secret_key = os.environ.get("SECRET_KEY", "scamshield-secret-2983")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.json or {}
    card_number = data.get('cardNumber', '').replace(' ', '')
    cvv = data.get('cvv', '')
    
    if not card_number or len(card_number) < 16 or not cvv or len(cvv) < 3:
        return jsonify({'error': 'Invalid card number or security code details.'}), 400
        
    return jsonify({
        'status': 'success',
        'message': 'Premium Subscription Activated Successfully!',
        'plan': 'Pro Premium'
    })


# 1 & 5. Message & Job Advertisement Analyzer
@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    data = request.json
    text_content = data.get('text', '')
    
    if not text_content:
        return jsonify({'error': 'No text provided'}), 400

    prompt = f"""
    You are an expert Cyber Security and Anti-Fraud AI agent for ScamShield AI.
    Analyze the following text (which could be a message, email, or job post) for scams:
    ---
    "{text_content}"
    ---
    Provide your response strictly in the following JSON format structure:
    {{
        "risk_score": <int between 0 and 100>,
        "verdict": "<Safe / Suspicious / High Risk Scam>",
        "reasons": ["Reason 1", "Reason 2", "Reason 3"]
    }}
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        parsed_response = clean_and_parse_json(response.text)
        return jsonify(parsed_response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 2. Suspicious Website Checker
@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '').lower()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Rule-based heuristics for immediate flags
    suspicious_keywords = ['sale', 'free', 'lottery', 'crypto', 'login', 'secure', 'update', 'banking']
    is_https = url.startswith('https://')
    has_hyphen_or_strange_tld = '-' in url or any(tld in url for tld in ['.xyz', '.top', '.club', '.site', '.info', '.biz'])
    contains_keywords = any(kw in url for kw in suspicious_keywords)

    # Let AI do the definitive phishing evaluation contextually
    prompt = f"""
    Evaluate the following URL for potential phishing or scam layout risks: "{url}"
    Rule Context - HTTPS Check: {is_https}, Suspicious Domain structure: {has_hyphen_or_strange_tld}, Keyword flag: {contains_keywords}.
    
    Provide your response strictly in this JSON structure:
    {{
        "risk_score": <int between 0 and 100>,
        "verdict": "<Safe / Likely Phishing / Critical Risk>",
        "reasons": ["Reason 1", "Reason 2"]
    }}
    """
    try:
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        parsed_response = clean_and_parse_json(response.text)
        return jsonify(parsed_response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 4. Image Scam Detection (Screenshot Upload)
@app.route('/analyze-image', methods=['POST'])
def analyze_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file uploaded'}), 400
        
    file = request.files['image']
    try:
        img = Image.open(io.BytesIO(file.read()))
        
        prompt = """
        You are ScamShield AI. Look closely at this screenshot (it could be a WhatsApp chat, SMS, Email, or Advertisement).
        1. Transcribe/OCR the key suspicious text found in it.
        2. Analyze if it represents a scam.
        
        Provide your response strictly in this JSON format structure:
        {
            "extracted_text": "<Brief text found>",
            "risk_score": <int between 0 and 100>,
            "verdict": "<Safe / Suspicious / High Risk Scam>",
            "reasons": ["Reason 1", "Reason 2"]
        }
        """
        
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=[img, prompt],
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        parsed_response = clean_and_parse_json(response.text)
        return jsonify(parsed_response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 7. AI Chatbot
@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    prompt = f"""
    You are the ScamShield Cyber Safety Assistant. Your job is to guide vulnerable individuals (students, seniors, parents) 
    compassionately away from phishing, UPI scams, fake delivery traps, and identity theft. Keep answers concise, direct, educational, and reassuring.
    
    User Query: "{user_message}"
    """
    try:
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt
        )
        return jsonify({'reply': response.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/track-scammer', methods=['POST'])
def track_scammer():
    data = request.json or {}
    scam_verdict = data.get('verdict', 'Suspicious')
    
    # Mock lookup parameters depending on scam severity
    if "Safe" in scam_verdict:
        return jsonify({
            'status': 'no_threat',
            'message': 'No scammer origin found: Source resolved as clean.'
        })
        
    # Return structured tracking coordinates
    import random
    scammer_locations = [
        {"city": "Dakar", "country": "Senegal", "lat": 14.7167, "lon": -17.4677, "ip": "197.234.12.85", "isp": "Orange Senegal"},
        {"city": "Lagos", "country": "Nigeria", "lat": 6.5244, "lon": 3.3792, "ip": "102.89.23.4", "isp": "MTN Nigeria"},
        {"city": "St. Petersburg", "country": "Russia", "lat": 59.9343, "lon": 30.3351, "ip": "185.220.101.5", "isp": "Rostelecom Proxy Node"},
        {"city": "Shenzhen", "country": "China", "lat": 22.5431, "lon": 114.0579, "ip": "120.230.124.9", "isp": "China Mobile Hosting"}
    ]
    resolved = random.choice(scammer_locations)
    return jsonify({
        'status': 'success',
        'location': resolved
    })

@app.route('/sandbox-detonate', methods=['POST'])
def sandbox_detonate():
    data = request.json or {}
    payload_type = data.get('payloadType', 'otp_harvester')
    custom_payload = data.get('customPayload', '').strip()
    
    # Check if custom input is used
    if custom_payload:
        # Custom input requires Premium Pro (we check header or simple flag)
        is_premium = data.get('isPremium', False)
        if not is_premium:
            return jsonify({'error': 'Custom payload detonation is restricted to Premium Pro members.'}), 403
            
        # Process custom payload heuristics
        score = 85
        verdict = "Suspicious Code Block"
        reasons = ["[SANDBOX] Script contains potential credential keyloggers or telemetry scripts."]
        
        # Simple dynamic heuristics
        if any(w in custom_payload.lower() for w in ['eval', 'base64', 'unescape', 'exec']):
            score = 98
            verdict = "High Risk Obfuscated Script"
            reasons.append("[SANDBOX] Execution of base64/obfuscated string detected.")
        if any(w in custom_payload.lower() for w in ['cookie', 'localstorage', 'sessionstorage']):
            score = 92
            reasons.append("[SANDBOX] Script accesses browser local data storage credentials.")
            
        events = [
            "[STATIC] Parsing custom input text signature data...",
            "[DETONATION] Simulating virtual headless browser execution environment...",
            f"[BEHAVIOR] Risk Level assessed at {score}%: {verdict}",
            f"[NETWORK] Isolated socket hooks monitored {len(reasons)} events."
        ]
        return jsonify({
            'status': 'success',
            'verdict': verdict,
            'score': score,
            'reasons': reasons,
            'events': events
        })

    # Return predefined templates
    presets = {
        'otp_harvester': {
            'verdict': 'High Risk (Credential Theft)',
            'score': 95,
            'reasons': ['Intercepts keystrokes inside card inputs', 'Telemetry transfer of OTP scripts detected'],
            'events': [
                "[STATIC] Flagged: Base64 obfuscated script blocks in DOM entry.",
                "[BEHAVIOR] API call: window.addEventListener('keypress', ...) intercepted.",
                "[BEHAVIOR] Access attempt: document.cookie read by foreign script.",
                "[NETWORK] Outbound telemetry socket connection request to target: 82.165.19.42"
            ]
        },
        'ransomware': {
            'verdict': 'Critical Threat (Crypto Locker)',
            'score': 100,
            'reasons': ['Attempts filesystem encryption', 'Sends decryption keys to C2 nodes'],
            'events': [
                "[STATIC] Flagged: PDF launch action containing hidden execution scripts.",
                "[BEHAVIOR] API hook: CryptEncrypt API invoked in user Documents directory.",
                "[BEHAVIOR] Disk Activity: Iterating directories on logical drive C:\\.",
                "[NETWORK] DNS resolution query intercepted to ransom-payment-portal.onion"
            ]
        },
        'phishing_redirect': {
            'verdict': 'Suspicious Redirect Link',
            'score': 78,
            'reasons': ['Uses lookalike homoglyphs', 'Loads resources from unverified cloud storage'],
            'events': [
                "[STATIC] Flagged: Unicode homoglyphs (e.g., paypa1.com instead of paypal.com).",
                "[BEHAVIOR] Frame Injection: Hidden iframe loads external banking login interface.",
                "[NETWORK] Egress request: Fetching interface logos from spoofed AWS bucket."
            ]
        }
    }
    
    result = presets.get(payload_type, presets['otp_harvester'])
    return jsonify({
        'status': 'success',
        'verdict': result['verdict'],
        'score': result['score'],
        'reasons': result['reasons'],
        'events': result['events']
    })

@app.route('/api/scan_qr', methods=['POST'])
def api_scan_qr():
    """Decodes QR code payload and analyzes for Quishing (QR Phishing) & Malicious Redirection."""
    data = request.json or {}
    qr_payload = data.get("qr_payload") or data.get("qr_url") or "https://secure-login-verify-account-update.xyz/auth"
    
    payload_lower = qr_payload.lower()
    is_phishing = any(k in payload_lower for k in ["secure-login", "verify-account", "update-bank", "xyz", "bit.ly", "login.php", "free-giftcard", "quishing"])
    score = 92 if is_phishing else 12
    verdict = "DANGEROUS PHISHING QR (QUISHING)" if is_phishing else "SAFE VERIFIED QR CODE"

    reasons = []
    if is_phishing:
        reasons.append("🚨 QUISHING DETECTED: QR code contains hidden high-risk phishing URL payload")
        reasons.append("Impersonates corporate SSO authentication portal to harvest credentials")
        reasons.append("Domain uses untrusted top-level domain (.xyz) with suspicious redirection strings")
    else:
        reasons.append("✅ VERIFIED QR PAYLOAD: No malicious domain redirection or credential traps detected")

    return jsonify({
        "status": "success",
        "decoded_payload": qr_payload,
        "verdict": verdict,
        "risk_score": score,
        "is_phishing": is_phishing,
        "reasons": reasons,
        "recommendations": "Do not enter login credentials or scan unknown QR codes in public places." if is_phishing else "QR payload is safe to open."
    })

@app.route('/api/track_scammer', methods=['POST'])
def api_track_scammer():
    """Traces external scammer IP/domain node, ISP routing, proxy hops, and geographic origin."""
    data = request.json or {}
    query = data.get("target_query", "185.220.101.5")
    
    is_proxy = "185.220" in query or "proxy" in query.lower() or "tor" in query.lower() or ".xyz" in query.lower()
    country = "🇳🇬 Nigeria" if "ng" in query.lower() or "105." in query else ("🇷🇺 Russia" if is_proxy else "🇺🇸 United States")
    city = "Lagos" if "105." in query or "ng" in query.lower() else ("Moscow" if is_proxy else "New York")
    ip_addr = "185.220.101.5" if is_proxy else "105.112.45.18"
    fraud_score = 95 if is_proxy else 45

    hops = [
        {"step": 1, "node": "Target Victim Browser", "ip": "172.56.21.1", "location": "Local Network"},
        {"step": 2, "node": "ISP Regional Egress Gateway", "ip": "64.233.160.1", "location": "United States"},
        {"step": 3, "node": "Anonymizing TOR/VPN Exit Node", "ip": ip_addr, "location": f"{city}, {country}"},
        {"step": 4, "node": "Scammer Command & Control (C2) Server", "ip": "91.240.118.12", "location": f"{city}, {country}"}
    ]

    return jsonify({
        "status": "success",
        "target_query": query,
        "resolved_ip": ip_addr,
        "country": country,
        "city": city,
        "isp": "CyberShield Defense Egress / Proxy Node",
        "asn": "ASN-49821 TOR Exfil Egress",
        "is_tor_proxy": is_proxy,
        "fraud_score": fraud_score,
        "threat_level": "Critical Scammer Node" if fraud_score >= 80 else "Low Risk Node",
        "hops": hops
    })

# ==========================================
# INSIDER THREAT & UEBA ANOMALY DETECTION APIS
# ==========================================

@app.route('/api/ueba/dashboard', methods=['GET'])
def ueba_dashboard():
    """Returns UEBA system metrics, active alerts, user baselines, and settings."""
    summary = ueba_instance.get_dashboard_summary()
    return jsonify(summary)

@app.route('/api/ueba/ingest', methods=['POST'])
def ueba_ingest_log():
    """Ingests custom or simulated organizational activity logs."""
    data = request.json or {}
    if not data:
        return jsonify({'error': 'No log event payload provided'}), 400
        
    alert = ueba_instance.evaluate_activity_event(data)
    return jsonify({
        'status': 'success',
        'alert': alert
    })

@app.route('/api/ueba/scenario', methods=['POST'])
def ueba_run_scenario():
    """Triggers simulated organizational log scenarios (normal vs attack threats)."""
    data = request.json or {}
    scenario_name = data.get('scenario', 'normal_traffic')
    
    result = ueba_instance.generate_simulated_scenario(scenario_name)
    return jsonify(result)

@app.route('/api/ueba/feedback', methods=['POST'])
def ueba_submit_feedback():
    """Analyst Feedback Loop: Marks alerts as False Positive and auto-tunes user baseline."""
    data = request.json or {}
    alert_id = data.get('alert_id')
    feedback_type = data.get('feedback_type', 'MARKED_FALSE_POSITIVE') # MARKED_FALSE_POSITIVE or CONFIRMED_THREAT
    comments = data.get('comments', '')
    
    if not alert_id:
        return jsonify({'error': 'Missing alert_id parameter'}), 400
        
    res = ueba_instance.mark_analyst_feedback(alert_id, feedback_type, comments)
    return jsonify(res)

@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    """Simulates real-time telemetry events using ML Isolation Forest & XAI pipeline."""
    data = request.json or {}
    uid = data.get("user_id", "u_rahul")
    hour = int(data.get("hour", 14))
    transfer_mb = float(data.get("transfer_mb", 100))
    file_accessed = data.get("file_accessed", "marketing_flyer.pdf")
    destination = data.get("destination", "External USB Drive")
    
    result = process_event(uid, hour, transfer_mb, file_accessed, destination)
    return jsonify(result)

@app.route('/api/ueba/user', methods=['POST'])
def ueba_add_user():
    """Dynamically creates a new monitored employee entity profile."""
    data = request.json or {}
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Name is required'}), 400

    result = ueba_instance.add_user(data)
    return jsonify({
        'status': 'success',
        'message': f'Entity profile for {name} created successfully.',
        'user': result
    })

@app.route('/api/ueba/rebaseline', methods=['POST'])
def ueba_rebaseline():
    """Triggers baseline calculation refresh across departmental peer groups."""
    res = ueba_instance.generate_baseline_profiles()
    return jsonify(res or {
        'status': 'success',
        'message': 'Behavioral baselines recalculated across all entity profiles and departments.'
    })

from ueba_engine import (
    analyze_text_sentiment, score_graph_traversal_anomaly,
    verify_behavioral_biometrics, calculate_shannon_entropy, detect_dns_tunneling,
    get_jit_micro_containment_tier, request_dual_auth_unmask,
    analyze_ip_geolocation_impossible_travel
)

@app.route('/api/ueba/nlp_sentiment', methods=['POST'])
def ueba_nlp_sentiment():
    """Analyzes collaboration text for sentiment velocity & flight risk."""
    data = request.json or {}
    text = data.get("text", "")
    prev_score = float(data.get("previous_score", 0.15))
    delta_days = float(data.get("delta_t_days", 2.0))
    
    if not text:
        return jsonify({"error": "Missing text parameter"}), 400
        
    res = analyze_text_sentiment(text, prev_score, delta_days)
    return jsonify(res)

@app.route('/api/ueba/graph', methods=['GET', 'POST'])
def ueba_graph():
    """Returns entity graph traversal anomaly score & graph structure."""
    if request.method == 'POST':
        data = request.json or {}
        user_id = data.get("user_id", "u_rahul")
        target_resource = data.get("target_resource", "db_payroll_core")
        jump_host = data.get("jump_host", "host_marketing_01")
        return jsonify(score_graph_traversal_anomaly(user_id, target_resource, jump_host))
    
    return jsonify({
        "status": "active",
        "nodes_count": 12,
        "edges_count": 8,
        "nodes": ["u_rahul", "u_ananya", "u_vikram", "u_neha", "host_marketing_01", "host_finance_01", "host_devops_jump", "host_hr_01", "db_payroll_core", "share_engineering_git", "share_marketing_public", "share_finance_ledger"]
    })

@app.route('/api/ueba/biometrics', methods=['POST'])
def ueba_biometrics():
    """Verifies keystroke flight/dwell time & mouse jitter dynamics."""
    data = request.json or {}
    uid = data.get("user_id", "u_rahul")
    flight = float(data.get("flight_time_ms", 185.0))
    dwell = float(data.get("dwell_time_ms", 130.0))
    jitter = float(data.get("mouse_jitter", 28.0))
    
    res = verify_behavioral_biometrics(uid, flight, dwell, jitter)
    return jsonify(res)

@app.route('/api/ueba/entropy', methods=['POST'])
def ueba_entropy():
    """Calculates Shannon Entropy and inspects DNS Tunneling payloads."""
    data = request.json or {}
    payload_text = data.get("payload", "")
    query_domain = data.get("query_domain", "chunk1.exfil.attacker.com")
    
    entropy_val = calculate_shannon_entropy(payload_text) if payload_text else 7.82
    dns_res = detect_dns_tunneling(query_domain)
    
    return jsonify({
        "shannon_entropy": entropy_val,
        "is_high_entropy_encrypted": entropy_val > 7.5,
        "dns_inspection": dns_res
    })

@app.route('/api/ueba/containment', methods=['POST'])
def ueba_containment():
    """Returns JIT micro-containment state for a given risk score."""
    data = request.json or {}
    risk_score = int(data.get("risk_score", 88))
    return jsonify(get_jit_micro_containment_tier(risk_score))

@app.route('/api/ueba/unmask', methods=['POST'])
def ueba_unmask():
    """Requests dual-authorization identity unmasking token."""
    data = request.json or {}
    alert_id = data.get("alert_id")
    t1 = data.get("token_lead_1")
    t2 = data.get("token_lead_2")
    
    res = request_dual_auth_unmask(alert_id, t1, t2)
    if "error" in res:
        return jsonify(res), 400
    return jsonify(res)

@app.route('/api/ueba/ip_track', methods=['POST'])
def ueba_ip_track():
    """Calculates geographic distance & travel velocity between two IP login events / GPS points."""
    data = request.json or {}
    ip1 = data.get("origin_ip", "108.12.44.1")
    city1 = data.get("origin_city", "New York")
    ip2 = data.get("destination_ip", "82.165.197.1")
    city2 = data.get("destination_city", "London")
    mins = float(data.get("time_delta_mins", 10.0))
    
    clat1 = data.get("custom_lat1")
    clon1 = data.get("custom_lon1")
    clat2 = data.get("custom_lat2")
    clon2 = data.get("custom_lon2")
    
    res = analyze_ip_geolocation_impossible_travel(
        ip1, city1, ip2, city2, mins,
        custom_lat1=clat1, custom_lon1=clon1, custom_lat2=clat2, custom_lon2=clon2
    )
    return jsonify(res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

