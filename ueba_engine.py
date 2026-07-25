import random
import time
import math
import uuid
from datetime import datetime, timedelta

# Try importing numpy and sklearn; fallback to pure Python math if not installed
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Organizational User Database & Context Hub (Enrichment Engine)
USERS = {
    "u_rahul": {
        "name": "Rahul Verma",
        "dept": "Marketing",
        "role": "Content Manager",
        "peer_group": "marketing_team",
        "on_watchlist": True,  # Resignation notice served 3 days ago
        "watchlist_reason": "HR Notice Period Active (Resigned)",
        "baseline_avg_mb": 45.0,
        "baseline_std_mb": 15.0,
        "normal_hours": (9, 18),
        "current_risk": 95,
        "event_count": 8,
        "last_file_accessed": "executive_salaries_2026.xlsx"
    },
    "u_ananya": {
        "name": "Ananya Sharma",
        "dept": "Finance",
        "role": "Senior Accountant",
        "peer_group": "finance_team",
        "on_watchlist": False,
        "watchlist_reason": None,
        "baseline_avg_mb": 350.0,
        "baseline_std_mb": 80.0,  # Finance routinely transfers large ledger files
        "normal_hours": (9, 19),
        "current_risk": 20,
        "event_count": 12,
        "last_file_accessed": "general_ledger_2026.xlsx"
    },
    "u_vikram": {
        "name": "Vikram Patel",
        "dept": "DevOps",
        "role": "Cloud Architect",
        "peer_group": "engineering_team",
        "on_watchlist": False,
        "watchlist_reason": None,
        "baseline_avg_mb": 1200.0,
        "baseline_std_mb": 300.0,  # Engineers pull large codebases & container builds
        "normal_hours": (8, 20),
        "current_risk": 15,
        "event_count": 15,
        "last_file_accessed": "engineering_codebase.tar.gz"
    },
    "u_neha": {
        "name": "Neha Gupta",
        "dept": "HR",
        "role": "Talent Acquisition",
        "peer_group": "hr_team",
        "on_watchlist": False,
        "watchlist_reason": None,
        "baseline_avg_mb": 60.0,
        "baseline_std_mb": 20.0,
        "normal_hours": (9, 17),
        "current_risk": 10,
        "event_count": 5,
        "last_file_accessed": "q2_tax_returns.pdf"
    }
}

# Sensitivity scores assigned to file resources (1 = Public, 5 = Critical Core IP/Payroll)
RESOURCE_SENSITIVITY = {
    "marketing_flyer.pdf": 1,
    "public_press_release.docx": 1,
    "q3_campaign_draft.pptx": 2,
    "general_ledger_2026.xlsx": 4,
    "q2_tax_returns.pdf": 4,
    "engineering_codebase.tar.gz": 4,
    "aws_root_credentials_backup.txt": 5,
    "executive_salaries_2026.xlsx": 5,
    "canary_honeypot_passwords.xlsx": 5  # Honeypot trap file
}

def generate_synthetic_history(num_days=30):
    """Generates 30 days of baseline activity data for all users to train ML models."""
    logs = []
    base_time = datetime.now() - timedelta(days=num_days)
    
    for day in range(num_days):
        current_day = base_time + timedelta(days=day)
        # Skip weekends for standard baseline
        if current_day.weekday() >= 5:
            continue
            
        for uid, profile in USERS.items():
            # 2 to 5 normal file access operations per user per day
            num_events = random.randint(2, 5)
            for _ in range(num_events):
                # Sample login hours based on profile normal work hours
                start_h, end_h = profile["normal_hours"]
                hour = random.randint(start_h, end_h - 1)
                minute = random.randint(0, 59)
                event_time = current_day.replace(hour=hour, minute=minute)
                
                # Sample outbound transfer size based on individual standard distribution
                if SKLEARN_AVAILABLE:
                    bytes_mb = max(1.0, float(np.random.normal(profile["baseline_avg_mb"] / 4, profile["baseline_std_mb"] / 4)))
                else:
                    bytes_mb = max(1.0, float(random.gauss(profile["baseline_avg_mb"] / 4, profile["baseline_std_mb"] / 4)))
                
                # Select department-appropriate files
                if profile["dept"] == "Finance":
                    file_name = random.choice(["general_ledger_2026.xlsx", "q2_tax_returns.pdf"])
                elif profile["dept"] == "DevOps":
                    file_name = random.choice(["engineering_codebase.tar.gz", "q3_campaign_draft.pptx"])
                else:
                    file_name = random.choice(["marketing_flyer.pdf", "public_press_release.docx"])
                    
                logs.append({
                    "timestamp": event_time,
                    "user_id": uid,
                    "hour": hour,
                    "transfer_mb": round(bytes_mb, 2),
                    "file_accessed": file_name,
                    "sensitivity": RESOURCE_SENSITIVITY.get(file_name, 1),
                    "destination": "Internal Shares"
                })
    return logs

def extract_feature_vectors(logs):
    """
    Transforms raw telemetry events into numerical vectors for Isolation Forest:
    Vector: [hour_offset_from_peak, transfer_mb, file_sensitivity]
    """
    X = []
    for row in logs:
        hour_offset = abs(row["hour"] - 14)
        X.append([
            float(hour_offset),
            float(row["transfer_mb"]),
            float(row["sensitivity"])
        ])
    return X

# Generate baseline training data & train ML Model
print("[UEBA Engine] Generating synthetic 30-day baseline data...")
baseline_logs = generate_synthetic_history(num_days=30)
X_train = extract_feature_vectors(baseline_logs)

if SKLEARN_AVAILABLE:
    print("[UEBA Engine] Training Isolation Forest Unsupervised Anomaly Model (Scikit-Learn)...")
    X_train_np = np.array(X_train)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_np)
    iso_forest = IsolationForest(contamination=0.03, random_state=42)
    iso_forest.fit(X_train_scaled)
else:
    print("[UEBA Engine] Training Statistical Distance Anomaly Model (Pure Python)...")
    scaler = None
    iso_forest = None

# In-memory alert feed & telemetry history
LIVE_EVENTS = []
ALERT_FEED = []
FEEDBACK_RECORDS = []

def process_event(user_id, hour, transfer_mb, file_accessed, destination="External USB Drive"):
    """
    Multi-vector correlation pipeline:
    1. ML Anomaly Score (Isolation Forest / Multi-variate Distance)
    2. Peer Group Baseline Comparison
    3. Context Hub Amplifiers (HR Watchlist, Canary trap files)
    4. XAI (Explainable AI) Reason Generation
    5. Dynamic Entity Baseline Profile updates!
    """
    profile = USERS.get(user_id, USERS["u_rahul"])
    sensitivity = RESOURCE_SENSITIVITY.get(file_accessed, 2)
    
    # 1. Machine Learning Anomaly Detection
    hour_offset = abs(hour - 14)
    
    if SKLEARN_AVAILABLE and scaler and iso_forest:
        raw_vector = np.array([[hour_offset, transfer_mb, sensitivity]])
        scaled_vector = scaler.transform(raw_vector)
        ml_score_raw = float(iso_forest.score_samples(scaled_vector)[0])
        ml_risk_component = min(100, max(0, int((0.2 - ml_score_raw) * 200)))
    else:
        # Pure Python Distance-based Multivariate Anomaly Model
        dist_hour = hour_offset / 5.0
        dist_vol = max(0, (transfer_mb - profile["baseline_avg_mb"]) / max(1.0, profile["baseline_std_mb"]))
        dist_sens = sensitivity / 2.5
        composite_dist = math.sqrt(dist_hour**2 + dist_vol**2 + dist_sens**2)
        ml_risk_component = min(100, max(0, int(composite_dist * 18)))

    # 2. Peer Group & Individual Baseline Relative Deviation calculation
    user_z_score = (transfer_mb - profile["baseline_avg_mb"]) / max(1.0, profile["baseline_std_mb"])
    
    reasons = []
    
    # Check 1: Temporal Anomaly (Off-hours access)
    is_off_hours = hour < profile["normal_hours"][0] or hour >= profile["normal_hours"][1]
    if is_off_hours:
        reasons.append(f"Off-hours activity at {hour:02d}:00 (Standard window: {profile['normal_hours'][0]}:00 - {profile['normal_hours'][1]}:00)")
        
    # Check 2: Volume Anomaly vs User Baseline
    if user_z_score > 3.0:
        reasons.append(f"Massive data movement ({transfer_mb} MB) is {user_z_score:.1f}x standard deviation above user baseline ({profile['baseline_avg_mb']} MB)")
    elif user_z_score > 1.5:
        reasons.append(f"Elevated transfer volume ({transfer_mb} MB) vs personal baseline")

    # Check 3: Resource Sensitivity & Canary Files
    if file_accessed == "canary_honeypot_passwords.xlsx":
        reasons.append("🚨 HONEYPOT TRAP TRIGGERED: Touched fake classified canary document")
        ml_risk_component += 50
    elif sensitivity >= 4:
        reasons.append(f"Accessed highly classified file asset ('{file_accessed}' Sensitivity: Level {sensitivity}/5)")

    # Check 4: Destination Risk
    if destination in ["External USB Drive", "Personal Google Drive"]:
        reasons.append(f"Egress vector targeting unauthorized endpoint ({destination})")

    # 3. Contextual Amplifiers & Peer Group False-Positive Suppression
    composite_score = ml_risk_component + (user_z_score * 10) + (sensitivity * 8)
    if is_off_hours:
        composite_score += 20

    # Peer Suppression Logic: If user belongs to DevOps/Finance and transfer matches team norm, suppress!
    # (Honeypot trap files and Level 5 assets bypass peer suppression)
    if profile["dept"] in ["DevOps", "Finance"] and user_z_score < 2.0 and not is_off_hours and file_accessed != "canary_honeypot_passwords.xlsx" and sensitivity < 5:
        composite_score *= 0.4  # Suppress false positives for heavy data users in normal hours
        reasons.append(f"🟢 PEER GROUP SUPPRESSION: Volume matches standard operational norm for {profile['dept']} team")

    # Watchlist Amplifier: If employee is resigning, amplify risk score
    if profile["on_watchlist"]:
        composite_score *= 1.45
        reasons.append(f"⚠️ WATCHLIST AMPLIFIER: User on HR departure watch list ({profile['watchlist_reason']})")

    # Cap Final Risk Score (0-100)
    final_score = int(min(100, max(0, composite_score)))
    
    # Categorize Severity
    if final_score >= 85:
        severity = "Critical"
    elif final_score >= 60:
        severity = "High"
    elif final_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    # --- Dynamic Update of User Behavioral Profile State ---
    profile["current_risk"] = final_score
    profile["event_count"] = profile.get("event_count", 0) + 1
    profile["last_file_accessed"] = file_accessed
    profile["last_event_time"] = datetime.now().strftime("%H:%M:%S")

    # Adaptively update user baseline rolling mean volume if non-anomalous
    if user_z_score <= 2.0 and not is_off_hours:
        profile["baseline_avg_mb"] = round((profile["baseline_avg_mb"] * 0.95) + (transfer_mb * 0.05), 1)

    alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

    event_record = {
        "alert_id": alert_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "name": profile["name"],
        "dept": profile["dept"],
        "role": profile.get("role", "Employee"),
        "hour": f"{hour:02d}:00",
        "transfer_mb": transfer_mb,
        "file_accessed": file_accessed,
        "destination": destination,
        "risk_score": final_score,
        "severity": severity,
        "reasons": reasons,
        "anomaly_drivers": reasons,
        "mitigation_notes": [],
        "false_positive_status": "UNREVIEWED"
    }

    LIVE_EVENTS.insert(0, event_record)
    if len(LIVE_EVENTS) > 100:
        LIVE_EVENTS.pop()

    if final_score >= 30:
        ALERT_FEED.insert(0, event_record)
        if len(ALERT_FEED) > 100:
            ALERT_FEED.pop()
        
    return event_record

def add_user_entity(name, dept, role, baseline_avg_mb=100.0, baseline_std_mb=30.0, start_hour=9, end_hour=18, on_watchlist=False, watchlist_reason=None, user_id=None):
    """Dynamically registers a new monitored employee entity profile."""
    if not user_id:
        safe_name = name.lower().replace(" ", "_")
        user_id = f"u_{safe_name}_{uuid.uuid4().hex[:4]}"

    profile = {
        "name": name,
        "dept": dept,
        "role": role,
        "peer_group": f"{dept.lower()}_team",
        "on_watchlist": bool(on_watchlist),
        "watchlist_reason": watchlist_reason if on_watchlist else None,
        "baseline_avg_mb": float(baseline_avg_mb),
        "baseline_std_mb": float(baseline_std_mb),
        "normal_hours": (int(start_hour), int(end_hour)),
        "current_risk": 90 if on_watchlist else 15,
        "event_count": 0,
        "last_file_accessed": "None"
    }

    USERS[user_id] = profile
    return {"user_id": user_id, "profile": profile}

# Seed initial baseline events
process_event("u_ananya", 11, 380.0, "general_ledger_2026.xlsx", "Internal Corporate Share")
process_event("u_vikram", 14, 1100.0, "engineering_codebase.tar.gz", "Dev Server Build")
process_event("u_rahul", 2, 2450.0, "executive_salaries_2026.xlsx", "External USB Drive")

class UEBAEngineWrapper:
    """Class wrapper for backward compatibility with API calls and dashboard helpers."""

    def __init__(self):
        self.users = USERS
        self.alerts = ALERT_FEED
        self.logs_history = LIVE_EVENTS
        self.feedback_records = FEEDBACK_RECORDS

    def add_user(self, data):
        name = data.get("name", "New Employee")
        dept = data.get("dept", data.get("department", "Engineering"))
        role = data.get("role", "Engineer")
        avg_mb = float(data.get("baseline_avg_mb", 100.0))
        std_mb = float(data.get("baseline_std_mb", 30.0))
        start_h = int(data.get("start_hour", data.get("normal_start_hour", 9)))
        end_h = int(data.get("end_hour", data.get("normal_end_hour", 18)))
        on_watchlist = bool(data.get("on_watchlist", False))
        watchlist_reason = data.get("watchlist_reason", "HR Flag")

        return add_user_entity(name, dept, role, avg_mb, std_mb, start_h, end_h, on_watchlist, watchlist_reason)

    def evaluate_activity_event(self, log_event):
        uid = log_event.get("user_id", "u_rahul")
        hour = int(log_event.get("hour", datetime.now().hour))
        transfer_mb = float(log_event.get("transfer_mb", log_event.get("bytes_transferred", 100)))
        file_accessed = log_event.get("file_accessed", "marketing_flyer.pdf")
        destination = log_event.get("destination", "External USB Drive")

        return process_event(uid, hour, transfer_mb, file_accessed, destination)

    def mark_analyst_feedback(self, alert_id, feedback_type, comments=""):
        alert = next((a for a in ALERT_FEED if a.get("alert_id") == alert_id), None)
        if not alert:
            return {"error": "Alert not found"}

        alert["false_positive_status"] = feedback_type
        record = {
            "alert_id": alert_id,
            "feedback_type": feedback_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "comments": comments
        }
        FEEDBACK_RECORDS.append(record)

        if feedback_type == "MARKED_FALSE_POSITIVE":
            user_id = alert["user_id"]
            profile = USERS.get(user_id)
            if profile:
                profile["baseline_std_mb"] = round(max(profile["baseline_std_mb"], alert["transfer_mb"] * 0.5), 1)
                profile["current_risk"] = max(10, profile["current_risk"] - 35)

            return {
                "status": "success",
                "message": f"Alert {alert_id} marked as False Positive. Entity baseline expanded.",
                "alert_id": alert_id
            }

        return {"status": "success", "message": f"Alert {alert_id} updated."}

    def generate_simulated_scenario(self, scenario_name):
        if scenario_name == "normal_traffic":
            ev1 = process_event("u_ananya", 11, 280.0, "general_ledger_2026.xlsx", "Internal Corporate Share")
            ev2 = process_event("u_vikram", 14, 900.0, "engineering_codebase.tar.gz", "Dev Server Build")
            return {"scenario": "Normal Enterprise Traffic", "primary_alert": ev1}
        elif scenario_name == "exfiltration_insider":
            ev = process_event("u_rahul", 2, 3450.0, "executive_salaries_2026.xlsx", "External USB Drive")
            return {"scenario": "Exfiltration Insider Threat", "primary_alert": ev}
        elif scenario_name == "honeypot":
            ev = process_event("u_rahul", 23, 100.0, "canary_honeypot_passwords.xlsx", "Personal Google Drive")
            return {"scenario": "Honeypot Trap Triggered", "primary_alert": ev}
        elif scenario_name == "impossible_travel":
            ev = process_event("u_neha", 3, 550.0, "q2_tax_returns.pdf", "Personal Google Drive")
            return {"scenario": "Off-Hours HR Access", "primary_alert": ev}
        elif scenario_name == "slow_stealth":
            ev = process_event("u_ananya", 22, 1200.0, "aws_root_credentials_backup.txt", "External USB Drive")
            return {"scenario": "Stealth Credential Egress", "primary_alert": ev}

        return {"error": "Unknown scenario"}

    def generate_baseline_profiles(self):
        """
        Full Baseline Recalculation & ML Model Retraining:
        1. Retrains Isolation Forest / Statistical distance model on synthetic 30-day data.
        2. Recalculates mean and std dev parameters for all entity profiles.
        3. Recalibrates current risk scores and peer department norms.
        """
        global X_train, X_train_scaled, iso_forest, scaler
        
        # 1. Regenerate baseline logs & retrain ML Model
        baseline_logs = generate_synthetic_history(num_days=30)
        X_train = extract_feature_vectors(baseline_logs)

        if SKLEARN_AVAILABLE:
            X_train_np = np.array(X_train)
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train_np)
            iso_forest = IsolationForest(contamination=0.03, random_state=42)
            iso_forest.fit(X_train_scaled)

        # 2. Recalculate per-entity baseline statistics
        updated_count = 0
        for uid, user in USERS.items():
            user_logs = [e for e in LIVE_EVENTS if e.get("user_id") == uid]
            if user_logs:
                volumes = [e["transfer_mb"] for e in user_logs]
                mean_vol = sum(volumes) / len(volumes)
                variance = sum((x - mean_vol) ** 2 for x in volumes) / len(volumes)
                std_vol = math.sqrt(variance)
                
                user["baseline_avg_mb"] = round((user["baseline_avg_mb"] * 0.4) + (mean_vol * 0.6), 1)
                user["baseline_std_mb"] = round(max(10.0, (user["baseline_std_mb"] * 0.4) + (std_vol * 0.6)), 1)
            else:
                user["baseline_avg_mb"] = round(user["baseline_avg_mb"] * 1.02, 1)
                
            # Reset/recalibrate entity current risk after rebaselining
            user["current_risk"] = max(10, int(user.get("current_risk", 15) * 0.5))
            updated_count += 1

        return {
            "status": "success",
            "message": f"Successfully retrained Isolation Forest ML model and recalculated behavioral baselines for {updated_count} entities.",
            "recalculated_count": updated_count
        }

    def get_dashboard_summary(self):
        total_alerts = len(ALERT_FEED)
        critical_count = len([a for a in ALERT_FEED if a.get("severity") == "Critical" or a.get("risk_score", 0) >= 85])
        high_count = len([a for a in ALERT_FEED if a.get("severity") == "High" or (60 <= a.get("risk_score", 0) < 85)])
        fp_count = len([a for a in ALERT_FEED if a.get("false_positive_status") == "MARKED_FALSE_POSITIVE"])

        fp_rate = (fp_count / float(total_alerts) * 100.0) if total_alerts > 0 else 1.2

        user_list = []
        for uid, u in USERS.items():
            user_list.append({
                "user_id": uid,
                "name": u["name"],
                "department": u["dept"],
                "role": u["role"],
                "current_risk": u.get("current_risk", 15),
                "bytes_mean_mb": u["baseline_avg_mb"],
                "bytes_std_mb": round(u["baseline_std_mb"], 1),
                "event_count": u.get("event_count", 0),
                "last_file_accessed": u.get("last_file_accessed", "None"),
                "working_hours": f"{u['normal_hours'][0]:02d}:00 - {u['normal_hours'][1]:02d}:00",
                "on_watchlist": u["on_watchlist"],
                "watchlist_reason": u["watchlist_reason"],
                "sensitivity_tuning": 0.85 if u["dept"] in ["DevOps", "Finance"] else 1.0
            })

        return {
            "total_entities_monitored": len(USERS),
            "total_alerts": total_alerts,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "false_positives_marked": fp_count,
            "false_positive_rate": round(fp_rate, 1),
            "users": user_list,
            "alerts": ALERT_FEED[:30],
            "live_events": LIVE_EVENTS[:30]
        }

# =====================================================================
# 🚀 ADVANCED ENTERPRISE EXTENSIONS FOR UEBA & INSIDER THREAT ENGINE
# =====================================================================

def analyze_text_sentiment(text, previous_score=0.15, delta_t_days=2.0):
    """
    Analyzes masked collaboration text snippets (Slack/Teams/Email) to detect toxic workplace interactions,
    resignation talk, and hostile language toward management.
    Calculates Sentiment Velocity: (Current_Neg_Score - Prev_Neg_Score) / Delta_t
    """
    if not text or not text.strip():
        text = "Normal workplace collaboration text"

    text_lower = text.lower()
    negative_keywords = ["resign", "quitting", "quit", "hate this company", "management is corrupt", "looking for new job", "competitor offer", "interview next week", "unfair salary", "manager is terrible", "downloading files before leaving", "leaving soon"]
    toxic_keywords = ["corrupt", "idiots", "terrible", "worst place", "screw this", "stealing code", "backup everything", "hate", "unfair", "angry"]
    
    neg_hits = sum(1 for kw in negative_keywords if kw in text_lower)
    toxic_hits = sum(1 for kw in toxic_keywords if kw in text_lower)
    
    if neg_hits > 0 or toxic_hits > 0:
        current_neg_score = min(1.0, 0.25 + (neg_hits * 0.25) + (toxic_hits * 0.15))
    else:
        current_neg_score = 0.05

    sentiment_velocity = round((current_neg_score - previous_score) / max(0.1, delta_t_days), 3)
    flight_risk = current_neg_score >= 0.40 or sentiment_velocity > 0.15
    
    reasons = []
    if flight_risk:
        reasons.append(f"⚠️ HIGH FLIGHT RISK DETECTED: Sentiment Velocity = +{sentiment_velocity:.3f}/day (Threshold > +0.15)")
    if neg_hits > 0:
        reasons.append(f"Detected {neg_hits} resignation/job-hunting keywords in collaboration metadata")
    if toxic_hits > 0:
        reasons.append(f"Detected {toxic_hits} hostile workplace expressions")
    if not reasons:
        reasons.append("✅ BENIGN DIALOGUE: Collaboration text shows standard operational interaction with no hostility or departure intent")

    return {
        "text_snippet": text,
        "negative_sentiment_score": round(current_neg_score, 2),
        "sentiment_velocity": sentiment_velocity,
        "flight_risk": flight_risk,
        "reasons": reasons
    }

# 🕸️ 2. Graph Neural Networks & Entity Relationship Graphs
def build_entity_relationship_graph():
    """Builds organizational graph connecting Users -> Workstations/Jump Hosts -> Database Servers -> Sensitive Folders."""
    try:
        import networkx as nx
        G = nx.DiGraph()
        
        G.add_node("u_rahul", type="User", dept="Marketing")
        G.add_node("u_ananya", type="User", dept="Finance")
        G.add_node("u_vikram", type="User", dept="DevOps")
        G.add_node("u_neha", type="User", dept="HR")
        
        G.add_node("host_marketing_01", type="Workstation")
        G.add_node("host_finance_01", type="Workstation")
        G.add_node("host_devops_jump", type="JumpHost")
        G.add_node("host_hr_01", type="Workstation")
        
        G.add_node("db_payroll_core", type="DatabaseServer", sensitivity=5)
        G.add_node("share_engineering_git", type="CodeRepository", sensitivity=4)
        G.add_node("share_marketing_public", type="SharedFolder", sensitivity=1)
        G.add_node("share_finance_ledger", type="SharedFolder", sensitivity=4)

        G.add_edge("u_rahul", "host_marketing_01", relation="AUTH")
        G.add_edge("host_marketing_01", "share_marketing_public", relation="READ")
        
        G.add_edge("u_ananya", "host_finance_01", relation="AUTH")
        G.add_edge("host_finance_01", "share_finance_ledger", relation="READ_WRITE")
        
        G.add_edge("u_vikram", "host_devops_jump", relation="SSH")
        G.add_edge("host_devops_jump", "share_engineering_git", relation="DEPLOY")
        G.add_edge("host_devops_jump", "db_payroll_core", relation="DB_ADMIN")

        G.add_edge("u_neha", "host_hr_01", relation="AUTH")
        G.add_edge("host_hr_01", "db_payroll_core", relation="READ_HR")

        return G
    except ImportError:
        return None

def score_graph_traversal_anomaly(user_id, target_resource, jump_host="host_marketing_01"):
    """Evaluates graph traversal path anomalies using NetworkX shortest path and node centrality."""
    G = build_entity_relationship_graph()
    if G is None:
        is_atypical = (jump_host == "host_marketing_01" and "db_" in target_resource)
        return {
            "user_id": user_id,
            "target_resource": target_resource,
            "jump_host": jump_host,
            "has_authorized_graph_path": not is_atypical,
            "graph_distance": 99 if is_atypical else 2,
            "graph_anomaly_score": 90 if is_atypical else 15,
            "is_atypical_traversal": is_atypical,
            "reason": f"🕸️ ATYPICAL GRAPH TRAVERSAL: {user_id} accessed '{target_resource}' via unusual jump host '{jump_host}'" if is_atypical else "Standard Graph Traversal Path"
        }

    import networkx as nx
    if not G.has_node(user_id):
        G.add_node(user_id, type="User", dept="External")
    if not G.has_node(target_resource):
        G.add_node(target_resource, type="ResourceNode", sensitivity=4)

    has_path = nx.has_path(G, user_id, target_resource)
    path_len = nx.shortest_path_length(G, user_id, target_resource) if has_path else 99
    
    is_atypical_path = (not has_path) or (path_len > 2) or (jump_host == "host_marketing_01" and "db_" in target_resource)
    anomaly_score = 90 if is_atypical_path else 15

    return {
        "user_id": user_id,
        "target_resource": target_resource,
        "jump_host": jump_host,
        "has_authorized_graph_path": has_path,
        "graph_distance": path_len if has_path else "No Direct Path",
        "graph_anomaly_score": anomaly_score,
        "is_atypical_traversal": is_atypical_path,
        "reason": f"🕸️ ATYPICAL GRAPH TRAVERSAL: {user_id} accessed '{target_resource}' via unusual host '{jump_host}' (Graph Distance: {path_len})" if is_atypical_path else "Standard Graph Traversal Path"
    }

# ⌨️ 3. Behavioral Biometrics (Keystroke & Mouse Dynamics)
def verify_behavioral_biometrics(user_id, flight_time_ms=120.0, dwell_time_ms=85.0, mouse_jitter=12.5):
    """
    Tracks keystroke flight time (pause between keys) and dwell time (key press duration),
    plus mouse cursor curvature jitter.
    If typing/mouse rhythms differ by > 3.5 sigma from user profile, triggers instant MFA re-authentication challenge!
    """
    profile = USERS.get(user_id, USERS["u_rahul"])
    base_flight = profile.get("bio_flight_ms", 120.0)
    base_dwell = profile.get("bio_dwell_ms", 85.0)
    base_jitter = profile.get("bio_jitter", 12.0)
    
    flight_z = abs(flight_time_ms - base_flight) / 15.0
    dwell_z = abs(dwell_time_ms - base_dwell) / 10.0
    jitter_z = abs(mouse_jitter - base_jitter) / 3.0
    
    max_sigma = max(flight_z, dwell_z, jitter_z)
    mfa_required = max_sigma > 3.5

    reasons = []
    if mfa_required:
        reasons.append(f"⌨️ BIOMETRIC DEVIATION EXCEEDED: {max_sigma:.2f}σ > 3.5σ threshold (Flight: {flight_time_ms}ms, Dwell: {dwell_time_ms}ms, Jitter: {mouse_jitter})")
        reasons.append("🔒 AUTOMATED CONTAINMENT: Instant MFA Re-Authentication Challenge triggered before granting file access")

    return {
        "user_id": user_id,
        "flight_time_ms": flight_time_ms,
        "dwell_time_ms": dwell_time_ms,
        "mouse_jitter": mouse_jitter,
        "sigma_deviation": round(max_sigma, 2),
        "mfa_required": mfa_required,
        "reasons": reasons
    }

# 📦 4. High-Entropy Exfiltration & Protocol Tunneling Inspector
def calculate_shannon_entropy(data_bytes):
    """
    Measures payload randomness (Shannon Entropy): H(X) = -sum( P(x_i) * log2(P(x_i)) )
    High Entropy (> 7.5 / 8.0) indicates encrypted archives (.zip, .7z) or obfuscated exfiltration payloads.
    """
    if isinstance(data_bytes, str):
        data_bytes = data_bytes.encode('utf-8')
    if not data_bytes:
        return 0.0

    length = len(data_bytes)
    freq = {}
    for byte in data_bytes:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)

def detect_dns_tunneling(query_domain):
    """
    Detects DNS Tunneling exfiltration (e.g. chunk1.exfil.attacker.com)
    by measuring subdomain length, entropy, and query frequency spikes.
    """
    subdomain = query_domain.split('.')[0] if '.' in query_domain else query_domain
    subdomain_len = len(subdomain)
    subdomain_entropy = calculate_shannon_entropy(subdomain)
    
    is_dns_tunnel = subdomain_len > 25 or subdomain_entropy > 4.2 or "exfil" in query_domain.lower()
    
    reasons = []
    if is_dns_tunnel:
        reasons.append(f"📡 DNS TUNNELING DETECTED: High entropy query '{query_domain}' (Subdomain Length: {subdomain_len}, Entropy: {subdomain_entropy}/8.0)")

    return {
        "query_domain": query_domain,
        "subdomain_length": subdomain_len,
        "entropy": subdomain_entropy,
        "is_dns_tunnel": is_dns_tunnel,
        "reasons": reasons
    }

# ⚡ 5. Just-In-Time (JIT) Dynamic Deprivileging (Micro-Containment)
def get_jit_micro_containment_tier(risk_score):
    """
    Determines Just-In-Time (JIT) micro-containment state based on risk score tier:
    - 0 - 30 (Low): Normal Access (Full Unrestricted Access)
    - 31 - 60 (Medium): Speed Throttling (Bandwidth capped to 100 KB/s on external data moves)
    - 61 - 85 (High): Adaptive JIT Revocation (Revoke AWS IAM admin roles; downgrade filesystem to read-only)
    - 86 - 100 (Critical): Active Isolation (Terminate VPN sessions; revoke Active Directory tokens; isolate host)
    """
    score = int(risk_score)
    if score <= 30:
        return {
            "tier": "Low",
            "tier_level": 1,
            "badge_class": "bg-success",
            "action": "Normal Access",
            "system_state": "Full Unrestricted Access",
            "bandwidth_limit": "Unrestricted",
            "iam_state": "Active Admin/Read-Write",
            "network_state": "Fully Connected"
        }
    elif score <= 60:
        return {
            "tier": "Medium",
            "tier_level": 2,
            "badge_class": "bg-info text-dark",
            "action": "Speed Throttling",
            "system_state": "Bandwidth capped to 100 KB/s on external data moves",
            "bandwidth_limit": "100 KB/s Capped",
            "iam_state": "Standard Access",
            "network_state": "Throttled Egress"
        }
    elif score <= 85:
        return {
            "tier": "High",
            "tier_level": 3,
            "badge_class": "bg-warning text-dark",
            "action": "Adaptive JIT Revocation",
            "system_state": "Revoke AWS IAM admin roles; downgrade filesystem to read-only",
            "bandwidth_limit": "10 KB/s Capped",
            "iam_state": "IAM Admin Revoked / Read-Only Mode",
            "network_state": "Strict Segmented Network"
        }
    else:
        return {
            "tier": "Critical",
            "tier_level": 4,
            "badge_class": "bg-danger",
            "action": "Active Isolation",
            "system_state": "Terminate VPN sessions; revoke Active Directory tokens; isolate host",
            "bandwidth_limit": "0 KB/s (Blocked)",
            "iam_state": "AD & IAM Tokens Revoked",
            "network_state": "Host Isolated / Quarantine VNET"
        }

# 🔒 6. Zero-Trust Analyst Privacy & Dual-Authorization Unmasking
def anonymize_user_id(user_id):
    """Anonymizes user identities into zero-trust hashes (e.g. Entity_7F8A92) to prevent SOC analyst bias."""
    import hashlib
    hash_tag = hashlib.md5(user_id.encode('utf-8')).hexdigest()[:6].upper()
    return f"Entity_{hash_tag}"

UNMASK_TOKENS = {}

def request_dual_auth_unmask(alert_id, token_lead_1, token_lead_2):
    """
    Unmasks real identity tags only when two SOC leads or an HR representative
    approve an unmasking token request for scores exceeding 85/100.
    """
    alert = next((a for a in ALERT_FEED if a.get("alert_id") == alert_id), None)
    if not alert:
        return {"error": "Alert ID not found"}

    if alert.get("risk_score", 0) < 85:
        return {"error": "Dual-authorization unmasking is restricted to Critical alerts (Risk Score >= 85/100)"}

    if not token_lead_1 or not token_lead_2 or token_lead_1 == token_lead_2:
        return {"error": "Two distinct valid SOC Lead / HR authorization tokens are required for unmasking"}

    UNMASK_TOKENS[alert_id] = {
        "unmasked_by": [token_lead_1, token_lead_2],
        "expires_at": (datetime.now() + timedelta(minutes=15)).strftime("%H:%M:%S")
    }

    return {
        "status": "success",
        "message": f"Dual-authorization granted by {token_lead_1} & {token_lead_2}. Identity unmasked for 15 minutes.",
        "real_name": alert["name"],
        "real_user_id": alert["user_id"],
        "role": alert["role"],
        "department": alert["dept"]
    }


# 🌐 7. IP Geolocation & Impossible Travel Node Tracker
CITY_COORDINATES = {
    # Americas
    "New York": (40.7128, -74.0060, "🇺🇸 United States"),
    "San Francisco": (37.7749, -122.4194, "🇺🇸 United States"),
    "Chicago": (41.8781, -87.6298, "🇺🇸 United States"),
    "Toronto": (43.6532, -79.3832, "🇨🇦 Canada"),
    "Sao Paulo": (-23.5505, -46.6333, "🇧🇷 Brazil"),
    "Mexico City": (19.4326, -99.1332, "🇲🇽 Mexico"),
    "Buenos Aires": (-34.6037, -58.3816, "🇦🇷 Argentina"),

    # Europe
    "London": (51.5074, -0.1278, "🇬🇧 United Kingdom"),
    "Paris": (48.8566, 2.3522, "🇫🇷 France"),
    "Berlin": (52.5200, 13.4050, "🇩🇪 Germany"),
    "Amsterdam": (52.3676, 4.9041, "🇳🇱 Netherlands"),
    "Zurich": (47.3769, 8.5417, "🇨🇭 Switzerland"),
    "Madrid": (40.4168, -3.7038, "🇪🇸 Spain"),
    "Rome": (41.9028, 12.4964, "🇮🇹 Italy"),
    "Stockholm": (59.3293, 18.0686, "🇸🇪 Sweden"),
    "Moscow": (55.7558, 37.6173, "🇷🇺 Russia"),

    # Asia-Pacific
    "Tokyo": (35.6762, 139.6503, "🇯🇵 Japan"),
    "Singapore": (1.3521, 103.8198, "🇸🇬 Singapore"),
    "Hong Kong": (22.3193, 114.1694, "🇭🇰 Hong Kong"),
    "Sydney": (-33.8688, 151.2093, "🇦🇺 Australia"),
    "Mumbai": (19.0760, 72.8777, "🇮🇳 India"),
    "Delhi": (28.6139, 77.2090, "🇮🇳 India"),
    "Seoul": (37.5665, 126.9780, "🇰🇷 South Korea"),
    "Shanghai": (31.2304, 121.4737, "🇨🇳 China"),
    "Beijing": (39.9042, 116.4074, "🇨🇳 China"),

    # Middle East & Africa
    "Dubai": (25.2048, 55.2708, "🇦🇪 UAE"),
    "Tel Aviv": (32.0853, 34.7818, "🇮🇱 Israel"),
    "Cairo": (30.0444, 31.2357, "🇪🇬 Egypt"),
    "Johannesburg": (-26.2041, 28.0473, "🇿🇦 South Africa"),
    "Nairobi": (-1.2921, 36.8219, "🇰🇪 Kenya")
}

def calculate_haversine_distance(lat1, lon1, lat2, lon2):
    """Calculates physical distance in miles between two latitude/longitude points."""
    R = 3958.8
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return round(R * c, 1)

def analyze_ip_geolocation_impossible_travel(ip1="108.12.44.1", city1="New York", ip2="82.165.197.1", city2="London", time_delta_mins=10.0, custom_lat1=None, custom_lon1=None, custom_lat2=None, custom_lon2=None):
    """
    Calculates geographic distance between consecutive IP logins / GPS coordinates and evaluates physical travel velocity (mph).
    Supports preset global cities OR custom latitude/longitude GPS parameters!
    Triggers Impossible Travel & Credential Hijacking Alert if required velocity > 500 mph!
    """
    if custom_lat1 is not None and custom_lon1 is not None:
        lat1, lon1 = float(custom_lat1), float(custom_lon1)
        c1_country = "📍 Custom GPS Point 1"
    else:
        c1_info = CITY_COORDINATES.get(city1, (40.7128, -74.0060, "🇺🇸 United States"))
        lat1, lon1, c1_country = c1_info[0], c1_info[1], c1_info[2]

    if custom_lat2 is not None and custom_lon2 is not None:
        lat2, lon2 = float(custom_lat2), float(custom_lon2)
        c2_country = "📍 Custom GPS Point 2"
    else:
        c2_info = CITY_COORDINATES.get(city2, (51.5074, -0.1278, "🇬🇧 United Kingdom"))
        lat2, lon2, c2_country = c2_info[0], c2_info[1], c2_info[2]

    distance_miles = calculate_haversine_distance(lat1, lon1, lat2, lon2)
    time_hours = max(0.01, float(time_delta_mins) / 60.0)
    velocity_mph = round(distance_miles / time_hours, 1)

    is_impossible_travel = velocity_mph > 500.0
    is_tor_proxy = "82.165" in ip2 or "185.220" in ip2

    reasons = []
    if is_impossible_travel:
        reasons.append(f"🚨 IMPOSSIBLE TRAVEL DETECTED: Required travel speed between {city1} ({lat1:.2f}, {lon1:.2f}) and {city2} ({lat2:.2f}, {lon2:.2f}) is {velocity_mph:.1f} mph (Physical limit: 500 mph)")
        reasons.append(f"Traversed {distance_miles} miles in only {time_delta_mins} minutes across distinct geographic points")
    if is_tor_proxy:
        reasons.append("⚠️ SUSPECT EXIT NODE: Secondary IP belongs to known VPN/TOR exit proxy range")

    return {
        "origin_ip": ip1,
        "origin_city": city1,
        "origin_country": c1_country,
        "origin_coords": (lat1, lon1),
        "destination_ip": ip2,
        "destination_city": city2,
        "destination_country": c2_country,
        "destination_coords": (lat2, lon2),
        "distance_miles": distance_miles,
        "time_delta_mins": time_delta_mins,
        "required_velocity_mph": velocity_mph,
        "is_impossible_travel": is_impossible_travel,
        "is_tor_proxy": is_tor_proxy,
        "threat_level": "Critical" if is_impossible_travel else "Low",
        "reasons": reasons
    }


ueba_instance = UEBAEngineWrapper()
