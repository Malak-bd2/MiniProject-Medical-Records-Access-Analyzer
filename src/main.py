
import csv
from datetime import datetime
from export_results import export_results
from display import display_alerts


# ==========================================
# 1. READ ACCESS LOGS
# ==========================================

with open("access_logs.csv", "r", encoding="utf-8") as file:
    reader = csv.DictReader(file)
    logs = list(reader)


# ==========================================
# 2. CONVERT ACCESS TIMES
# ==========================================

for row in logs:
    row["datetime"] = datetime.strptime(
        row["access_time"], "%Y-%m-%d %H:%M"
    )


# ==========================================
# 3. PREPARE ONE-HOUR WINDOWS
# FOR UNUSUAL ACCESS VOLUME DETECTION
# ==========================================

volume_windows = {}

for row in logs:
    user = row["user_name"]
    date = row["datetime"].date()

    user_day_logs = [
        r for r in logs
        if r["user_name"] == user
        and r["datetime"].date() == date
    ]

    first_time = min(r["datetime"] for r in user_day_logs)

    window_number = int(
        (row["datetime"] - first_time).total_seconds() // 3600
    )

    window_key = (user, date, window_number)

    volume_windows.setdefault(window_key, []).append(row)


# ==========================================
# 4. ANALYZE ACCESS LOGS
# ==========================================

results = []

for row in logs:

    access_time = row["datetime"]
    user = row["user_name"]


    # ==========================================
    # RULE 1: DETECT ACCESS OUTSIDE WORKING HOURS
    # Working hours: 08:00 - 20:00
    # ==========================================

    outside_working_hours = (
        access_time.hour < 8 or access_time.hour >= 20
    )


    # ==========================================
    # RULE 2: DETECT UNUSUAL ACCESS VOLUME
    # More than 10 different files in one hour
    # ==========================================

    date = access_time.date()

    user_day_logs = [
        r for r in logs
        if r["user_name"] == user
        and r["datetime"].date() == date
    ]

    first_time = min(r["datetime"] for r in user_day_logs)

    window_number = int(
        (access_time - first_time).total_seconds() // 3600
    )

    window_key = (user, date, window_number)

    window_logs = volume_windows[window_key]

    records_in_window = {
        r["record_id"] for r in window_logs
    }

    unusual_volume = len(records_in_window) > 10


    # ==========================================
    # RULE 3: DETECT ACCESS OUTSIDE USER'S DEPARTMENT
    # ==========================================

    outside_department = (
        row["user_department"] != row["record_department"]
    )


    # ==========================================
    # 5. CALCULATE SUSPICION SCORE
    # ==========================================

    suspicion_score = 0

    if outside_working_hours:
        suspicion_score += 2

    if unusual_volume:
        suspicion_score += 7

    if outside_department:
        suspicion_score += 3


    # ==========================================
    # 6. GENERATE ALERT REASONS
    # ==========================================

    reasons = []

    if outside_working_hours:
        reasons.append("Outside working hours")

    if unusual_volume:
        reasons.append("Unusual access volume")

    if outside_department:
        reasons.append("Outside user's department")


    # ==========================================
    # 7. DETERMINE ALERT LEVEL
    # ==========================================

    if suspicion_score <= 2:
        alert_level = "Normal"

    elif suspicion_score <= 3:
        alert_level = "Medium Alert"

    else:
        alert_level = "High Alert"


    # ==========================================
    # 8. STORE ANALYSIS RESULTS
    # ==========================================

    results.append({
        **row,
        "suspicion_score": suspicion_score,
        "alert_level": alert_level,
        "reasons": ", ".join(reasons) if reasons
                   else "No suspicious activity"
    })


# ==========================================
# 9. EXPORT RESULTS TO CSV
# ==========================================

export_results(results)


# ==========================================
# 10. DISPLAY ANALYSIS RESULTS
# ==========================================

display_alerts(results)

