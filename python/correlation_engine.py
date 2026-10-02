import re
import json
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
OUTPUT_FILE = "/home/shubam/SOC-Sentinel/python/incidents.json"

events = []
incidents = []


# ==========================================
# STEP 1: READ AND CLASSIFY LOG EVENTS
# ==========================================

with open(LOG_FILE, "r") as log_file:

    for line in log_file:

        if "ROOT LOGIN" in line:
            event_type = "ROOT_LOGIN"

        elif "password changed" in line:
            event_type = "PASSWORD_CHANGE"

        elif "sudo:" in line and "authentication failure" in line:
            event_type = "SUDO_AUTH_FAILURE"

        elif "sudo:" in line and "session opened for user root" in line:
            event_type = "SUDO_SUCCESS"

        elif "sudo:" in line:
            event_type = "SUDO_ACTIVITY"

        elif "session opened" in line:
            event_type = "SESSION_OPEN"

        elif "session closed" in line:
            event_type = "SESSION_CLOSE"

        else:
            continue

        # ==========================================
        # STEP 2: EXTRACT TIMESTAMP
        # ==========================================

        timestamp_match = re.match(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})",
            line
        )

        if timestamp_match:

            timestamp = datetime.fromisoformat(
                timestamp_match.group(1)
            )

            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "raw": line.strip()
            })


# ==========================================
# STEP 3: CORRELATION ENGINE
# ==========================================

for i, event in enumerate(events):

    if event["event_type"] == "SUDO_AUTH_FAILURE":

        failure_time = event["timestamp"]

        for next_event in events[i + 1:]:

            if next_event["event_type"] == "SUDO_SUCCESS":

                success_time = next_event["timestamp"]

                time_gap = (
                    success_time - failure_time
                ).total_seconds()

                if 0 <= time_gap <= 300:

                    incident_id = (
                        "SOC-"
                        + failure_time.strftime("%Y%m%d%H%M%S")
                    )

                    incident = {
                        "incident_id": incident_id,
                        "alert_name":
                            "Sudo Authentication Failure Followed by Success",
                        "severity": "Medium",
                        "status": "INVESTIGATE",
                        "correlation_window_seconds": 300,
                        "failure_time":
                            failure_time.isoformat(),
                        "success_time":
                            success_time.isoformat(),
                        "time_gap_seconds": time_gap,
                        "mitre_technique":
                            "Candidate - T1078 Valid Accounts",
                        "analyst_note":
                            "Authentication failure was followed by "
                            "successful sudo activity within the "
                            "correlation window. This is an "
                            "investigation candidate, not proof of "
                            "compromise."
                    }

                    incidents.append(incident)

                    break


# ==========================================
# STEP 4: SAVE INCIDENTS AS JSON
# ==========================================

with open(OUTPUT_FILE, "w") as output_file:

    json.dump(
        incidents,
        output_file,
        indent=4
    )


# ==========================================
# STEP 5: DISPLAY RESULTS
# ==========================================

print("SOC Sentinel - Correlation Engine")
print("=================================")

print(
    "Correlated Incidents:",
    len(incidents)
)

for incident in incidents:

    print("\n---------------------------------")

    print(
        "Incident ID:",
        incident["incident_id"]
    )

    print(
        "Alert:",
        incident["alert_name"]
    )

    print(
        "Severity:",
        incident["severity"]
    )

    print(
        "Status:",
        incident["status"]
    )

    print(
        "Time Gap:",
        incident["time_gap_seconds"],
        "seconds"
    )

    print(
        "MITRE:",
        incident["mitre_technique"]
    )

print("\nIncident data saved to:")
print(OUTPUT_FILE)
