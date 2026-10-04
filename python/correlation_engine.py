import re
import json
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
SIMULATED_LOG_FILE = "/home/shubam/SOC-Sentinel/python/simulated_attack.log"
OUTPUT_FILE = "/home/shubam/SOC-Sentinel/python/incidents.json"

events = []
simulated_events = []
incidents = []


# ==========================================
# STEP 1: READ AND CLASSIFY REAL LOG EVENTS
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
# STEP 2: READ SIMULATED LAB EVENTS
# ==========================================

with open(SIMULATED_LOG_FILE, "r") as log_file:

    for line in log_file:

        if "session opened for user root" in line:
            event_type = "ROOT_LOGIN"

        elif "password changed" in line:
            event_type = "PASSWORD_CHANGE"

        elif "command execution detected" in line:
            event_type = "COMMAND_EXECUTION"

        else:
            continue

        timestamp_match = re.match(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})",
            line
        )

        if timestamp_match:

            timestamp = datetime.fromisoformat(
                timestamp_match.group(1)
            )

            simulated_events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "raw": line.strip()
            })


# ==========================================
# STEP 3: REAL SUDO CORRELATION
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
                        "timestamp":
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
# STEP 4: SIMULATED ATTACK STORY CORRELATION
# ==========================================

simulated_events.sort(
    key=lambda event: event["timestamp"]
)

for i, event in enumerate(simulated_events):

    if event["event_type"] != "ROOT_LOGIN":
        continue

    root_login = event
    password_change = None
    command_execution = None

    for next_event in simulated_events[i + 1:]:

        time_gap = (
            next_event["timestamp"]
            - root_login["timestamp"]
        ).total_seconds()

        if time_gap > 300:
            break

        if (
            next_event["event_type"] == "PASSWORD_CHANGE"
            and password_change is None
        ):
            password_change = next_event

        elif (
            next_event["event_type"] == "COMMAND_EXECUTION"
            and password_change is not None
        ):
            command_execution = next_event
            break

    if password_change and command_execution:

        incident_id = (
            "SIM-"
            + root_login["timestamp"].strftime("%Y%m%d%H%M%S")
        )

        incident = {
            "incident_id": incident_id,
            "alert_name":
                "Privileged Account Activity Attack Story",
            "severity": "High",
            "status": "INVESTIGATE",
            "scenario_type": "SIMULATED_LAB_EVENT",
            "attack_story": [
                "ROOT_LOGIN",
                "PASSWORD_CHANGE",
                "COMMAND_EXECUTION"
            ],
            "root_login_time":
                root_login["timestamp"].isoformat(),
            "timestamp":
                root_login["timestamp"].isoformat(),
            "password_change_time":
                password_change["timestamp"].isoformat(),
            "command_execution_time":
                command_execution["timestamp"].isoformat(),
            "attack_story_duration_seconds":
                (
                    command_execution["timestamp"]
                    - root_login["timestamp"]
                ).total_seconds(),
            "command":
                "whoami",
            "mitre_technique":
                "Candidate - T1078 Valid Accounts",
            "analyst_note":
                "This is a simulated laboratory attack scenario "
                "created for SOC Sentinel testing. The sequence "
                "demonstrates correlation of privileged account "
                "activity followed by password modification and "
                "command execution. It is not evidence of a real "
                "compromise."
        }

        incidents.append(incident)



# ==========================================
# STEP 6: DISPLAY RESULTS
# ==========================================

AUTH_ATTACK_LOG_FILE = (
    "/home/shubam/SOC-Sentinel/python/"
    "simulated_auth_attack.log"
)

auth_events = []

with open(AUTH_ATTACK_LOG_FILE, "r") as log_file:

    for line in log_file:

        if "authentication failure" in line:
            event_type = "AUTH_FAILURE"

        elif "successful authentication" in line:
            event_type = "AUTH_SUCCESS"

        else:
            continue

        timestamp_match = re.match(
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})",
            line
        )

        if timestamp_match:

            timestamp = datetime.fromisoformat(
                timestamp_match.group(1)
            )

            auth_events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "raw": line.strip()
            })


# ------------------------------------------
# CORRELATE MULTIPLE FAILURES → SUCCESS
# ------------------------------------------

auth_events.sort(
    key=lambda event: event["timestamp"]
)

for i, event in enumerate(auth_events):

    if event["event_type"] != "AUTH_FAILURE":
        continue

    window_start = event["timestamp"]
    failure_events = [event]

    for next_event in auth_events[i + 1:]:

        time_gap = (
            next_event["timestamp"]
            - window_start
        ).total_seconds()

        if time_gap > 300:
            break

        if next_event["event_type"] == "AUTH_FAILURE":
            failure_events.append(next_event)

        elif (
            next_event["event_type"] == "AUTH_SUCCESS"
            and len(failure_events) >= 3
        ):

            incident_id = (
                "SIM-AUTH-"
                + window_start.strftime("%Y%m%d%H%M%S")
            )

            incident = {
                "incident_id": incident_id,
                "alert_name":
                    "Multiple Authentication Failures "
                    "Followed by Successful Login",
                "severity": "High",
                "status": "INVESTIGATE",
                "scenario_type":
                    "SIMULATED_LAB_EVENT",
                "failed_attempts":
                    len(failure_events),
                "success_time":
                    next_event["timestamp"].isoformat(),
                "timestamp":
                    next_event["timestamp"].isoformat(),
                "correlation_window_seconds": 300,
                "attack_pattern":
                    "FAILED_LOGIN -> FAILED_LOGIN -> "
                    "FAILED_LOGIN -> SUCCESSFUL_LOGIN",
                "source_ip":
                    "10.10.10.50",
                "target_user":
                    "shubam",
                "mitre_technique":
                    "Candidate - T1110 Brute Force",
                "analyst_note":
                    "This is a simulated laboratory "
                    "authentication attack scenario. Multiple "
                    "authentication failures were followed by "
                    "a successful authentication within the "
                    "correlation window. This is an investigation "
                    "candidate, not proof of compromise."
            }

            incidents.append(incident)

            break

# ==========================================
# STEP 5: SAVE INCIDENTS AS JSON
# ==========================================

with open(OUTPUT_FILE, "w") as output_file:

    json.dump(
        incidents,
        output_file,
        indent=4
    )

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

    if "attack_story" in incident:

        print(
            "Attack Story:",
            " -> ".join(incident["attack_story"])
        )

        print(
            "Scenario:",
            incident["scenario_type"]
        )

    if "time_gap_seconds" in incident:

        print(
            "Time Gap:",
            incident["time_gap_seconds"],
            "seconds"
        )

    if "attack_story_duration_seconds" in incident:

        print(
            "Attack Story Duration:",
            incident["attack_story_duration_seconds"],
            "seconds"
        )

    print(
        "MITRE:",
        incident["mitre_technique"]
    )

print("\nIncident data saved to:")
print(OUTPUT_FILE)
