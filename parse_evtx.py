

#!/usr/bin/env python3
"""
Parse Windows Security Event Logs (.evtx) and detect failed login attempts (4625).
"""

from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from collections import Counter
import csv

evtx_file = "CA4625.evtx"

failed_logins = []
with Evtx(evtx_file) as log:
    for record in log.records():
        xml_str = record.xml()
        root = ET.fromstring(xml_str)

        # Get EventID
        event_id = root.find(".//{*}EventID")
        if event_id is not None and event_id.text == "4625":  # Failed logon
            data = {d.attrib["Name"]: d.text for d in root.findall(".//{*}Data")}
            failed_logins.append({
                "Time": root.find(".//{*}TimeCreated").attrib.get("SystemTime"),
                "TargetUser": data.get("TargetUserName"),
                "IpAddress": data.get("IpAddress"),
                "ProcessName": data.get("ProcessName"),
                "FailureReason": data.get("FailureReason")
            })

# Print sample results
print(f"Total failed logins: {len(failed_logins)}")
for f in failed_logins[:10]:  # show first 10
    print(f)

# Count failed attempts by IP and user
ip_counter = Counter(f["IpAddress"] for f in failed_logins if f["IpAddress"])
user_counter = Counter(f["TargetUser"] for f in failed_logins if f["TargetUser"])

print("\nTop offending IPs:")
for ip, count in ip_counter.most_common(5):
    print(f"{ip}: {count} attempts")

print("\nTop targeted accounts:")
for user, count in user_counter.most_common(5):
    print(f"{user}: {count} attempts")



with open("failed_logins.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["Time", "TargetUser", "IpAddress", "ProcessName", "FailureReason"])
    writer.writeheader()
    writer.writerows(failed_logins)

print("\n[+] Results saved to failed_logins.csv")
