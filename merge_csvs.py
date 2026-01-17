import csv
import os

rule_summary_path = "/home/vincenzolog/Request-Linux/rule_summary.csv"
bypass_path = "/home/vincenzolog/Request-Linux/bypass.csv"
output_path = "/home/vincenzolog/Request-Linux/combined_rule_summary.csv"

def normalize_name(name):
    n = name.lower()
    n = n.replace(" - linux", "")
    n = n.replace(" - auditd", "")
    n = n.replace("/job", "")
    n = n.strip()
    return n

# Load bypass data into a normalization map
bypass_data = {}
if os.path.exists(bypass_path):
    with open(bypass_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row["Rule Name"]: continue
            norm = normalize_name(row["Rule Name"])
            bypass_data[norm] = row

# Load rule summary and merge
combined_data = []
if os.path.exists(rule_summary_path):
    with open(rule_summary_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rule_name = row["Rule Name"]
            norm = normalize_name(rule_name)
            
            # Default values for bypass columns
            match_events = ""
            evasion_events = ""
            total_bypass_events = ""
            
            if norm in bypass_data:
                b_row = bypass_data[norm]
                match_events = b_row.get("Match Events", "")
                evasion_events = b_row.get("Evasion Events", "")
                total_bypass_events = b_row.get("Total Events", "")
            
            combined_row = {
                "Rule Name": rule_name,
                "Command Count (Summarize)": row["Command Count"],
                "Match Events (Bypass)": match_events,
                "Evasion Events (Bypass)": evasion_events,
                "Total Events (Bypass)": total_bypass_events
            }
            combined_data.append(combined_row)

# Headers for the new CSV
fieldnames = [
    "Rule Name", 
    "Command Count (Summarize)", 
    "Match Events (Bypass)", 
    "Evasion Events (Bypass)", 
    "Total Events (Bypass)"
]

# Calculate grand totals
total_summarize = 0
total_match = 0
total_evasion = 0
total_bypass = 0

for row in combined_data:
    try: total_summarize += int(row["Command Count (Summarize)"])
    except: pass
    try: total_match += int(row["Match Events (Bypass)"])
    except: pass
    try: total_evasion += int(row["Evasion Events (Bypass)"])
    except: pass
    try: total_bypass += int(row["Total Events (Bypass)"])
    except: pass

combined_data.append({
    "Rule Name": "GRAND TOTAL",
    "Command Count (Summarize)": str(total_summarize),
    "Match Events (Bypass)": str(total_match),
    "Evasion Events (Bypass)": str(total_evasion),
    "Total Events (Bypass)": str(total_bypass)
})

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in combined_data:
        writer.writerow(row)

print(f"Combined CSV written to {output_path}")
print(f"Total rules processed: {len(combined_data)}")
