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
    "Match Events (Trigger)", 
    "Evasion Events (Bypass)", 
    "Total Training Events (Match + Evasion)",
    "Bypass Rate (%)"
]

# Process data and calculate rates
for row in combined_data:
    match = row.get("Match Events (Bypass)", "") or row.get("Match Events (Trigger)", "")
    evasion = row.get("Evasion Events (Bypass)", "")
    total_ev = row.get("Total Events (Bypass)", "") or row.get("Total Training Events (Match + Evasion)", "")
    
    # Normalize internal keys
    row["Match Events (Trigger)"] = match
    row["Evasion Events (Bypass)"] = evasion
    row["Total Training Events (Match + Evasion)"] = total_ev
    
    for k in ["Match Events (Bypass)", "Total Events (Bypass)"]:
        if k in row: del row[k]

    try:
        e_val = float(evasion)
        t_val = float(total_ev)
        if t_val > 0:
            row["Bypass Rate (%)"] = round((e_val / t_val) * 100, 2)
        else:
            row["Bypass Rate (%)"] = 0.0
    except (ValueError, TypeError):
        row["Bypass Rate (%)"] = -1.0 # Placeholder for rules without bypass data

# Sort rules: Put rules with data first, sorted by Bypass Rate DESC, then rules without data
data_rows = [r for r in combined_data if r["Bypass Rate (%)"] != -1.0]
nodata_rows = [r for r in combined_data if r["Bypass Rate (%)"] == -1.0]

data_rows.sort(key=lambda x: x["Bypass Rate (%)"], reverse=True)
nodata_rows.sort(key=lambda x: x["Rule Name"]) # Alphabetical for the rest

final_data = data_rows + nodata_rows

# Calculate grand totals
total_summarize = 0
total_match = 0
total_evasion = 0
total_bypass = 0

for row in final_data:
    try: total_summarize += int(row["Command Count (Summarize)"])
    except: pass
    try: total_match += int(row["Match Events (Trigger)"])
    except: pass
    try: total_evasion += int(row["Evasion Events (Bypass)"])
    except: pass
    try: total_bypass += int(row["Total Training Events (Match + Evasion)"])
    except: pass

grand_total_bypass_rate = round((total_evasion / total_bypass * 100), 2) if total_bypass > 0 else 0

final_data.append({
    "Rule Name": "GRAND TOTAL",
    "Command Count (Summarize)": str(total_summarize),
    "Match Events (Trigger)": str(total_match),
    "Evasion Events (Bypass)": str(total_evasion),
    "Total Training Events (Match + Evasion)": str(total_bypass),
    "Bypass Rate (%)": grand_total_bypass_rate
})

# Final string conversion for CSV output (replacing -1.0 placeholders)
for row in final_data:
    if row["Bypass Rate (%)"] == -1.0:
        row["Bypass Rate (%)"] = ""

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in final_data:
        writer.writerow(row)

print(f"Combined CSV written to {output_path}")
print(f"Total rules processed: {len(combined_data)}")
