import csv
import os

def normalize_name(name):
    """Normalize rule name by replacing underscores with spaces and stripping whitespace."""
    return name.replace('_', ' ').strip()

def read_csv(filepath):
    """Read CSV file and return a dictionary keyed by normalized rule name."""
    data = {}
    with open(filepath, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Skip empty rows
            if not row['Rule Name']:
                continue
            norm_name = normalize_name(row['Rule Name'])
            data[norm_name] = row
    return data

def calculate_change(new_val, old_val):
    try:
        n = float(new_val) if new_val else 0.0
        o = float(old_val) if old_val else 0.0
        return n - o
    except ValueError:
        return 0.0

def main():
    base_dir = r"d:\Downloads in D\Request Linux"
    original_file = os.path.join(base_dir, "combined_rule_summary.csv")
    fixed_file = os.path.join(base_dir, "Summary_Fixed_Rule_Report.csv")
    output_file = os.path.join(base_dir, "final_combined_rule_change_report.csv")

    print(f"Reading original file: {original_file}")
    original_data = read_csv(original_file)
    
    print(f"Reading fixed file: {fixed_file}")
    fixed_data = read_csv(fixed_file)

    # Prepare output headers
    fieldnames = [
        "Rule Name",
        "Command Count",
        "Original Match Events",
        "Fixed Match Events",
        "Match Events Change",
        "Original Evasion Events",
        "Fixed Evasion Events",
        "Evasion Events Change",
        "Original Bypass Rate (%)",
        "Fixed Bypass Rate (%)",
        "Bypass Rate Change (%)"
    ]

    print(f"Writing output file: {output_file}")
    with open(output_file, mode='w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        # Iterate through original data to preserve order
        # We need to re-read the original file to get the correct order including rows that might not be in the dictionary if we filtered them,
        # but for the report we mainly want the rules.
        # Let's use the dictionary keys for rules, but what about TOTAL? 
        # The user wants "add data from Summary_Fixed_rule_report to combined_rule_summary".
        # Let's iterate through the rows of combined_rule_summary.csv again.
        
        with open(original_file, mode='r', encoding='utf-8') as f_orig:
            reader = csv.DictReader(f_orig)
            
            for row in reader:
                rule_name = row['Rule Name']
                if not rule_name: # Handle empty lines
                    continue
                
                norm_name = normalize_name(rule_name)
                
                # Base data
                out_row = {
                    "Rule Name": rule_name,
                    "Command Count": row.get('Command Count (Summarize)', ''),
                    "Original Match Events": row.get('Match Events (Trigger)', ''),
                    "Original Evasion Events": row.get('Evasion Events (Bypass)', ''),
                    "Original Bypass Rate (%)": row.get('Bypass Rate (%)', '')
                }

                # Start with empty 'Fixed' values
                out_row["Fixed Match Events"] = ""
                out_row["Fixed Evasion Events"] = ""
                out_row["Fixed Bypass Rate (%)"] = ""
                
                out_row["Match Events Change"] = ""
                out_row["Evasion Events Change"] = ""
                out_row["Bypass Rate Change (%)"] = ""

                # Look up in fixed data
                matched_key = None
                if norm_name in fixed_data:
                    matched_key = norm_name
                else:
                    # Try finding a key that is a substring (or vice versa) to handle "- Linux" suffix
                    for key in fixed_data:
                        if key in norm_name or norm_name in key:
                            # Verify it's a "good" match to avoid false positives?
                            # For "Shell Execution via Flock - Linux" vs "Shell Execution via Flock", this works.
                            matched_key = key
                            break

                if matched_key:
                    fixed_row = fixed_data[matched_key]
                    out_row["Fixed Match Events"] = fixed_row.get('Match Events (Trigger)', '')
                    out_row["Fixed Evasion Events"] = fixed_row.get('Evasion Events (Bypass)', '')
                    out_row["Fixed Bypass Rate (%)"] = fixed_row.get('Bypass Rate (%)', '')

                    match_change = calculate_change(out_row["Fixed Match Events"], out_row["Original Match Events"])
                    out_row["Match Events Change"] = f"{match_change:g}" if out_row["Fixed Match Events"] and out_row["Original Match Events"] else ""

                    evasion_change = calculate_change(out_row["Fixed Evasion Events"], out_row["Original Evasion Events"])
                    out_row["Evasion Events Change"] = f"{evasion_change:g}" if out_row["Fixed Evasion Events"] and out_row["Original Evasion Events"] else ""

                    rate_change = calculate_change(out_row["Fixed Bypass Rate (%)"], out_row["Original Bypass Rate (%)"])
                    out_row["Bypass Rate Change (%)"] = f"{rate_change:.2f}" if out_row["Fixed Bypass Rate (%)"] and out_row["Original Bypass Rate (%)"] else ""

                elif "GRAND TOTAL" in rule_name.upper():
                    # Explicit fallback for TOTAL if not matched above
                     if "TOTAL" in fixed_data:
                         fixed_row = fixed_data["TOTAL"]
                         out_row["Fixed Match Events"] = fixed_row.get('Match Events (Trigger)', '')
                         out_row["Fixed Evasion Events"] = fixed_row.get('Evasion Events (Bypass)', '')
                         out_row["Fixed Bypass Rate (%)"] = fixed_row.get('Bypass Rate (%)', '')
                         
                         match_change = calculate_change(out_row["Fixed Match Events"], out_row["Original Match Events"])
                         out_row["Match Events Change"] = f"{match_change:g}"
                         
                         evasion_change = calculate_change(out_row["Fixed Evasion Events"], out_row["Original Evasion Events"])
                         out_row["Evasion Events Change"] = f"{evasion_change:g}"
                         
                         rate_change = calculate_change(out_row["Fixed Bypass Rate (%)"], out_row["Original Bypass Rate (%)"])
                         out_row["Bypass Rate Change (%)"] = f"{rate_change:.2f}"

                writer.writerow(out_row)

    print("Success.")

if __name__ == "__main__":
    main()
