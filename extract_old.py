import os
import json
import re
import glob

brain_dir = r"C:\Users\MOHAMED BAASIL\.gemini\antigravity-ide\brain"
log_files = glob.glob(os.path.join(brain_dir, "*", ".system_generated", "logs", "transcript_full.jsonl"))

# Sort by modification time to get chronological order
log_files.sort(key=os.path.getmtime)

files_to_find = ["styles.css", "react-app.jsx", "index.html"]
found = {f: False for f in files_to_find}

def process_file_content(content):
    # Remove the "1: ", "2: " line numbers added by view_file
    lines = content.split('\n')
    cleaned = []
    # Skip preamble like "File Path:", "Total Lines:", "Showing lines...", "The following code..."
    start_idx = 0
    for i, line in enumerate(lines):
        if re.match(r'^\d+:\s', line):
            start_idx = i
            break
    
    for line in lines[start_idx:]:
        match = re.match(r'^\d+:\s(.*)', line)
        if match:
            cleaned.append(match.group(1))
        else:
            cleaned.append(line)
    return '\n'.join(cleaned)

for log_file in log_files:
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if "tool_calls" in entry:
                        for call in entry["tool_calls"]:
                            pass # We can look at tool calls too
                    
                    if entry.get("type") == "TOOL_RESPONSE":
                        content = entry.get("content", "")
                        for target in files_to_find:
                            if not found[target] and target in content and "File Path:" in content:
                                print(f"Found original {target} in {log_file}")
                                cleaned = process_file_content(content)
                                with open(f"old_{target}", "w", encoding="utf-8") as out_f:
                                    out_f.write(cleaned)
                                found[target] = True
                except Exception as e:
                    pass
    except Exception as e:
        print(f"Error reading {log_file}: {e}")

print("Search complete.")
